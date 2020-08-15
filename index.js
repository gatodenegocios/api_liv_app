require('dotenv').config();

const express = require('express');
//const session = require('express-session');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const app = express();
const mysql = require('mysql');
const crypto = require('crypto');


const { v4: uuidv4 } = require('uuid');


const connection = mysql.createConnection({
  host     : 'localhost',
  user     : 'root',
  password : 'senha',
  database : 'liv_app',
  charset  : 'utf8mb4'
});

connection.connect(function(err){
  if(err) return console.log(err);
  console.log('conectou!');
});

app.use(express.json());
app.use(bodyParser.urlencoded({extended:true}));

app.set('view engine','ejs');

/*

  DROP DATABASE liv_app;
  CREATE DATABASE liv_app;

  USE liv_app;

  CREATE TABLE people(
    idPeople VARCHAR(36) NOT NULL PRIMARY KEY,
    user VARCHAR(64) NOT NULL UNIQUE,
    hash VARCHAR(128) NOT NULL UNIQUE,
    salt VARCHAR(16) NOT NULL UNIQUE,
    value DOUBLE NOT NULL DEFAULT 1000
  ) ENGINE=InnoDB CHARACTER SET utf8;

  CREATE TABLE transfer(
    idTransfer VARCHAR(36) NOT NULL PRIMARY KEY,
    idPeopleFrom VARCHAR(36) NOT NULL,
    idPeopleTo VARCHAR(36) NOT NULL,
    value DOUBLE NOT NULL,
    date TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (idPeopleFrom) REFERENCES people (idPeople),
    FOREIGN KEY (idPeopleTo) REFERENCES people (idPeople)
  ) ENGINE=InnoDB CHARACTER SET utf8;

*/


/**
 * PASSWORDREGION 
 * generates random string of characters i.e salt
 * @function
 * @param {number} length - Length of the random string.
 */
  let genRandomString = function(length){
      return crypto.randomBytes(Math.ceil(length/2))
              .toString('hex') /** convert to hexadecimal format */
              .slice(0,length);   /** return required number of characters */
  };

  /**
   * hash password with sha512.
   * @function
   * @param {string} password - List of required fields.
   * @param {string} salt - Data to be validated.
   */
  let sha512 = function(password, salt){
      var hash = crypto.createHmac('sha512', salt); /** Hashing algorithm sha512 */
      hash.update(password);
      var value = hash.digest('hex');
      return {
          salt:salt,
          passwordHash:value
      };
  };

  function saltHashPassword(userpassword) {
      var salt = genRandomString(16); /** Gives us salt of length 16 */
      var passwordData = sha512(userpassword, salt);
      return passwordData;
  }

/* end password region */




app.listen(3000,
  () => console.log('Server On')
);

app.get('/', (req, res) => {
  res.send('Funcionando!');
});


/*rota para testar conexão com o servidor*/
app.post('/test-conection', (req, res) => {
  
  return res.status(200).json({
    success: true,
    msg: "Conexão bem sucedida."
  });
});


/*rota login*/
app.post('/sign-up', (req, res) => {

  let passwordData = saltHashPassword(req.body.password);

  let _id = uuidv4();
  let _user = req.body.user;
  let _hash = passwordData.passwordHash;
  let _salt = passwordData.salt;


  /*verifica se já existe alguem com o mesmo user*/
  connection.query("SELECT 1 FROM people WHERE people.user = ? LIMIT 1;",[
    _user
    ],  function(error, results){
        if(error) {
          console.log(error);
          return res.status(500).json({
            success: false,
            msg: "Erro de conexão com o banco."
          });
        }
        if(results.length>=1){
          return res.status(406).json({
            success: false,
            msg: "Esse usuario já existe!"
          });
        }else{
          /*insere user no banco*/
          connection.query("INSERT INTO people VALUES(?,?,?,?,DEFAULT);",[
                _id,
                _user,
                _hash,
                _salt
              ],
              function(error, results){ 
                if(error) {
                  console.log(error);
                  return res.status(500).json({
                    success: false,
                    msg: "Erro de conexão com o banco."
                  });
                }else{
                  return res.status(201).json( {
                    success: false,
                    msg: "Usuario criado!"
                  });
                }
          });
      }
  });
 
});

/* rota para logar usuario*/
app.post('/sign-in', (req, res) => {
  let passwordData = saltHashPassword(req.body.password);

  let _user = req.body.user;
  let _password = req.body.password;

  /* verifica se o user existe */
  connection.query("SELECT * FROM people WHERE people.user = ? LIMIT 1;",[
    _user
    ],
    function(error, results){
      if(error) { 
        
        return res.status(500).json({
          success: false,
          msg: "Erro de conexão com o banco."
        });
      }

      if(results.length <= 0){
        
        return res.status(406).json({
          success: false,
          msg: "Esse usuario não existe!"
        });
      }else{

        /*hasheia a senha recebida com o salt do banco e compara os resultados */
        let _salt  = results[0].salt;
        let _hashUser = (sha512(_password,_salt)).passwordHash;

        if(_hashUser === results[0].hash){ console.log("logado");

          const user = {
            user: results[0].user,
            value: results[0].value.toString(),
          };

          /*gera uma chave jwt*/
          const acessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);


          res.status(201).json({
            success: true,
            msg: acessToken,
          });

        }else{
          return res.status(406).json({
            success: false,
            msg: "Senha errada!"
          });
        }
      }
    }

  );


});

/*rota para realizar uma transferencia*/
app.post('/transfer', (req, res) => {
  let passwordData = saltHashPassword(req.body.password);

  let _userFrom = req.body.userFrom;
  let _userTo = req.body.userTo;

  let _value = req.body.value;
  let _pass = req.body.password;

  /*verifica se o usuario que quer transferir existe*/
  connection.query("SELECT * FROM people WHERE people.user = ? LIMIT 1;",[
    _userFrom
    ],
    function(error, resultsUserFrom){
      if(error) { 
        console.log(error);
        return res.status(500).json({
          success: false,
          msg: "Erro de conexão com o banco."
        });
      }

      if(resultsUserFrom.length <= 0){
        
        return res.status(406).json({
          success: false,
          msg: "Esse usuario não existe!"
        });
      }else{
        
        /*verifica se a senha enviada bate com a senha do usuario*/

        let _salt  = resultsUserFrom[0].salt;
        let _hashUser = (sha512(_pass,_salt)).passwordHash;

        if(_hashUser === resultsUserFrom[0].hash){
          /*verifica se o user tem dinhero para fazer a transferencia*/
          if(_value > resultsUserFrom[0].value){
            return res.status(406).json({
              success: false,
              msg: "Saldo insufuciente!"
            });
          }else{
            /*verifica se o valor da transferencia é valido*/
            if(_value<= 0){
              return res.status(406).json({
                success: false,
                msg: "O valor de transferencia é invalido!"
              });
            }

            /*verifica se o ele não estaa transferindo para si mesmo*/
            if(_userFrom == _userTo){
              return res.status(406).json({
                success: false,
                msg: "O remetente e o destinatário não podem ser a mesma pesssoa!"
              });
            }

            /*verifica se o user que irá receber existe*/
            let peopleFromId = resultsUserFrom[0].idPeople;           
            connection.query("SELECT * FROM people WHERE people.user = ? LIMIT 1;",[
              _userTo
              ],
              function(error, resultsUserTo){
                if(error) { 
                  console.log(error);
                  return res.status(500).json({
                    success: false,
                    msg: "Erro de conexão com o banco."
                  });
                }

                if(resultsUserTo.length <= 0){
                  return res.status(406).json({
                    success: false,
                    msg: "Usuario remetente não existe!"
                  });
                }else{
                  
                  /*separa as informações que serão usadas na transferencia*/

                  let peopleToId = resultsUserTo[0].idPeople;          

                  let userFromValue = resultsUserFrom[0].value -_value; 
                  let userToValue = parseFloat(resultsUserTo[0].value) + parseFloat(_value); 
       
                  /*inicia o processo de transação*/
                  connection.beginTransaction(function(err) {
                     if (err) {                  //Transaction Error (Rollback and release connection)
                        connection.rollback(function() {console.log("Deu ruim inicio");
                          return res.status(406).json({
                            success: false,
                            msg: "Houve um problema de conexão."
                          });
                        });
                    }

                    connection.query("UPDATE people SET people.value = ? WHERE people.user = ?;",[ //UPDATE People SET People.value = ? WHERE People.user = ?;
                     userFromValue, _userFrom
                    ],

                      function(error, resultsUserTo){
                        if(error){//Transaction Error (Rollback and release connection)
                        connection.rollback(function() { console.log("Deu ruim meio");
                          return res.status(406).json({
                            success: false,
                            msg: "Houve um problema de conexão."
                            });
                          });
                        }

                        connection.query("UPDATE people SET people.value = ? WHERE people.user = ?;",[ //UPDATE People SET People.value = ? WHERE People.user = ?;
                         userToValue, _userTo
                        ],
                          function(error, resultsUserTo){
                            if(error){//Transaction Error (Rollback and release connection)
                            connection.rollback(function() { console.log(error);
                              return res.status(406).json({
                                success: false,
                                msg: "Houve um problema de conexão."
                                });
                              });
                            }

                            connection.query("INSERT INTO transfer VALUES(?,?,?,?,DEFAULT);",[ //UPDATE People SET People.value = ? WHERE People.user = ?;
                             uuidv4(),peopleFromId,peopleToId,_value
                            ],
                              function(error, resultsUserTo){
                                if(error){//Transaction Error (Rollback and release connection)
                                connection.rollback(function() { console.log(error);
                                  return res.status(406).json({
                                    success: false,
                                    msg: "Houve um problema de conexão."
                                    });
                                  });
                                }

                                connection.commit(function(err) {
                                  if (err) {
                                      connection.rollback(function() {
                                      });
                                  } else {
                                    return res.status(201).json({
                                      success: true,
                                      msg: "Transferencia realizada com sucesso!"
                                    });
                                      //Success
                                  }
                                });
                            });
                          });                        
                        });
                    });
                }
              }
            );

          }

        }else{
          console.log("Senha errada");
          return res.status(406).json({
            success: false,
            msg: "Senha errada!"
          });
        }
      }
    }

  );

});

/*rota para pegar o saldo do user*/
app.post('/updateValue', verifyJWT, (req, res, next) => {

    let _user = req.body.user;

    connection.query("SELECT * FROM people WHERE people.user = ? LIMIT 1;",[
      _user
    ],
      function(error, result){
        if(error) { 
          console.log(error);
          return res.status(500).json({
            success: false,
            msg: "Erro de conexão com o banco."
          });
        }

        if(result.length <= 0){
          console.log("usuario to n existe");
          return res.status(406).json({
            success: false,
            msg: "Usuario remetente não existe!"
          });
        }else{
          let _value = result[0].value;
          return res.status(200).json({
            success: true,
            msg:{
              value: _value.toString(),
            }
          });
        }
      }
    );
    
  });

/*rota para pegar o histórico de transações do user*/
app.post('/updateTransactions', verifyJWT, (req, res, next) => {

    let _user = req.body.user;


    connection.query("SELECT * FROM people WHERE people.user = ? LIMIT 1;",[
    _user
    ],
    function(error, results){
      if(error) { 
        console.log(error);
        return res.status(500).json({
          success: false,
          msg: "Erro de conexão com o banco."
        });
      }

      if(results.length <= 0){
        
        return res.status(406).json({
          success: false,
          msg: "Esse usuario não existe!"
        });
      }else{

        connection.query("SELECT t.value, p1.user AS userFrom,  p2.user AS userTo, t.date  FROM transfer t LEFT JOIN people p1 ON t.idPeopleFrom = p1.idPeople LEFT JOIN people p2 ON t.idPeopleTo = p2.idPeople WHERE p1.user = ? OR p2.user = ? ORDER BY(t.date) DESC;",[
          _user,_user
        ],
          function(error, result){
            if(error) { 
              console.log(error);
              return res.status(500).json({
                success: false,
                msg: "Erro de conexão com o banco."
              });
            }

            if(result.length <= 0){
              return res.status(406).json({
                success: false,
                msg: "Sem transações!"
              });
            }else{
              let transactions= [];

              for(var i = 0 ; i < result.length; i++){
                let _input = result[i].userTo == _user;

                let _otherUser = _input? result[i].userFrom : result[i].userTo;

                let _type = _input? "Entrada" : "Saida";

                transactions.push(
                  {
                    user:_otherUser,
                    value: result[i].value,
                    date: result[i].date,
                    type: _type
                  }
                );
              }

              return res.status(200).json({
                success: true,
                msg: transactions
              });
            }
          }
        );

      }
    }

  );



    
    
  });




/*verifica jwt*/
function verifyJWT(req, res, next){
  var token = req.headers['authorization'];
  if (!token) return res.status(401).send({ auth: false, message: 'No token provided.' });
  
  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, function(err, decoded) {
    if (err) return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
    
    // se tudo estiver ok, salva no request para uso posterior
    req.userId = decoded.id;
    next();
  });
}
