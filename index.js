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

  CREATE TABLE People(
    idPeople VARCHAR(36) NOT NULL PRIMARY KEY,
    user VARCHAR(64) NOT NULL UNIQUE,
    hash VARCHAR(128) NOT NULL UNIQUE,
    salt VARCHAR(16) NOT NULL UNIQUE,
    value DOUBLE NOT NULL DEFAULT 1000
  ) ENGINE=InnoDB CHARACTER SET utf8;

  CREATE TABLE Transfer(
    idTransfer VARCHAR(36) NOT NULL PRIMARY KEY,
    idPeopleFrom VARCHAR(36) NOT NULL,
    idPeopleTo VARCHAR(36) NOT NULL,
    value DOUBLE NOT NULL,

    FOREIGN KEY (idPeopleFrom) REFERENCES People (idPeople),
    FOREIGN KEY (idPeopleTo) REFERENCES People (idPeople)
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




app.listen(3000,
  () => console.log('Server On')
);

app.get('/', (req, res) => {
  res.send('Funcionando!');
});

app.post('/sign-up', (req, res) => {

  let passwordData = saltHashPassword(req.body.password);

  let _id = uuidv4();
  let _user = req.body.user;
  let _hash = passwordData.passwordHash;
  let _salt = passwordData.salt;

  connection.query("SELECT 1 FROM People WHERE People.user = ? LIMIT 1;",[
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
        }else{console.log("ARIU");
        
          connection.query("INSERT INTO People VALUES(?,?,?,?,DEFAULT);",[
                _id,
                _user,
                _hash,
                _salt
              ],
              function(error, results){ 
                if(error) {console.log(_hash.length);console.log(_salt.length);
                  console.log(error);
                  return res.status(500).json({
                    success: false,
                    msg: "Erro de conexão com o banco."
                  });
                }else{
                  console.log("Usuario criado!");
                  return res.status(201).json( {
                    success: false,
                    msg: "Usuario criado!"
                  });
                }
          });
      }
  });
 // res.send('success');
});

app.post('/sign-in', (req, res) => {
  let passwordData = saltHashPassword(req.body.password);

  let _user = req.body.user;
  let _password = req.body.password;


  connection.query("SELECT * FROM People WHERE People.user = ? LIMIT 1;",[
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
        console.log("Usuario não existe");
        return res.status(406).json({
          success: false,
          msg: "Esse usuario não existe!"
        });
      }else{

        let _salt  = results[0].salt;
        let _hashUser = (sha512(_password,_salt)).passwordHash;

        if(_hashUser === results[0].hash){ console.log("logado");

          const user = {
            user: results[0].user,
            value: results[0].value.toString(),
          };


          const acessToken = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET);


          res.status(201).json({
            success: true,
            msg: acessToken,
          });

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

app.post('/transfer', (req, res) => {
  let passwordData = saltHashPassword(req.body.password);

  let _userFrom = req.body.userFrom;
  let _userTo = req.body.userTo;

  let _value = req.body.value;
  let _pass = req.body.password;

  console.log("recebi transfer de " + _userFrom+" pra " + _userTo+" de "+ +"  _value");
  connection.query("SELECT * FROM People WHERE People.user = ? LIMIT 1;",[
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
        console.log("Usuario não existe");
        return res.status(406).json({
          success: false,
          msg: "Esse usuario não existe!"
        });
      }else{
        console.log("User from existe");
        let _salt  = resultsUserFrom[0].salt;
        let _hashUser = (sha512(_pass,_salt)).passwordHash;

        if(_hashUser === resultsUserFrom[0].hash){ console.log("logado");

        console.log("a senha bate");
          if(_value > resultsUserFrom[0].value){
            console.log("saldo não");
            return res.status(406).json({
              success: false,
              msg: "Saldo insufuciente!"
            });
          }else{
           
            connection.query("SELECT * FROM People WHERE People.user = ? LIMIT 1;",[
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
                  console.log("usuario to n existe");
                  return res.status(406).json({
                    success: false,
                    msg: "Usuario remetente não existe!"
                  });
                }else{
                  console.log("usuario to existe");

                  let userFromValue = resultsUserFrom[0].value -_value;
                  let userToValue = resultsUserTo[0].value +_value;

                  connection.query("UPDATE People SET People.value = ? WHERE People.user = ?;",[ //UPDATE People SET People.value = ? WHERE People.user = ?;
                     userFromValue, _userFrom
                  ],
                    function(error, resultsUserTo){
                      if(error) { 
                        console.log(error);
                        return res.status(500).json({
                          success: false,
                          msg: "Erro de conexão com o banco."
                        });
                      }
                      console.log("Transferencia realizada com sucesso!");
                      return res.status(500).json({
                          success: true,
                          msg: "Transferencia realizada com sucesso!"
                        });

                    });

                }
              }
            );

          }
            
          

          //logado



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



function authenticateToken(req,res,next){
  const _authHeader = req.headers['authorization'];
  const _token = _authHeader && _authHeader.split(' ')[1];

  if (_token == null){ 
    console.log("erro 401"); 
  return res.sendStatus(401);
}

  jwt.verify(_token,process.env.ACCESS_TOKEN_SECRET, (err,user) => {
    if (err){ console.log("erro 403"); return res.sendStatus(403);}

    req.user = user;
    next();
  });
}
