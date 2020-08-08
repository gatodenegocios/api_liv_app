const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const app = express();
const crypto = require('crypto');

app.use(express.json());
app.use(bodyParser.urlencoded({extended:true}));

app.set('view engine','ejs');

app.listen(3000,
	() => console.log('Server On')
);

app.get('/',(req,res) => {
	console.log("yaho");
	res.send('pe');
});
