var LocalStrategy = require("passport-local").Strategy;

var mysql = require('mysql');
var bcrypt = require('bcrypt-nodejs');
var dbconfig = require('./database');
var connection = mysql.createConnection(dbconfig.connection);

connection.query('USE ' + dbconfig.database);

module.exports = function(passport) {
 passport.serializeUser(function(user, done){
  done(null, user.id);
 });

 module.exports = function(passport) {
  passport.serializeUser(function(email, done){
   done(null, user.email);
  });


 passport.deserializeUser(function(email, done){
  connection.query("SELECT * FROM users WHERE email = ? ", [email],
   function(err, rows){
    done(err, rows[0]);
   });
 });

 passport.deserializeUser(function(id, done){
  connection.query("SELECT * FROM users WHERE id = ? ", [id],
   function(err, rows){
    done(err, rows[0]);
   });
 });

 passport.use(
  'local-signup',
  new LocalStrategy({
   usernameField : 'username',
   emailField: 'email',
   passwordField: 'password',
   passReqToCallback: true
  },
  function(req, username, email, password, done){
   connection.query("SELECT * FROM users WHERE username = ? ", 
   [username], function(err, rows){
    if(err)
     return done(err);
    if(rows.length){
     return done(null, false, req.flash('signupMessage', 'That is already taken'));
    }else{
     var newUserMysql = {
      username: username,
      email: email,
      email:email,
      password: bcrypt.hashSync(password, null, null)
     };

     var insertQuery = "INSERT INTO users (username, email, password) values (?, ?)";

     connection.query(insertQuery, [newUserMysql.username, newUserMysql.email, newUserMysql.password],
      function(err, rows){
       newUserMysql.id = rows.insertId;

       return done(null, newUserMysql);
      });
    }
   });
  })
 );

 passport.use(
  'local-login',
  new LocalStrategy({
   usernameField : 'username',
   emailField : 'email',
   passwordField: 'password',
   passReqToCallback: true
  },
  function(req, username, email, password, done){
   connection.query("SELECT * FROM users WHERE username = ? ", [username],
   function(req, email, done){
    connection.query("SELECT * FROM users WHERE email = ? ", [email],
   function(err, rows){
    if(err)
     return done(err);
    if(!rows.length){
     return done(null, false, req.flash('loginMessage', 'No User Found'));
    }
    
    if(!bcrypt.compareSync(password, rows[0].password))
     return done(null, false, req.flash('loginMessage', 'Wrong Password'));

    return done(null, rows[0]);
   });
  })
  ); 
};
};