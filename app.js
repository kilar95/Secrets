//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
/* encrypting using hash and salt */
const bcrypt = require('bcrypt'); 
const saltRounds = 10; 

// const encrypt = require('mongoose-encryption'); for encryption with mongoose
// const md5 = require('md5'); /* for encrypting password with md5 */

const app = express();

app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema ({
  email: String,
  password: String
});

const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res){
  res.render("home");
});

// REGISTER


app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res){
    bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
      const newUser = new User({
        email: req.body.username,
        password: hash
      });
      newUser.save(function(err){
        if(err){
          console.log(err);
        } else {
          res.render("secrets");
        }
      });
    })
  });


  // LOGIN 

  app.route("/login")
  .get(function(req, res){
    res.render("login");
  })
  .post(function(req, res){
    const username = req.body.username;
    const password = req.body.password;
  
    User.findOne({email: username}, function(err, foundUser){
      if(err){
        console.log(err);
      } else {
        if (foundUser) {
          // if (foundUser.password === password) {
          //    res.render("secrets");
          bcrypt.compare(password, foundUser.password, function(err, result){
              if (result) {
                res.render("secrets");
              }
          });
          }
        }
      })
    });


app.listen('3000', function() {
  console.log("Server started on port 3000.");
});
