//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const encrypt = require('mongoose-encryption');

const app = express();

app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));

mongoose.connect("mongodb://127.0.0.1/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema ({
  email: String,
  password: String
});

// for encrypting the password
userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ['password'] });


const User = new mongoose.model("User", userSchema);


app.get("/", function(req, res){
  res.render("home");
});

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
        if (foundUser.password === password) {
          res.render("secrets");
        }
      }
    }
  })
});

app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res){
    const newUser = new User({
      email: req.body.username,
      password: req.body.password
    });

    newUser.save(function(err){
      if(err){
        console.log(err);
      } else {
        res.render("secrets");
      }
    });
  });

app.listen('3000', function() {
  console.log("Server started on port 3000.");
});
