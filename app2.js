//jshint esversion:6
require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
const connectEnsureLogin = require('connect-ensure-login'); // authorization



// const encrypt = require('mongoose-encryption'); for encryption with mongoose
// const md5 = require('md5'); /* for encrypting password with md5 */

const app = express();

app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));

// configure session middleware
app.use(session({
    secret: "dhejklahdjklhajkls", /* solitamente è meglio importare la chiave segreta da un environemtal variable */
    resave: false,
    saveUninitialized: false /* forces an unititialized session to be saved to the store */
}));

// configure more middleware
// initialize passport (see passport documentation)
app.use(passport.initialize());
app.use(passport.session()); /* set up our session with passport */

mongoose.connect("mongodb://127.0.0.1/userDB", {useNewUrlParser: true});

const userSchema = new mongoose.Schema ({
  username: String,
  password: String
});

// set up passport-local-mongoose
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);


// local strategy to authenticate user with username and password
passport.use(User.createStrategy());
// necessary when we use sessions
passport.serializeUser(User.serializeUser()); /* creates cookie and stuffs the message (user and identification) inside the cookie*/
passport.deserializeUser(User.deserializeUser()); /* allows passport to know who the user is and their identification using the cookie */

app.get("/", function(req, res){
  res.render("home");
});

app.get('/dashboard', connectEnsureLogin.ensureLoggedIn(), (req, res) => {
    res.send(`Hello ${req.user.username}. Your session ID is ${req.sessionID}.
     <a href="/logout">Log Out</a><br><br>
     <a href="/secret">Members Only</a>`);
  });

// mostro la pagina secrets solo se l'utente è già autenticato 
app.get("/secrets", function(req, res){
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});

app.get("/logout", connectEnsureLogin.ensureLoggedIn(), function(req, res, next) {
    req.logOut(function(err){
        if(err) {
            return next(err);
        }
    });
    res.redirect("/");
});

// REGISTER

app.route("/register")
  .get(function(req, res) {
    res.render("register");
  })
  .post(function(req, res){
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if (err){
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req,res, function(){
                res.redirect("/secrets");
            })
        }
    })
  });


  // LOGIN 

  app.route("/login")
  .get(function(req, res){
    res.render("login");
  })
  .post(function(req, res){
    const user = new User ({
        username: req.body.username,
        password: req.body.password
    });
    // use passport to authenticate new user
    req.login(user, function(err){
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function(){
                res.redirect("/secrets");
            });
        }
    })
 });


app.listen('3000', function() {
  console.log("Server started on port 3000.");
});
