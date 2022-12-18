//jshint esversion:6

require('dotenv').config();
const express = require('express');
const ejs = require('ejs');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require("passport-local-mongoose");
const connectEnsureLogin = require('connect-ensure-login'); // authorization
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const FacebookStrategy = require('passport-facebook').Strategy;


// const encrypt = require('mongoose-encryption'); for encryption with mongoose
// const md5 = require('md5'); /* for encrypting password with md5 */

const app = express();

app.use(express.static(__dirname + '/public'));
app.set('view engine', 'ejs');
app.use(express.urlencoded({extended: true}));

// configure session middleware
app.use(session({
    secret: process.env.SECRET, /* solitamente è meglio importare la chiave segreta da un environemtal variable */
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
  password: String,
  googleId: String,
  facebookId: String,
  secret: String
});

// set up passport-local-mongoose
userSchema.plugin(passportLocalMongoose);
// plugin for findorcreate pseudo method
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);


// Configuring local strategy to authenticate user with username and password
passport.use(User.createStrategy());

// serialize and deserialize using passport
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, {
        id: user.id,
        username: user.username,
        picture: user.picture
      });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


// Configuring google Strategy
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

//configuring facebook strategy
passport.use(new FacebookStrategy({
    clientID: process.env.APP_ID,
    clientSecret: process.env.APP_SECRET,
    callbackURL: "http://localhost:3000/auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


// GET
app.get("/", function(req, res){
  res.render("home");
});

// authenticate with google
app.get("/auth/google",
    passport.authenticate("google", {scope: ["profile"], prompt: 'select_account' }));

app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: "/login" }),
    function(req, res) {
      // Successful authentication, redirect to secrets.
      res.redirect('/secrets');
});

//authenticate with facebook
app.get('/auth/facebook',
  passport.authenticate('facebook'));

app.get('/auth/facebook/secrets',
  passport.authenticate('facebook', { failureRedirect: '/login' }),
  function(req, res) {
    // Successful authentication, redirect to secrets.
    res.redirect('/secrets');
  });


app.get("/secrets", function(req, res){
    User.find({"secret": {$ne: null}}, function(err, foundUsers){
        if (err) {
            console.log(err);
        } else {
            if (foundUsers) {
                res.render("secrets", {usersWithSecrets: foundUsers});
            }
        }
    })
});

// mostro la pagina submit solo se l'utente è già autenticato 
app.route("/submit")
    .get(function(req, res){
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
})
.post(function(req, res){
    const submittedSecret = req.body.secret;

    User.findById(req.user.id, function(err, foundUser){
        if (err) {
            console.log(err);
         } else {
            if (foundUser) {
                foundUser.secret = submittedSecret;
            foundUser.save(function(){
                 res.redirect("/secrets");
            })};     
         }
    })
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








