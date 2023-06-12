const express = require('express');
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require('mongoose');
// const md5 = require('md5');
// const bcrypt = require("bcrypt");
require("dotenv").config();
const session = require('express-session');
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const LocalStrategy = require('passport-local');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.use(express.static("public"));
app.set('view engine','ejs')
const port = 3000;
app.use(bodyParser.urlencoded({extended:true}));
// const saltRounds = 10;
app.use(session({
    secret: "secret file.",
    resave: false,
    saveUninitialized: false,
    cookie:{}
}));
app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(process.env.URI);

const userSchema = new mongoose.Schema({
    googleId:String,
    facebookId:String,
    username:String,
    password:String,
    secret:Array
});


userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate)

// const secret = process.env.SECRET;
// userSchema.plugin(encrypt,{ secret:secret, encryptedFields:['password'] });

const User = mongoose.model("User",userSchema);



passport.use(new LocalStrategy(User.authenticate()));
// passport.serializeUser(User.serializeUser());
// passport.deserializeUser(User.deserializeUser());
passport.serializeUser(function(user, cb) {
    process.nextTick(function() {
      cb(null, { id: user.id, username: user.username });
    });
  });
  
  passport.deserializeUser(function(user, cb) {
    process.nextTick(function() {
      return cb(null, user);
    });
  });


passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "https://secrets-rl5f.onrender.com/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

passport.use(new FacebookStrategy({
    clientID: process.env.CLIENT_ID_FB,
    clientSecret: process.env.CLIENT_SECRET_FB,
    callbackURL: "https://secrets-rl5f.onrender.com./auth/facebook/secrets"
  },
  function(accessToken, refreshToken, profile, cb) {
    User.findOrCreate({ facebookId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));


app.get('/', (req, res) => {
    res.render('home')
});

app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile"] }
  ));

app.get("/auth/google/secrets", 
    passport.authenticate("google", { failureRedirect: '/login' }),
    function(req, res) {
        res.redirect('/secrets');
    });

app.get('/auth/facebook',
    passport.authenticate('facebook'));
  
app.get('/auth/facebook/secrets',
    passport.authenticate('facebook', { failureRedirect: '/login' }),
    function(req, res) {
      res.redirect('/secrets');
});

app.route("/login")
    .get((req,res)=>{
        res.render("login")
    })
    .post((req,res)=>{
        const loginUser = req.body.username;
        const loginPassword = req.body.password;
        // User.findOne({email:loginEmail})
        // .then((data)=>{
        //     bcrypt.compare(loginPassword,data,(err,result)=>{
        //         if(result=true){
        //             res.redirect("/secrets")
        //         } else {
        //             res.render("Invalid Password or Email")
        //         }
        //     })
                
        // })
        // .catch((error)=>{
        //     console.error(error)
        // })
        const user = new User({
            username:loginUser,
            password:loginPassword
        });

        req.login(user,(err)=>{
            if(err){
                console.log(err)
            } else {
                passport.authenticate("local")(req,res,()=>{
                    res.redirect("/secrets");
                })
            }
        })
    })

app.route("/register")
    .get((req, res) => {
        res.render('register')
    })
    .post((req,res)=>{
        const username = req.body.username;
        const loginPassword = req.body.password;
        User.register({username:username},loginPassword,(err,user)=>{
            if(err){
                console.log(err);
                res.redirect("/register")
            } else {
                passport.authenticate('local')(req,res,()=>{
                    console.log("redirected to get function")
                    res.redirect("/secrets");
                })
            }
        })
    })

app.route("/submit")
    .get((req,res)=>{
        if(req.isAuthenticated()){
            res.render("submit")
        } else {
            res.redirect("/login");
        }
    })
    .post((req,res)=>{
        const secrets = req.body.secret;
        console.log(secrets)
        User.findById(req.user.id)
        .then((data)=>{
            if(data){
                data.secret.push(req.body.secret);
                data.save()
                .then((data)=>{
                    res.redirect("/secrets")
                })
                .catch((err)=>{
                    console.error(err)
                })
            }
        })
        .catch((err)=>{
            console.error(err)
        })
        // const newSecret = new Secret({
        //     secret:secrets
        // });
        // newSecret.save()
        // .then((data)=>{
        //     res.redirect("/secrets");
        // })
        // .catch((error)=>{
        //     console.error(error);
        // })
    })

app.get("/secrets",(req,res)=>{
    User.find({"secret":{$ne:null}})
    .then((data)=>{
        res.render("secrets",{data:data})
    })
    .catch((err)=>{
        console.error(err)
    })
})

app.get("/logout",(req,res,next)=>{
    req.logout((err)=>{
        if(err){return next(err);}
        res.redirect("/")
    });
})
    



app.listen(port, () => {
    console.log(`App listening on port ${port}!`)
});