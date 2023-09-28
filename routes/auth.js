var express = require("express");
var router = express.Router();

const mongoose = require("mongoose");

const bcrypt = require("bcrypt");
const saltRounds = 10;

const User = require("../models/User");

const { isLoggedIn, isLoggedOut } = require('../middleware/route-guard');

router.get("/signup", isLoggedOut, (req, res, next) => {
  res.render("auth/signup.hbs");
});

router.post("/signup", isLoggedOut, (req, res, next) => {
  // console.log("The form data: ", req.body);

  const { username, email, password } = req.body;

  if (!username || !email || !password) {
    res.render("auth/signup", {
      errorMessage:
        "All fields are mandatory. Please provide your username, email and password.",
    });
    return;
  }
  // COMMENTED OUT FOR TESTING//
  //   const regex = /(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,}/;
  //   if (!regex.test(password)) {
  //     res.status(500).render("auth/signup", {
  //       errorMessage:
  //         "Password needs to have at least 6 chars and must contain at least one number, one lowercase and one uppercase letter.",
  //     });
  //     return;
  //   }

  bcrypt
    .genSalt(saltRounds)
    .then((salt) => bcrypt.hash(password, salt))
    .then((hashedPassword) => {
      return User.create({
        username,
        email,
        passwordHash: hashedPassword,
      });
    })
    .then((userFromDB) => {
      console.log("Newly created user is: ", userFromDB);
      res.redirect("/auth/login");
    })
    .catch((error) => {
      if (error instanceof mongoose.Error.ValidationError) {
        res.status(500).render("auth/signup", { errorMessage: error.message });
      } else if (error.code === 11000) {
        console.log(
          " Username and email need to be unique. Either username or email is already used. "
        );

        res.status(500).render("auth/signup", {
          errorMessage: "Invalid username, email, or password",
        });
      } else {
        next(error);
      }
    });
});

router.get("/login", isLoggedOut, (req, res, next) => {
  res.render("auth/login.hbs");
});

router.post("/login", isLoggedOut, (req, res, next) => {
  console.log("SESSION =====> ", req.session);
  const { email, password } = req.body;

  if (email === "" || password === "") {
    res.render("auth/login", {
      errorMessage: "Please enter both, email and password to login.",
    });
    return;
  }

  User.findOne({ email })
    .then((user) => {
      if (!user) {
        console.log("Email not registered. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
        return;
      } else if (bcrypt.compareSync(password, user.passwordHash)) {
        req.session.user = user;
        console.log("Session after success ===>", req.session);
        res.redirect("/users/userProfile");
      } else {
        console.log("Incorrect password. ");
        res.render("auth/login", {
          errorMessage: "User not found and/or incorrect password.",
        });
      }
    })
    .catch((error) => next(error));
});

router.post("/logout", isLoggedIn, (req, res, next) => {
  req.session.destroy((err) => {
    if (err) next(err);
    res.redirect("/auth/login");
  });
});

module.exports = router;
