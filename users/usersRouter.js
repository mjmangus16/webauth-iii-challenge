const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const Users = require("../users/users-model");
const restricted = require("../middleware/restricted");

const router = express.Router();

router.get("/", restricted, (req, res) => {
  Users.find()
    .then(users => {
      res.status(200).json(users);
    })
    .catch(err => {
      console.log(err);
      res.status(500).json({
        message: "There was an error when trying to process this request."
      });
    });
});

router.post("/register", (req, res) => {
  const newUser = req.body;

  Users.findByUsername(newUser.username).then(userFound => {
    if (userFound !== null) {
      return res.status(400).json({ message: "That username already exists!" });
    } else {
      bcrypt.genSalt(10, (err, salt) => {
        bcrypt.hash(newUser.password, salt, (err, hash) => {
          if (err) throw err;
          newUser.password = hash;
          Users.add(newUser)
            .then(user => {
              return res.status(200).json(user);
            })
            .catch(err =>
              res.status(400).json({
                message:
                  "Something went wrong when adding the user to the database"
              })
            );
        });
      });
    }
  });
});

router.post("/login", (req, res) => {
  const username = req.body.username;
  const password = req.body.password;

  Users.findByUsername(username).then(userFound => {
    if (userFound === null) {
      return res.status(404).json({ email: "User does not exist" });
    } else {
      bcrypt
        .compare(password, userFound.password)
        .then(isMatch => {
          if (isMatch) {
            const payload = {
              id: userFound.id,
              username: userFound.username
            };
            // Sign Token
            const secret = "secret123";
            jwt.sign(payload, secret, { expiresIn: 7200 }, (err, token) => {
              res.status(200).json({
                success: true,
                token: token
              });
            });
          } else {
            res.status(401).json({ message: "Invalid Credentials" });
          }
        })
        .catch(error => {
          res.status(500).json(error);
        });
    }
  });
});

router.get("/logout", (req, res) => {
  req.session.destroy(err => {
    if (err) {
      res.status(500).json({ message: "No one is logged in to be logged out" });
    } else {
      res.status(200).json({ message: "You are logged out" });
    }
  });
});

module.exports = router;
