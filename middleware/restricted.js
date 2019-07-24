const jwt = require("jsonwebtoken");

module.exports = (req, res, next) => {
  const token = req.headers.authorization;
  const secret = "secret123";

  if (token) {
    jwt.verify(token, secret, (err, decoded) => {
      if (err) {
        res.status(401).json({ msg: "You shall not pass!" });
      } else {
        next();
      }
    });
  } else {
    res.status(400).json({ msg: "No token provided" });
  }
};
