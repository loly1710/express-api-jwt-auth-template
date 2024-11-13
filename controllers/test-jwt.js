// controllers/test-jwt.js

const express = require("express");
const router = express.Router();
const jwt = require("jsonwebtoken");

const user = {
  _id: 1,
  username: "test",
  password: "test",
};

router.get("/sign-token", (req, res) => {
  const token = jwt.sign({ user }, process.env.JWT_SECRET);

  res.json({ token });
});

// controllers/test-jwt.js
router.post("/verify-token", (req, res) => {
  try {
    const token = req.headers.authorization.split(" ")[1];
    // Add in verify method
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    res.json({ decoded });
  } catch (error) {
    res.status(401).json({ error: "Invalid token." });
  }

  //const token = req.headers.authorization;
  //const token = req.headers.authorization.split(' ')[1];
  //res.json({token });
});

module.exports = router;
