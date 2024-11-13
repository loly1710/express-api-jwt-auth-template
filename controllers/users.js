// /controllers/users.js
const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/user');
const jwt = require('jsonwebtoken');
const router = express.Router();

router.post('/signup', async(req, res) => {
    try {
        // Check if the username is already taken
        const userInDatabase = await User.findOne({ username: req.body.username });
        
        if (userInDatabase) throw new Error ('Username already taken.'); /*{
            return res.status(400).json({error:'Username already taken.'});
        }*/

        // Create a new user with hashed password
        const user = await User.create({
            username: req.body.username,
            hashedPassword: bcrypt.hashSync(req.body.password, parseInt(process.env.SALT_ROUNDS)),
        });
        console.log(user);
        res.status(201).json({ user });
    } catch (error) {
        console.error(error);
        res.status(400).json({ error: error.message });
    }
    //res.json({ message: 'Signup route' });
});


router.post('/signin', async (req, res) => {
    try {
      const user = await User.findOne({ username: req.body.username });
      if (user && bcrypt.compareSync(req.body.password, user.hashedPassword)) {
        const token = jwt.sign(
          { username: user.username, _id: user._id },
          process.env.JWT_SECRET
        );
        res.status(200).json({ token });
      } else {
        res.status(401).json({ error: 'Invalid username or password.' });
      }
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });

/*router.post('/signin', async (req, res) => {
    try {
      const user = await User.findOne({ username: req.body.username });
      if (user && bcrypt.compareSync(req.body.password, user.hashedPassword)) {
        res.json({ message: 'You are authorized!' });
      } else {
        res.json({ message: 'Invalid credentials.' });
      }
    } catch (error) {
      res.status(400).json({ error: error.message });
    }
  });*/

module.exports = router;