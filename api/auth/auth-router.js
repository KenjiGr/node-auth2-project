const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const {BCRYPT_ROUNDS } = require("../secrets"); // use this secret!
const User = require('../users/users-model');
const bcrypt = require('bcryptjs');
const {tokenBuilder} = require('./auth-helpers');

router.post("/register", validateRoleName, (req, res, next) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);
  user.password = hash;
  User.add(user).then(saved => {
    res.status(201).json(saved)
  }).catch(next);
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let {username, password} = req.body;
  User.findBy({username}).then(([user]) => {
    if(user && bcrypt.compareSync(password, user.password)){
      const token = tokenBuilder(user);
      res.status(200).json({
        message: `${user.username} is back!`,
        token: token
      })
    }else{
      next({status: 401, message: 'Invalid credentials'})
    }
  })
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
