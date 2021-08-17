const router = require('express').Router()
const bcrypt = require('bcryptjs')

const tokenBuilder = require('./token-builder')
const {
  checkUsernameExists,
  validateRoleName
} = require('./auth-middleware')
const {
  JWT_SECRET,
  SALT
} = require('../secrets')
const User = require('../users/users-model')

router.post('/register', validateRoleName, (req, res, next) => {
  let user = {
    username: req.body.username,
    password: req.body.password,
    role_name: req.body.role_name
  }

  user.password = bcrypt.hashSync(user.password, SALT)

  User.add(user)
    .then(created => res.status(201).json(created))
    .catch(next)
})


router.post('/login', checkUsernameExists, (req, res, next) => {
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
})

module.exports = router
