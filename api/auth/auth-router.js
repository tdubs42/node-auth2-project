const router = require('express').Router()

const tokenBuilder = require('./token-builder')
const {
  checkUsernameExists,
  validateRoleName,
  hashPassword,
  verifyHash
} = require('./auth-middleware')
const User = require('../users/users-model')

router.post('/register', validateRoleName, hashPassword, (req, res, next) => {
  User.add(req.cleanedPayload)
    .then(created => res.status(201).json(created))
    .catch(next)
})


router.post('/login', verifyHash, checkUsernameExists, (req, res, next) => {
  const token = tokenBuilder(req.body)

  res.json({
    message: `${req.body.username} is back!`,
    token
  })
})

module.exports = router
