const jwt = require('jsonwebtoken')
const bcrypt = require('bcryptjs')
const {JWT_SECRET} = require('../secrets')
const User = require('../users/users-model')

const restricted = (req, res, next) => {
  const token = req.headers.authorization

  if (!token) return next({
    status: 401,
    message: 'Token required'
  })

  jwt.verify(token, JWT_SECRET, (sad, happy) => {
    if (sad) return next({
      status: 401,
      message: 'Token invalid'
    })
    req.token = happy
    next()
  })
}

const only = role_name => (req, res, next) => {
  if (role_name === 'admin') return next()
  if (role_name !== 'admin') return next({
    status: 403,
    message: 'This is not for you'
  })
}


const checkUsernameExists = (req, res, next) => {
  const {username} = req.body

  User.findBy({username})
    .then(found => {
      if (found.length > 0) return next()
      next({
        status: 401,
        message: 'Invalid credentials'
      })
    })
    .catch(next)
}


const validateRoleName = (req, res, next) => {
  const {role_name} = req.user

  if (role_name.trim().length
    === 0
    || !role_name
    || typeof role_name
    === 'undefined') return {
    ...req.user,
    role_name: 'student'
  } && next()

  if (role_name.trim() === /admin/i) return next({
    status: 422,
    message: 'Role name can not be admin'
  })
  if (role_name.trim().length > 32) return next({
    status: 422,
    message: 'Role name can not be longer than 32 chars'
  })

  req.role_name = role_name.trim()
  next()
}

const hashPassword = (req, res, next) => {
  req.user = {
    username: req.user.username,
    password: bcrypt.hashSync(req.body.password),
    role_name: req.role_name
  }
  next()
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  hashPassword
}
