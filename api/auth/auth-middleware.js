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

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) return next({
      status: 401,
      message: 'Token invalid'
    })
    req.decodedJwt = decoded
    return next()
  })
}

const only = role_name => (req, res, next) => {
  if (role_name !== 'admin') return next({
    status: 403,
    message: 'This is not for you'
  })
  next()
}


const checkUsernameExists = (req, res, next) => {
  const {username} = req.body

  User.findBy({username})
    .then(found => {
      if (found.length === 0) return next({
        status: 401,
        message: 'Invalid credentials'
      })
      req.found = found[0]
      next()
    })
    .catch(next)
}


const validateRoleName = (req, res, next) => {
  const {role_name} = req.body

  if (!role_name || typeof role_name === 'undefined' || role_name === '') {
    req.role_name = 'student'
    next()
  } else {
    if (role_name.trim() === /admin/i) return next({
      status: 422,
      message: 'Role name can not be admin'
    })
    if (role_name.trim().length > 32) return next({
      status: 422,
      message: 'Role name can not be longer than 32 chars'
    })
    if (role_name.trim() && role_name === 'instructor') {
      req.role_name = role_name.trim()
      req.role_id = 2
      return next()
    }
    User.findBy({role_name})
      .then(found => {
        if (!found || typeof found === 'undefined') {
          req.role_name = role_name.trim()
          return next()
        }
        if (found) {
          req.role_name = role_name.trim()
          req.role_id = found.role_id
          return next()
        }
      })
      .catch(next)
  }
}

const hashPassword = (req, res, next) => {
  req.cleanedPayload = {
    username: req.body.username,
    password: bcrypt.hashSync(req.body.password),
    role_name: req.role_name,
    role_id: req.role_id
  }
  next()
}

const verifyHash = (req, res, next) => {
  const {
    username,
    password
  } = req.body
  User.findBy({username})
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) return next()
      return next({
        status: 401,
        message: 'Invalid credentials'
      })
    })
    .catch(next)
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
  hashPassword,
  verifyHash
}
