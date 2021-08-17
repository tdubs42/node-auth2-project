require('dotenv').config()
const server = require('./api/server.js')
const {PORT} = require('./api/secrets')

server.listen(PORT, () => {
  console.log(`turtle up on port ${PORT}...`)
})
