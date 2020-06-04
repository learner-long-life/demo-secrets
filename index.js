const server = require('./src/server')
const load = require('./src/load')
const secrets = require('./src/secrets')
const password = require('./src/passwordgen')

module.exports = {
  ...server,
  ...load,
  ...secrets,
  ...password,
}
