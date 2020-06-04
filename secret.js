const randombytes = require('randombytes')
const aesjs = require('aes-js')
const pbkdf2 = require('pbkdf2')
const { setImmutableKey: set, getImmutableKey: get, ensureDir, DB_DIR, Logger } = require('demo-utils')
const secrets = require('.')

const readline = require('readline')
const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
})

const LOGGER = new Logger('save-secret')

const properties = [
  {
    name: 'username',
    validator: /^[a-zA-Z\s\-]+$/,
    warning: 'Username must be only letters, spaces, or dashes',
  },
  {
    name: 'password',
    hidden: true,
  }
]


const main = async () => {
  await secrets.init()
  prompt.start()
  prompt.get(properties, (err, result) => {
    if (err) { return onErr(err); }
    console.log(result);
  })

}

main()
