const secrets = require('.')
const secp256k1 = require('secp256k1')
const randombytes = require('randombytes')

const main = async () => {
  await secrets.init()
  const nonce = randombytes(32)
  const userId = (await secrets.computeUserId({ nonce })).toString('hex')
  console.log(userId, userId.length)
}

main()
