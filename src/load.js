const { parsed } = require('dotenv').config()
const { assert } = require('chai')
const pbkdf2 = require('pbkdf2')

const trimQuotes = (string) => {
  const firstChar = string[0]
  const lastChar = string[string.length - 1]
  const startIndex = (firstChar === '"' || firstChar === "'") ? 1 : 0
  const endIndex = (lastChar === '"' || lastChar === "'") ? string.length - 1 : string.length
  return string.substr(startIndex, endIndex)
}


const secp256k1 = require('secp256k1')

const load = {}

load.DEFAULT_ITERATIONS = 10000
load.DEFAULT_KEY_LENGTH_BYTES = 32

load.init = () => {
  load.publicKeyString = trimQuotes(parsed['PUBLIC_KEY'])
  load.privateKeyString = trimQuotes(parsed['PRIVATE_KEY'])

  load.publicKeyBuffer = Buffer.from(load.publicKeyString, 'hex')
  assert(load.publicKeyBuffer.length === 33, `Public key buffer had length ${load.publicKeyBuffer.length} instead of 33`)

  load.privateKeyBuffer = Buffer.from(load.privateKeyString, 'hex')
  assert(load.privateKeyBuffer.length === 32, `Private key buffer had length ${load.privateKeyBuffer.length} instead of 32`)
}

load.getPublicKeyString = () => {
  return load.publicKeyString
}


/**
 * @returns true if the loaded keypair for .env matches each other, false otherwise.
 */
load.verifyKeyPair = () => {
  const recoveredPublicKey = secp256k1.publicKeyCreate(load.privateKeyBuffer)
  return (recoveredPublicKey.toString('hex') === load.publicKeyString)
}

load.constructDerivedKey = ({ salt, iterations, keyLength }) => {
  const _iterations = iterations || load.DEFAULT_ITERATIONS
  const _keyLength = keyLength || load.DEFAULT_KEY_LENGTH_BYTES
  return pbkdf2.pbkdf2Sync(load.privateKeyBuffer, salt, _iterations, _keyLength, 'sha512')
}

/**
 * @returns 32-byte Buffer of recovered signature (signing the given nonce with the given private key)
 */
load.computeUserId = ({ nonce }) => {
  assert(nonce.length === 32, `Nonce length should be 32 bytes, instead was ${nonce.length}`)
  return load.signWithPrivateKey(nonce)
}

load.signWithPrivateKey = (bufferToSign) => {
  const sig = secp256k1.sign(bufferToSign, load.privateKeyBuffer)
  return sig.signature
}

module.exports = load
