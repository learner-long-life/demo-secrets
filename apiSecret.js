'use strict'
// Client to save a new crypto address

const pbkdf2 = require('pbkdf2')
const randombytes = require('randombytes')
const { RemoteDB } = require('demo-client')
const { setImmutableKey } = require('demo-utils')
const secrets = require('.')
const { assert } = require('chai')
const secp256k1 = require('secp256k1')
const { toJS, Logger } = require('demo-utils')
const { Map } = require('immutable')
const LOGGER = new Logger('client')

const rdb = new RemoteDB('localhost', 7000, false)

const uri = process.argv[2]
const projectId = process.argv[3]
const apiSecret = process.argv[4]
const description = process.argv[5] || ""

const main = async () => {
  await secrets.init()
  const publicKey = secrets.getPublicKeyString()
  const response = await rdb.getHTTP(`/api/nonces/${publicKey}`)
  LOGGER.debug(Object.keys(JSON.parse(response)))
  const { nonce } = JSON.parse(response)
  assert(typeof(nonce) === 'string', `Empty nonce returned for publicKey ${publicKey}`)
  const userId = (await secrets.computeUserId({ nonce: Buffer.from(nonce, 'hex') })).toString('hex')
  LOGGER.debug(`User ID ${userId}`)
  const response2 = await rdb.postHTTP(`/api/userIds/${userId}`, new Map({
    nonce: nonce, publicKey: publicKey,
  }))
  LOGGER.debug(JSON.stringify(response2))

  const salt = randombytes(32)
    //Buffer.from('bcb7cdf58ac4304a3f7a79ab05efda59646748e7c66e7e36b044d72b9b47f375', 'hex')
  const derivedKey = secrets.constructDerivedKey({ salt, keyLength: 32 })
  LOGGER.debug('Salt (to be saved):', salt.toString('hex'))
  LOGGER.debug('Derived Key:', derivedKey.toString('hex'))

  const secret = secrets.constructApiSecret({ uri, projectId, apiSecret })
  LOGGER.info('URI: ' + uri)
  LOGGER.info('Project ID: ' + projectId)
  LOGGER.info('API Secret: ' + apiSecret)
  const encryptedHexString = secrets.encryptJSON({ jsonObj: secret[0], key: derivedKey })

  const secretIdBuffer = secrets.computeSecretId(encryptedHexString)
  const secretId = secretIdBuffer.toString('hex')
  const secretSig = secrets.signWithPrivateKey(secretIdBuffer).toString('hex')
  LOGGER.debug('Secret ID', secretId)
  LOGGER.debug('Secret Sig', secretSig)
  const response3 = await rdb.postHTTP(`/api/secrets/${secretId}/${secretSig}/${publicKey}`, new Map({
    encryptedHexString: encryptedHexString,
  }))
  const response4 = await rdb.getHTTP(`/api/secrets/${secretId}/${secretSig}/${publicKey}`)
  LOGGER.debug(JSON.parse(response4)['encryptedHexString'])
  setImmutableKey(`salts/${secretId}`, new Map({ salt: salt.toString('hex') }))
}

main()
