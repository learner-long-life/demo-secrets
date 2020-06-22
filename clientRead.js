'use strict'
// Client tests for server REST interface

const pbkdf2 = require('pbkdf2')
const randombytes = require('randombytes')
const { RemoteDB } = require('demo-client')
const { Logger, getImmutableKey } = require('demo-utils')
const secrets = require('.')
const { assert } = require('chai')
const secp256k1 = require('secp256k1')
const { toJS } = require('demo-utils')
const { Map, List } = require('immutable')
const LOGGER = new Logger('clientRead')

const rdb = new RemoteDB('localhost', 7000, false)

const query = process.argv[2]
LOGGER.info('Query', query)

const main = async () => {
  await secrets.init()
  const publicKey = secrets.getPublicKeyString()
  const response = await rdb.getHTTP(`/api/nonces/${publicKey}`)
  console.log(Object.keys(JSON.parse(response)))
  const { nonce } = JSON.parse(response)
  assert(typeof(nonce) === 'string', `Empty nonce returned for publicKey ${publicKey}`)
  const userId = (await secrets.computeUserId({ nonce: Buffer.from(nonce, 'hex') })).toString('hex')
  console.log(`User ID ${userId}`)
  const response2 = await rdb.postHTTP(`/api/userIds/${userId}`, new Map({
    nonce: nonce, publicKey: publicKey,
  }))
  console.log(JSON.stringify(response2))

  const secretIds = getImmutableKey(`salts`, Map({}))

  const results = await Promise.all(List(secretIds.map(async (obj, secretId, i) => {
    const salt = obj.get('salt')
    LOGGER.debug(`Reading salt ${salt} for secret ID ${secretId}`)
    const derivedKey = secrets.constructDerivedKey({ salt: Buffer.from(salt, 'hex'), keyLength: 32 })
    LOGGER.debug('Salt (recovered):', salt)
    LOGGER.debug('Derived Key (recovered):', derivedKey.toString('hex'))

    const secretSig = secrets.signWithPrivateKey(Buffer.from(secretId, 'hex')).toString('hex')
    const response4 = await rdb.getHTTP(`/api/secrets/${secretId}/${secretSig}/${publicKey}`)
    const encryptedHexString = JSON.parse(response4)['encryptedHexString']
    LOGGER.debug('Secret ID', secretId)
    LOGGER.debug('Secret Sig', secretSig)
    LOGGER.debug('Retrieved Hex String', encryptedHexString)
    if (!encryptedHexString) {
      LOGGER.error('Null encrypted hex string for secret ID ', secretId)
      return null
    }
    const decryptedObj = JSON.parse(secrets.decryptHexString({ encryptedHexString, key: derivedKey }))
    LOGGER.debug('URI', decryptedObj['uri'])
    return decryptedObj
  }).values()).toJS())

  results.filter((obj, secretId, i) => {
    return obj && obj['uri'] && (obj['uri'].indexOf(query) !== -1)
  }).forEach((obj, secretId) => {
    console.log(JSON.stringify(obj, null, 2))
  })
}

main()
