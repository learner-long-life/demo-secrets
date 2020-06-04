'use strict'
// Client tests for server REST interface

const pbkdf2 = require('pbkdf2')
const randombytes = require('randombytes')
const { RemoteDB } = require('demo-client')
const { getImmutableKey } = require('demo-utils')
const secrets = require('.')
const { assert } = require('chai')
const secp256k1 = require('secp256k1')
const { toJS } = require('demo-utils')
const { Map } = require('immutable')

const rdb = new RemoteDB('localhost', 7000, false)

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

  secretIds.map(async (obj, secretId, i) => {
    const salt = obj.get('salt')
    console.log(`Reading salt ${salt} for secret ID ${secretId}`)
    const derivedKey = secrets.constructDerivedKey({ salt: Buffer.from(salt, 'hex'), keyLength: 32 })
    console.log('Salt (recovered):', salt)
    console.log('Derived Key (recovered):', derivedKey.toString('hex'))

    const secretSig = secrets.signWithPrivateKey(Buffer.from(secretId, 'hex')).toString('hex')
    console.log('Secret ID', secretId)
    console.log('Secret Sig', secretSig)
    const response4 = await rdb.getHTTP(`/api/secrets/${secretId}/${secretSig}/${publicKey}`)
    const encryptedHexString = JSON.parse(response4)['encryptedHexString']
    console.log('Retrieved Hex String', encryptedHexString)
    const decryptedObj = JSON.parse(secrets.decryptHexString({ encryptedHexString, key: derivedKey }))
    console.log('Decrypted JSON Object', JSON.stringify(decryptedObj))
  })
}

main()
