'use strict'
// Test enciphering and deciphering text with AES CTR mode

const secrets = require('.')
const randombytes = require('randombytes')
const { assert } = require('chai')

const main = async () => {
  await secrets.init()
  const jsonObjs = secrets.constructLogin({
    username: 'booberry',
    password: 'bibimbap',
    uri: 'https://loo.li',
  })
  const key = Buffer.from('55ed3bd632ad21ffeef9dcf3c069120d149e832fae47fd126151a5e013679525', 'hex')
    //randombytes(32) // 256 bit / 32 byte key
  console.log('Key', key.toString('hex'))

  const jsonObj = jsonObjs[0] // second obj is timestamp object, not to be encrypted

  const encryptedHexString = secrets.encryptJSON({ jsonObj, key })
  const jsonString = JSON.stringify(jsonObj)
  console.log('JSON Object', jsonString, jsonString.length)
  console.log('Encrypted Hex String', encryptedHexString, encryptedHexString.length)
  const decryptedText = secrets.decryptHexString({ encryptedHexString, key }) 
  const decryptedObj = JSON.parse(decryptedText)
  assert.equal(JSON.stringify(jsonObj), JSON.stringify(decryptedObj), `Mismatch between encrypted and decrypted JSON objects`)
}

main()
