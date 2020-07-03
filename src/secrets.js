const { keccak256 } = require('ethereumjs-util')
const aesjs = require('aes-js')

const secrets = {}

secrets.constructGenericSecret = ({ description, genericSecret }) => {
  const now = new Date()
  return [{
    description,
    genericSecret,
  }, {
    createdDateTime: now.toUTCString(),
    modifiedDateTime: now.toUTCString(),
  }]
}

secrets.constructApiSecret = ({ uri, projectId, apiSecret }) => {
  const now = new Date()
  return [{
    uri,
    projectId,
    apiSecret,
  }, {
    createdDateTime: now.toUTCString(),
    modifiedDateTime: now.toUTCString(),
  }]
}

secrets.constructCoinAddress = ({ coinSymbol, address, description }) => {
  const now = new Date()
  return [{
    coinSymbol,
    address,
    description,
  }, {
    createdDateTime: now.toUTCString(),
    modifiedDateTime: now.toUTCString(),
  }]
}

secrets.constructLogin = ({ username, password, uri }) => {
  const now = new Date()
  return [{
    username,
    password,
    uri,
  }, {
    createdDateTime: now.toUTCString(),
    modifiedDateTime: now.toUTCString(),
  }]
}

secrets.encryptJSON = ({ jsonObj, key }) => {
  const text = JSON.stringify(jsonObj)
  const textBytes = aesjs.utils.utf8.toBytes(text)
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5))
  const encryptedBytes = aesCtr.encrypt(textBytes)
  const encryptedHexString = aesjs.utils.hex.fromBytes(encryptedBytes)
  return encryptedHexString
}

secrets.decryptHexString = ({ encryptedHexString, key }) => {
  const encryptedBytes = aesjs.utils.hex.toBytes(encryptedHexString);
 
  // The counter mode of operation maintains internal state, so to
  // decrypt a new instance must be instantiated.
  const aesCtr = new aesjs.ModeOfOperation.ctr(key, new aesjs.Counter(5));
  const decryptedBytes = aesCtr.decrypt(encryptedBytes);
 
  // Convert our bytes back into text
  const decryptedText = aesjs.utils.utf8.fromBytes(decryptedBytes);
  return decryptedText
}
  
secrets.computeSecretId = (encryptedHexString) => {
  const secretObj = { encryptedHexString }
  return keccak256(JSON.stringify(secretObj))
}

secrets.computeSecretSig = ({ secretId, privateKeyString }) => {
  const privateKey = Buffer.from(privateKeyString, 'hex')
  return secp256k1.sign(secretId, privateKey)
}

module.exports = secrets
