const express = require('express')
const randombytes = require('randombytes')

const { setImmutableKey: set, getImmutableKey: get, fromJS, Logger, ensureDir, DB_DIR }
	      = require('demo-utils')
const { Map } = require('immutable')
const http = require('http')
const path = require('path')
const { assert } = require('chai')
const { keccak256 } = require('ethereumjs-util')
const secp256k1 = require('secp256k1')

const LOGGER = new Logger('rest-server')

var bodyParser = require('body-parser')

const server = {}

server.DEFAULT_PORT = 7000
server.SECRETS_DIR = 'secrets'
server.NONCES_DIR = 'nonces'

server.verifySecretSig = ({ secretIdString, secretSigString, publicKeyString }) => {
  const publicKeyBuffer = Buffer.from(publicKeyString, 'hex')
  const secretIdBuffer = Buffer.from(secretIdString, 'hex')
  const secretSigBuffer = Buffer.from(secretSigString, 'hex')

  return secp256k1.verify(
    secretIdBuffer, secretSigBuffer, publicKeyBuffer
  )
}

server.verifyUserId = ({ userIdString, publicKeyString }) => {
  const publicKeyBuffer = Buffer.from(publicKeyString, 'hex')
  const userIdBuffer = Buffer.from(userIdString, 'hex')

  let nonce = get(`/${server.NONCES_DIR}/${publicKeyString}`, new Map({}))
  if (nonce.isEmpty()) {
    throw new Error(`Missing nonce for public key ${publicKeyString}`)
  }
  const recoveredNonceBuffer = Buffer.from(nonce.get('nonce'), 'hex')
  return secp256k1.verify(
    recoveredNonceBuffer, userIdBuffer, publicKeyBuffer
  )
}

server.RESTServer = class {

  constructor(_port, _allowCORS) {
    this.port = _port || server.DEFAULT_PORT
    this.app  = express()

    // configure app to use bodyParser()
    // this will let us get the data from a POST
    this.app.use(bodyParser.json({limit: '50mb'}));
    this.app.use(bodyParser.urlencoded({limit: '5mb', extended: true}));

    if (_allowCORS) {
      // Allow CORS for development use
      this.app.use((req, res, next) => {
        res.header("Access-Control-Allow-Origin", "*");
        res.header("Access-Control-Allow-Headers", "Democracy-Overwrite, Origin, X-Requested-With, Content-Type, Accept");
        next();
      })
    }
    this.router = express.Router()
    this.populateRoutes(this.router)
    this.app.use('/api', this.router)
    ensureDir(path.join(DB_DIR, server.SECRETS_DIR))
    ensureDir(path.join(DB_DIR, server.NONCES_DIR))
  }

  getRouter() {
    return this.router
  }

  getApp() {
    return this.app
  }

  populateRoutes(_router) {
    // middleware to use for all requests
    _router.use((req, res, next) => {
        // do logging
        //LOGGER.debug('Received route', req)
        next() // make sure we go to the next routes and don't stop here
    });

    _router.route('/userIds/:userId').post((req, res) => {
      const userId = req.params.userId
      const jsBody = fromJS(req.body)
      console.log(jsBody.toJS())
      console.log(userId)
      const nonceString = jsBody.get('nonce')
      const publicKeyString = jsBody.get('publicKey')

      const verified = server.verifyUserId({ publicKeyString, userIdString: userId })

      const result = Map({ result: verified })
      res.json(result.toJS())
    })

    _router.route('/nonces/:publicKey').get((req, res) => {
      const publicKey = req.params.publicKey
      let nonce = get(`/${server.NONCES_DIR}/${publicKey}`, new Map({}))
      if (nonce.isEmpty()) {
        const now = new Date()
        nonce = new Map({
          nonce: randombytes(32).toString('hex'),
          publicKey: publicKey,
          timeStamp: now.getTime(),
          dateTimeString: now.toUTCString(),
        })
        set(`/${server.NONCES_DIR}/${publicKey}`, nonce)
      }
      res.json(nonce.toJS())
    })

    _router.route('/secrets/:secretId/:secretIdSig/:publicKey').get((req, res) => {
      const secretId  = req.params.secretId
      const secretSig = req.params.secretIdSig
      const publicKey = req.params.publicKey
      const verified  = server.verifySecretSig({
        secretIdString  : secretId,
        secretSigString : secretSig,
        publicKeyString : publicKey,
      })
      const message = `secret ID ${secretId} ` +
        `with secret ID sig ${secretSig}` +
        `with public key ${publicKey}`
      console.log('Trying to verify', message)
      assert(verified, `Failed to verify ` + message)
      const secret = get(`/${server.SECRETS_DIR}/${secretId}`, new Map({}))
      res.json(secret.toJS())
    })

    _router.route('/secrets/:secretId/:secretIdSig/:publicKey').post((req, res) => {
      const secretId  = req.params.secretId
      const secretSig = req.params.secretIdSig
      const publicKey = req.params.publicKey
      console.log('POST secrets')
      const verified  = server.verifySecretSig({
        secretIdString  : secretId,
        secretSigString : secretSig,
        publicKeyString : publicKey,
      })
      const message = `secret ID ${secretId} ` +
        `with secret ID sig ${secretSig}` +
        `with public key ${publicKey}`
      console.log('Trying to verify', message)
      assert(verified, `Failed to verify ` + message)

      const jsBody = fromJS(req.body)

      const recoveredSecretId = keccak256(JSON.stringify(req.body)).toString('hex')

      assert.equal(recoveredSecretId, secretId, `Mismatched secret IDs for ${JSON.stringify(req.body)}`)
      const overwrite = (req.headers['democracy-overwrite'] === 'true')
      try {
        const result = set(`/${server.SECRETS_DIR}/${secretId}`, jsBody, overwrite)
        res.json({result: result, body: jsBody})
      } catch(e) {
        LOGGER.error('Failed to set key:', e, secretId)
        res.json({result: false, error: e})
      }
    })

    _router.route('/test/:testSpace').get((req, res) => {
      const testSpace = req.params.testSpace
      const val = get(`/test/${testSpace}`, '')
      res.json({ ...val.toJS() })
    })

    _router.route('/test/:testSpace').post((req, res) => {
      const testSpace = req.params.testSpace
      LOGGER.debug('BODY', req.body)
      const testVal = fromJS(req.body)
      // Always allow overwriting on tests, so we can reset the state
      const overwrite = (req.headers['democracy-overwrite'] === 'true')
      set(`/test/${testSpace}`, testVal, overwrite)
      res.json({ message: 'Test posted!', ...req.body });
    })
   
  }

  start() {
    LOGGER.debug(`Starting server on  port ${this.port}`)
    this.server = http.createServer(this.app).listen(this.port)
  }
  
  listen() {
    const server = this.app.listen(this.port, () => {
      console.log(`Express server listening on port ${server.address().port}`)
    })
    return server
  }

  stop() {
    if (this.server) {
      LOGGER.debug(`Stopping server on  port ${this.port}`)
      this.server.close()
    } else {
      LOGGER.debug(`Trying to stop server that's not started.`)
    }
  }

}

module.exports = server
