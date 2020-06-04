const { RESTServer } = require('.')

const r = new RESTServer(7000, true)

r.start()
