'use strict'

const {randomBytes} = require('crypto')
const {createKeyPair, createAuthenticatedReceiver, createAuthenticatedSender} = require('.')

const onError = (err) => {
	console.error(err)
	process.exit(1)
}

const data = randomBytes(10 * 1024 * 1024) // 10 MB
const keyPair = createKeyPair()
const verifyPeerPublicKey = (key, cb) => {
	cb(null, Buffer.compare(keyPair.publicKey, key) === 0)
}

const sender = createAuthenticatedSender(keyPair)
sender.once('error', onError)
const receiver = createAuthenticatedReceiver(verifyPeerPublicKey)
receiver.once('error', onError)
sender.pipe(receiver)
receiver.on('data', () => {})

const t0 = Date.now()
receiver.once('end', () => {
	const ms = Date.now() - t0
	console.log('Wrote', data.byteLength, 'bytes in', ms, 'ms.')
})
sender.end(data)
