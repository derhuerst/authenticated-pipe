'use strict'

const {generateKeyPairSync, createSign, createVerify} = require('crypto')
const through2 = require('through2')
const createBuffer = require('./lib/buffer')

// from https://nodejs.org/api/crypto.html#crypto_class_sign
// todo: are these proper choices?
const createKeyPair = () => {
	const pair = generateKeyPairSync('ec', {
		namedCurve: 'sect239k1',
		publicKeyEncoding: {type: 'spki', format: 'pem'},
		privateKeyEncoding: {type: 'sec1', format: 'pem'}
	})
	return {
		publicKey: Buffer.from(pair.publicKey, 'utf8'),
		privateKey: Buffer.from(pair.privateKey, 'utf8')
	}
}
const DIGEST_ALGORITHM = 'SHA256'
const signer = (privateKey) => {
	const sign = (data) => {
		const signer = createSign(DIGEST_ALGORITHM)
		signer.end(data)
		return signer.sign(privateKey)
	}
	return sign
}
const verifier = (publicKey) => {
	const verify = (data, signature) => {
		const verifier = createVerify(DIGEST_ALGORITHM)
		verifier.end(data)
		return verifier.verify(publicKey, signature)
	}
	return verify
}

// todo: send this as a header
const KEY_LENGTH = createKeyPair().publicKey.byteLength
const SIGNATURE_LENGTH = signer(createKeyPair().privateKey)(Buffer.alloc(0)).byteLength
const PAYLOAD_LENGTH = 1024 // todo: make customisable

const createAuthenticatedReceiver = (verifyPeerPublicKey) => {
	if ('function' !== typeof verifyPeerPublicKey) {
		throw new Error('verifyPeerPublicKey must be a function')
	}

	const buf = createBuffer()
	let verify = null, signature = null

	const verifyAndPush = (out, flush, cb) => {
		while (true) {
			if (!signature) {
				// We expect a signature for the coming data.
				signature = buf.take(SIGNATURE_LENGTH)
				if (!signature) break // We don't have enough data yet.
			}

			// We expect data matching the received signature.
			const bytesToTake = flush ? Math.min(buf.size(), PAYLOAD_LENGTH) : PAYLOAD_LENGTH
			const payload = buf.take(bytesToTake)
			if (!payload) break // We don't have enough data yet.
			const isValid = verify(payload, signature)
			if (!isValid) return cb(new Error('invalid signature'))
			signature = null // We used the signature.
			out.push(payload)
		}
		cb()
	}

	function transform (data, _, cb) {
		const self = this
		buf.put(data)

		// Haven't received the peer public key yet, read it from the stream.
		if (!verify) {
			if (buf.size() < KEY_LENGTH) return cb()
			const peerPublicKey = buf.take(KEY_LENGTH)
			verifyPeerPublicKey(peerPublicKey, (err, isValid) => {
				if (err) return cb(err)
				if (isValid !== true) return cb(new Error('peer public key is not valid'))
				verify = verifier(peerPublicKey)
				verifyAndPush(self, false, cb)
			})
			return
		}

		verifyAndPush(self, false, cb)
	}

	function flush (cb) {
		// todo: throw if leftover data
		verifyAndPush(this, true, cb)
	}

	return through2(transform, flush)
}

const createAuthenticatedSender = (keyPair = null, _signer = signer) => {
	if (keyPair) {
		if (!Buffer.isBuffer(keyPair.privateKey)) {
			throw new Error('invalid/missing keyPair.privateKey')
		}
		if (!Buffer.isBuffer(keyPair.publicKey)) {
			throw new Error('invalid/missing keyPair.publicKey')
		}
	}
	const {privateKey, publicKey} = keyPair || createKeyPair()
	const sign = _signer(privateKey)

	const buf = createBuffer()
	let publicKeyWritten = false

	const signAndSend = (out, payload) => {
		if (!payload) return console.trace()
		const signature = sign(payload)
		out.push(signature)
		out.push(payload)
	}

	function transform (data, _, cb) {
		if (!publicKeyWritten) {
			this.push(publicKey)
			publicKeyWritten = true
		}

		buf.put(data)
		while (true) {
			const payload = buf.take(PAYLOAD_LENGTH)
			if (!payload) break; // We don't have enough data yet.
			signAndSend(this, payload)
		}
		cb()
	}

	function flush (cb) {
		const size = buf.size()
		if (size > 0) signAndSend(this, buf.take(size))
		cb()
	}

	return through2(transform, flush)
}

// todo: duplex
module.exports = {
	createKeyPair, signer, verifier,
	createAuthenticatedReceiver,
	createAuthenticatedSender
}
