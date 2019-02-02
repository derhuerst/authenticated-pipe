'use strict'

const {generateKeyPairSync, createSign, createVerify} = require('crypto')
const through2 = require('through2')
const duplexer = require('duplexer3')
const createBuffer = require('./lib/buffer')

// from https://nodejs.org/api/crypto.html#crypto_class_sign
// todo: are these proper choices?
const createKeyPair = () => {
	const pair = generateKeyPairSync('ec', {
		namedCurve: 'sect239k1',
		publicKeyEncoding: {type: 'spki', format: 'pem'},
		privateKeyEncoding: {type: 'pkcs8', format: 'pem'}
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

const uintToBuf = (x) => {
	const buf = Buffer.alloc(2)
	buf.writeUInt16LE(x)
	return buf
}
const bufToUint = buf => buf.readUInt16LE()

const createAuthenticatedReceiver = (verifyPeerPublicKey) => {
	if ('function' !== typeof verifyPeerPublicKey) {
		throw new Error('verifyPeerPublicKey must be a function')
	}

	const buf = createBuffer()
	let peerPublicKeyLength = null, verify = null
	let signatureLength = null, signature = null
	let chunkSize = null

	const verifyAndPush = (out, flush, cb) => {
		while (true) {
			if (signatureLength === null) {
				// We expect the length of the coming signature.
				const lBuf = buf.take(2)
				if (!lBuf) break // We don't have enough data yet.
				signatureLength = bufToUint(lBuf)
			}
			if (!signature) {
				// We expect a signature for the coming data.
				signature = buf.take(signatureLength)
				if (!signature) break // We don't have enough data yet.
			}

			// We expect data matching the received signature.
			const bytesToTake = flush ? Math.min(buf.size(), chunkSize) : chunkSize
			const payload = buf.take(bytesToTake)
			if (!payload) break // We don't have enough data yet.

			const isValid = verify(payload, signature)
			signatureLength = null
			signature = null
			if (!isValid) return cb(new Error('invalid signature'))
			out.push(payload)
		}
		cb()
	}

	function transform (data, _, cb) {
		const self = this
		buf.put(data)

		if (chunkSize === null) {
			const lBuf = buf.take(2)
			if (!lBuf) return cb()
			chunkSize = bufToUint(lBuf)
		}
		if (peerPublicKeyLength === null) {
			const lBuf = buf.take(2)
			if (!lBuf) return cb()
			peerPublicKeyLength = bufToUint(lBuf)
		}

		// Haven't received the peer public key yet.
		if (!verify) {
			const peerPublicKey = buf.take(peerPublicKeyLength)
			if (!peerPublicKey) return cb()
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
		verifyAndPush(this, true, cb)
	}

	return through2(transform, flush)
}

const createAuthenticatedSender = (keyPair = null, chunkSize = 10 * 1024) => {
	if (keyPair) {
		if (!Buffer.isBuffer(keyPair.privateKey)) {
			throw new Error('invalid/missing keyPair.privateKey')
		}
		if (!Buffer.isBuffer(keyPair.publicKey)) {
			throw new Error('invalid/missing keyPair.publicKey')
		}
	}
	const {privateKey, publicKey} = keyPair || createKeyPair()
	const sign = signer(privateKey)

	const buf = createBuffer()
	let headerSent = false

	const signAndSend = (out, payload) => {
		const signature = sign(payload)
		out.push(uintToBuf(signature.byteLength))
		out.push(signature)
		out.push(payload)
	}

	function transform (data, _, cb) {
		if (!headerSent) {
			this.push(uintToBuf(chunkSize))
			this.push(uintToBuf(publicKey.byteLength))
			this.push(publicKey)
			headerSent = true
		}

		buf.put(data)
		while (true) {
			const payload = buf.take(chunkSize)
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

	const out = through2(transform, flush)
	out.publicKey = publicKey
	return out
}

const createAuthenticatedStream = (verifyPeerPublicKey, keyPair = null, chunkSize = 10 * 1024) => {
	const sender = createAuthenticatedSender(keyPair, chunkSize)
	const receiver = createAuthenticatedReceiver(verifyPeerPublicKey)
	return duplexer(sender, receiver)
}

module.exports = Object.assign(createAuthenticatedStream, {
	createKeyPair, signer, verifier,
	createAuthenticatedReceiver,
	createAuthenticatedSender
})
