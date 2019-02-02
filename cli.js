#!/usr/bin/env node
'use strict'

const mri = require('mri')
const pkg = require('./package.json')

const argv = mri(process.argv.slice(2), {
	boolean: ['help', 'h', 'version', 'v']
})

if (argv.help || argv.h) {
	process.stdout.write(`
Sign & send data:
	auth-pipe send
Receive data:
	auth-pipe receive [peer-public-key]
Example:
	# machine A
	echo 'secret message' | auth-pipe send --hex | private-pipe 'secret password' | airpaste
	# Your identity: f9d13459b110

	# machine B
	airpaste | private-pipe 'secret password' | auth-pipe receive f9d13459b110
	# Sender identity f9d13459b110 matches.
	# secret message
\n`)
	process.exit()
}

if (argv.version || argv.v) {
	process.stdout.write(pkg.name + ' ' + pkg.version + '\n')
	process.exit(0)
}

const {createHash} = require('crypto')
const baseEmoji = require('base-emoji')
const authStream = require('.')
const {createAuthenticatedSender, createAuthenticatedReceiver} = authStream

const formatKey = (buf) => {
	const id = createHash('sha256').update(buf).digest('hex').slice(0, 12)
	return argv.hex ? id : baseEmoji.toUnicode(id)
}
const hex = /[a-f0-9]+/i

const onError = (err) => {
	console.error(err)
	process.exit(1)
}

let stream
if (argv._[0] === 'send') {
	const keyPair = authStream.createKeyPair()
	console.error('Your identity:', formatKey(keyPair.publicKey))
	stream = createAuthenticatedSender(keyPair)
} else if (argv._[0] === 'receive') {
	// Because there's only *one* stdin, we can't interactively ask the
	// user if the public key of the peer is correct.
	let expectedKey = null
	if (argv._[1]) {
		expectedKey = argv._[1].trim()
		if (hex.test(expectedKey)) argv.hex = true
	}

	const verifyPeerPublicKey = (rawKey, cb) => {
		const actualKey = formatKey(rawKey)
		if (!expectedKey) {
			console.error('Sender identity:', actualKey)
			return cb(null, true)
		}
		const ok = actualKey.slice(0, expectedKey.byteLength) === expectedKey
		console.error('Sender identity', actualKey, ok ? 'matches.' : 'does not match!')
		cb(null, ok)
	}

	stream = createAuthenticatedReceiver(verifyPeerPublicKey)
} else {
	console.error('invalid mode')
	process.exit(1)
}

process.stdin.pipe(stream).pipe(process.stdout)
stream.once('error', (err) => {
	console.error(err + '')
	process.exit(1)
})
