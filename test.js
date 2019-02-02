'use strict'

const tape = require('tape')
const {randomBytes} = require('crypto')

const createBuffer = require('./lib/buffer')
const {
	createKeyPair, signer, verifier,
	createAuthenticatedSender,
	createAuthenticatedReceiver
} = require('.')

const isEqual = (buf1, buf2) => Buffer.compare(buf1, buf2) === 0
const fromStr = str => Buffer.from(str, 'utf8')

const one = fromStr('one')
const two = fromStr('two')
const three = fromStr('three')
const helloWorld = fromStr('Hello World!')

tape('createBuffer', (t) => {
	const buf = createBuffer()
	t.equal(buf.take(2), null)
	t.ok(isEqual(buf.take(0), Buffer.alloc(0)))

	t.equal(buf.put(one), 3) // 3 from `one`
	t.ok(isEqual(buf.take(2), fromStr('on')))

	t.equal(buf.put(two), 1 + 3) // 1 left + 3 from `two`
	t.equal(buf.put(three), 4 + 5) // 4 left + 5 from `three`

	t.ok(isEqual(buf.take(4), fromStr('e' + 'two')))
	t.equal(buf.take(6), null) // only 5 bytes left

	t.ok(isEqual(buf.take(5), fromStr('three')))
	t.equal(buf.take(1), null) // 0 bytes left
	t.end()
})

tape('signer, verifier', (t) => {
	const {privateKey, publicKey} = createKeyPair()
	const sign = signer(privateKey)
	const verify = verifier(publicKey)

	const isValid = verify(helloWorld, sign(helloWorld))
	t.ok(isValid === true)
	t.end()
})

tape('sender -> receiver', (t) => {
	t.plan(2)
	const data = randomBytes(11111)
	const pair = createKeyPair()

	const verifyPeerPublicKey = (key, cb) => {
		const isValid = isEqual(key, pair.publicKey)
		t.ok(isValid)
		cb(null, isValid)
	}

	const sender = createAuthenticatedSender(pair)
	sender.once('error', t.ifError)
	const receiver = createAuthenticatedReceiver(verifyPeerPublicKey)
	receiver.once('error', t.ifError)
	sender.pipe(receiver)

	const bufs = []
	receiver.on('data', buf => bufs.push(buf))
	receiver.once('end', () => {
		t.ok(isEqual(Buffer.concat(bufs), data))
	})
	sender.end(data)
})
