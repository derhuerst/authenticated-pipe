# authenticated-pipe

**Make sure you receive data from the right person.** Goes hand in hand with [`airpaste`](https://npmjs.com/package/airpaste) (to magically send your data through the local network) and [`private-pipe`](https://npmjs.com/package/private-pipe) (to encrypt the data during transport).

*Note:* This library has *not* been cryptographically audited. Use it with a grain of salt.

[![npm version](https://img.shields.io/npm/v/authenticated-pipe.svg)](https://www.npmjs.com/package/authenticated-pipe)
[![build status](https://api.travis-ci.org/derhuerst/authenticated-pipe.svg?branch=master)](https://travis-ci.org/derhuerst/authenticated-pipe)
![ISC-licensed](https://img.shields.io/github/license/derhuerst/authenticated-pipe.svg)
[![support me via GitHub Sponsors](https://img.shields.io/badge/support%20me-donate-fa7664.svg)](https://github.com/sponsors/derhuerst)
[![chat with me on Twitter](https://img.shields.io/badge/chat%20with%20me-on%20Twitter-1da1f2.svg)](https://twitter.com/derhuerst)


## Installation

```shell
npm install authenticated-pipe -g
```

Or run it directly using [npx](https://npmjs.com/package/npx).


## Usage

```
Sign & send data:
	auth-pipe send
Receive data:
	auth-pipe receive [peer-public-key]
```

As an example, we're going to send `secret message` via [`airpaste`](https://npmjs.com/package/airpaste), encrypted via [`private-pipe`](https://npmjs.com/package/private-pipe) and authenticated via `auth-pipe`:

```shell
# machine A
echo 'secret message' | auth-pipe send | private-pipe 'secret password' | airpaste
# Your identity: 😄📊👉💧🙏💬

# machine B
airpaste | private-pipe 'secret password' | auth-pipe receive 😄📊👉💧🙏💬
# Sender identity 😄📊👉💧🙏💬 matches.
# secret message
```


## Contributing

If you have a question or need support using `authenticated-pipe`, please double-check your code and setup first. If you think you have found a bug or want to propose a feature, refer to [the issues page](https://github.com/derhuerst/authenticated-pipe/issues).
