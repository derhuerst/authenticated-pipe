'use strict'

const createBuffer = () => {
	let chunks = [] // list of buffered chunks
	let totalBytes = 0 // total size of all buffered chunks

	const put = (chunk) => {
		chunks.push(chunk)
		totalBytes += chunk.byteLength
		return totalBytes
	}

	const take = (bytesToTake) => {
		if (totalBytes < bytesToTake) return null

		let bytesTaken = 0, chunksTaken = []
		while (chunks.length > 0 && bytesTaken < bytesToTake) {
			const chunk = chunks.shift()
			const chunkLength = chunk.byteLength
			totalBytes -= chunkLength

			if (bytesTaken + chunkLength > bytesToTake) {
				const splitAt = bytesToTake - bytesTaken
				chunksTaken.push(chunk.slice(0, splitAt))
				chunks.unshift(chunk.slice(splitAt))
				totalBytes += chunkLength - splitAt
				break
			}

			chunksTaken.push(chunk)
			bytesTaken += chunkLength
			if (bytesTaken === bytesToTake) break
		}

		return Buffer.concat(chunksTaken)
	}

	const size = () => totalBytes
	return {put, take, size}
}

module.exports = createBuffer
