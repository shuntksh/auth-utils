import { decodeValue } from "./cbor-decode";
import { encodeValue } from "./cbor-encode";
import type { CBORValue } from "./types";

/**
 * RFC 8949: Concise Binary Object Representation (CBOR)
 */
export const CBOR = {
	encode,
	decode,
} as const;

const MAX_BUFFER_SIZE = 16 * 1024 * 1024;

function encode(value: CBORValue): ArrayBuffer {
	const buffers: Uint8Array[] = [];
	encodeValue(value, buffers);
	const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
	if (totalLength > MAX_BUFFER_SIZE) {
		throw new Error(
			`Encoded data exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`,
		);
	}
	return concatBuffers(buffers);
}

function decode(buffer: ArrayBuffer, startOffset = 0): CBORValue {
	if (buffer.byteLength > MAX_BUFFER_SIZE) {
		throw new Error(`Buffer exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`);
	}
	const [value] = decodeValue(buffer, startOffset);
	return value;
}

/**
 * Concatenates an array of ArrayBuffers into a single ArrayBuffer
 * @param buffers - Array of ArrayBuffers to concatenate
 * @returns Concatenated ArrayBuffer
 */
function concatBuffers(buffers: ArrayBuffer[] | Uint8Array[]): ArrayBuffer {
	const totalLength = buffers.reduce(
		(sum, buffer) => sum + buffer.byteLength,
		0,
	);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const buffer of buffers) {
		result.set(new Uint8Array(buffer), offset);
		offset += buffer.byteLength;
	}
	return result.buffer;
}
