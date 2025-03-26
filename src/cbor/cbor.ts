import { decodeFirstItem } from "./cbor-decode";
import { encodeValue } from "./cbor-encode";
import type { CBORValue } from "./types";

/**
 * RFC 8949: Concise Binary Object Representation (CBOR)
 */
export const CBOR = {
	encode,
	decode,
	decodeWithOffset,
	decodeMapToMap,
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

function decode(buffer: ArrayBuffer): CBORValue {
	if (buffer.byteLength > MAX_BUFFER_SIZE) {
		throw new Error(`Buffer exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`);
	}
	const [value] = decodeFirstItem(buffer, 0);
	return value;
}

/**
 * Decodes a CBOR buffer and returns the value along with the number of bytes consumed.
 * Useful for parsing concatenated CBOR data (e.g., COSE key followed by extensions in WebAuthn).
 *
 * @param buffer - The buffer to decode.
 * @param startOffset - The offset to start decoding from.
 * @returns The decoded value and the number of bytes consumed.
 */
function decodeWithOffset(
	buffer: ArrayBuffer,
	startOffset = 0,
): [CBORValue, number] {
	if (buffer.byteLength > MAX_BUFFER_SIZE) {
		throw new Error(`Buffer exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`);
	}
	const [value, newOffset] = decodeFirstItem(buffer, startOffset);
	return [value, newOffset - startOffset];
}

/**
 * Decodes a CBOR map directly into a JavaScript Map with specified key/value types.
 * Tailored for WebAuthn COSE keys (numeric keys, number/ArrayBuffer values).
 *
 * @param buffer - The buffer to decode.
 * @param startOffset - The offset to start decoding from.
 * @param keyValidator - The validator for the keys.
 * @param valueValidator - The validator for the values.
 * @returns The decoded map.
 */
function decodeMapToMap<K extends string | number, V extends CBORValue>(
	buffer: ArrayBuffer,
	startOffset = 0,
	keyValidator: (key: string | number) => key is K = (key): key is K => true,
	valueValidator: (value: CBORValue) => value is V = (value): value is V =>
		true,
): [Map<K, V>, number] {
	const [obj, newOffset] = decodeFirstItem(buffer, startOffset);
	if (
		typeof obj !== "object" ||
		obj === null ||
		"tag" in obj ||
		Array.isArray(obj)
	) {
		throw new Error("Expected CBOR map");
	}
	const map = new Map<K, V>();
	for (const [key, value] of Object.entries(obj)) {
		const parsedKey =
			Number(key) === Number.parseInt(key, 10) ? Number(key) : key;
		if (!keyValidator(parsedKey)) {
			throw new Error(`Invalid map key: ${parsedKey}`);
		}
		if (!valueValidator(value)) {
			throw new Error(`Invalid map value for key ${parsedKey}: ${value}`);
		}
		map.set(parsedKey as K, value as V);
	}
	return [map, newOffset - startOffset];
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
