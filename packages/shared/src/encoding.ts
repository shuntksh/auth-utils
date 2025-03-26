/**
 * @fileoverview Base64URL encoding and decoding utilities compatible with RFC 4648.
 *
 * This module provides functions for encoding and decoding strings and objects to
 * and from the base64url format, which is a URL-safe variant of base64 encoding.
 *
 * The base64url format uses the characters '-', '_', and '=' for padding instead of
 * the standard base64 characters '+', '/', and '='.
 */

/**
 * Base64URL encoding utilities
 */
export const base64Url = {
	encode: base64UrlEncode,
	decode: base64UrlDecodeToUint8Array,
	decodeAsString: base64UrlDecodeAsString,
	decodeAsJSON: base64UrlDecodeAsJSON,
} as const;

/**
 * Base32 encoding utilities
 */
export const base32 = {
	fromBuffer: bufferToBase32,
	toBuffer: base32ToBuffer,
} as const;

/**
 * Encodes a string, object, or Uint8Array to base64url format
 * @param input - String, object, or Uint8Array to encode
 * @returns Base64url encoded string
 */
function base64UrlEncode(input: string | object | Uint8Array): string {
	let data: Uint8Array;

	if (input instanceof Uint8Array) {
		// If input is already a Uint8Array, use it directly
		data = input;
	} else {
		// Convert string or object to Uint8Array
		const str = typeof input === "object" ? JSON.stringify(input) : input;
		data = new TextEncoder().encode(str);
	}

	const base64 = btoa(String.fromCharCode(...data));
	return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * Decodes a base64url string to Uint8Array
 * @param input - Base64url-encoded string
 * @returns Decoded Uint8Array
 */
function base64UrlDecodeToUint8Array(input: string): Uint8Array {
	const padded =
		input.replace(/-/g, "+").replace(/_/g, "/") +
		"=".repeat((4 - (input.length % 4)) % 4);
	const binary = atob(padded);
	const output = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		output[i] = binary.charCodeAt(i);
	}
	return output;
}

/**
 * Decodes a base64url string
 * @param input - Base64url encoded string
 * @returns Decoded string
 */
function base64UrlDecodeAsString(input: string): string {
	if (!input) {
		return "";
	}

	let base64 = input.replace(/-/g, "+").replace(/_/g, "/");
	const padding = base64.length % 4;
	if (padding) {
		base64 += "=".repeat(4 - padding);
	}

	try {
		const binaryStr = atob(base64);
		const bytes = Uint8Array.from(binaryStr, (char) => char.charCodeAt(0));
		return new TextDecoder("utf-8").decode(bytes);
	} catch (error) {
		throw new Error(`Failed to decode base64url: ${(error as Error).message}`);
	}
}

/**
 * Parses a base64url encoded JSON string
 * @param input - Base64url encoded JSON string
 * @returns Parsed object
 */
function base64UrlDecodeAsJSON<T>(input: string): T {
	try {
		const decoded = base64UrlDecodeAsString(input);
		return JSON.parse(decoded) as T;
	} catch (error) {
		throw new Error(
			`Failed to parse base64url-encoded JSON: ${(error as Error).message}`,
		);
	}
}

/**
 * Converts a key to a BufferSource
 * @param key - The key as string, ArrayBuffer, or Uint8Array
 * @returns The key as a BufferSource
 */
export function keyToBuffer(
	key: string | ArrayBuffer | Uint8Array,
): BufferSource {
	if (typeof key === "string") {
		return new TextEncoder().encode(key);
	}
	if (key instanceof Uint8Array) {
		return key;
	}
	if (key instanceof ArrayBuffer) {
		return new Uint8Array(key);
	}
	throw new Error(
		"Invalid key type: must be string, ArrayBuffer, or Uint8Array",
	);
}

// Base32 character set (RFC4648)
const BASE32_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const BASE32_CHAR_MAP = new Map<string, number>();
for (let i = 0; i < BASE32_CHARS.length; i++) {
	BASE32_CHAR_MAP.set(BASE32_CHARS[i], i);
}

/**
 * Converts a base32 encoded string to an ArrayBuffer
 * @param base32 - The base32 encoded string
 * @returns ArrayBuffer containing the decoded data
 * @throws Error if the input contains invalid base32 characters
 */
function base32ToBuffer(base32: string): ArrayBuffer {
	// Normalize the input: uppercase and remove padding
	const normalizedInput = base32.toUpperCase().replace(/=+$/, "");

	// Check for invalid characters
	for (const char of normalizedInput) {
		if (!BASE32_CHAR_MAP.has(char)) {
			throw new Error(`Invalid base32 character: ${char}`);
		}
	}

	const length = Math.floor((normalizedInput.length * 5) / 8);
	const result = new Uint8Array(length);

	let buffer = 0;
	let bitsLeft = 0;
	let resultIndex = 0;

	for (const char of normalizedInput) {
		// We've already checked that the character exists in the map
		const value = BASE32_CHAR_MAP.get(char) ?? 0; // This should never be 0 due to the check above
		buffer = (buffer << 5) | value;
		bitsLeft += 5;

		if (bitsLeft >= 8) {
			bitsLeft -= 8;
			result[resultIndex++] = (buffer >> bitsLeft) & 0xff;
		}
	}

	return result.buffer;
}

/**
 * Converts an ArrayBuffer or Uint8Array to a base32 encoded string
 * @param buffer - The buffer to encode
 * @returns Base32 encoded string
 */
function bufferToBase32(buffer: ArrayBuffer | Uint8Array): string {
	const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
	let result = "";
	let buffer32 = 0;
	let bitsLeft = 0;

	for (const byte of bytes) {
		buffer32 = (buffer32 << 8) | byte;
		bitsLeft += 8;

		while (bitsLeft >= 5) {
			bitsLeft -= 5;
			const index = (buffer32 >> bitsLeft) & 0x1f;
			result += BASE32_CHARS[index];
		}
	}

	// Handle remaining bits
	if (bitsLeft > 0) {
		buffer32 = buffer32 << (5 - bitsLeft);
		const index = buffer32 & 0x1f;
		result += BASE32_CHARS[index];
	}

	// Add padding to make the length a multiple of 8
	const padding = 8 - (result.length % 8);
	if (padding < 8) {
		result += "=".repeat(padding);
	}

	return result;
}
