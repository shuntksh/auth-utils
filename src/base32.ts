/**
 * Base32 encoding utilities
 */
export const base32 = {
	fromBuffer: bufferToBase32,
	toBuffer: base32ToBuffer,
} as const;

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
