import { base32 } from "./base32";
import { constantTimeEqual } from "./deps";

export const HOTP = {
	generate: generateHOTP,
	verify: verifyHOTP,
} as const;

/**
 * Generates an HMAC-SHA-1 digest using WebCrypto API
 * @param options - Options object containing:
 *   - key: The key as an ArrayBuffer
 *   - message: The message as an ArrayBuffer
 * @returns Promise resolving to the HMAC digest
 */
const sha1 = async (options: {
	key: BufferSource;
	message: BufferSource;
}): Promise<ArrayBuffer> => {
	const { key, message } = options;
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		key,
		{ name: "HMAC", hash: { name: "SHA-1" } },
		false,
		["sign"],
	);

	return crypto.subtle.sign("HMAC", cryptoKey, message);
};

/**
 * Generates an HOTP code according to RFC4226
 * @param options - Options object containing:
 *   - secret: Base32 encoded secret key
 *   - counter: Counter value
 *   - length: Length of the OTP code (default: 6)
 * @returns Promise resolving to the HOTP code
 * @throws Error if the secret is invalid or length is out of range
 */
async function generateHOTP(options: {
	secret: string;
	counter: number;
	length?: number;
}): Promise<string> {
	const { secret, counter, length = 6 } = options;
	// Validate inputs
	if (!secret) {
		throw new Error("Secret cannot be empty");
	}

	// Trim the secret to handle whitespace consistently
	const trimmedSecret = secret.trim();
	if (trimmedSecret === "") {
		throw new Error("Secret cannot be empty or whitespace only");
	}

	if (counter < 0 || !Number.isInteger(counter)) {
		throw new Error("Counter must be a non-negative integer");
	}

	if (length < 6 || length > 10 || !Number.isInteger(length)) {
		throw new Error("Length must be an integer between 6 and 10");
	}

	try {
		// Decode the secret (using trimmed version)
		const keyBuffer = base32.toBuffer(trimmedSecret);

		// Convert counter to buffer (8 bytes, big-endian)
		const counterBuffer = new ArrayBuffer(8);
		const counterView = new DataView(counterBuffer);

		// JavaScript bitwise operations are limited to 32 bits, so we need to handle the counter carefully
		const high = Math.floor(counter / 0x100000000);
		const low = counter % 0x100000000;

		counterView.setUint32(0, high);
		counterView.setUint32(4, low);

		// Generate HMAC-SHA-1
		const hmacResult = await sha1({
			key: keyBuffer,
			message: counterBuffer,
		});
		const hmacArray = new Uint8Array(hmacResult);

		// Dynamic truncation
		const offset = hmacArray[19] & 0x0f;
		const binCode =
			((hmacArray[offset] & 0x7f) << 24) |
			((hmacArray[offset + 1] & 0xff) << 16) |
			((hmacArray[offset + 2] & 0xff) << 8) |
			(hmacArray[offset + 3] & 0xff);

		// Generate OTP
		const modulo = 10 ** length;
		const otp = binCode % modulo;

		// Pad with leading zeros if necessary
		return otp.toString().padStart(length, "0");
	} catch (error) {
		if (error instanceof Error && error.message.includes("Invalid base32")) {
			throw error;
		}
		throw new Error(`Failed to generate HOTP: ${(error as Error).message}`);
	}
}

/**
 * Verifies an HOTP code
 * @param options - Options object containing:
 *   - secret: Base32 encoded secret key
 *   - counter: Counter value
 *   - otp: OTP code to verify
 *   - length: Length of the OTP code (default: 6)
 * @returns Promise resolving to true if OTP is valid, false otherwise
 */
async function verifyHOTP(options: {
	secret: string;
	counter: number;
	otp: string;
	length?: number;
}): Promise<boolean> {
	try {
		const { secret, counter, otp, length = 6 } = options;
		if (!secret || counter === undefined || counter < 0 || !otp) {
			return false;
		}

		// Trim the secret to handle whitespace consistently
		const trimmedSecret = secret.trim();
		if (trimmedSecret === "") {
			return false;
		}

		// Validate OTP format
		if (!otp.match(new RegExp(`^\\d{${length}}$`))) {
			return false;
		}

		const expectedOtp = await generateHOTP({
			secret: trimmedSecret,
			counter,
			length,
		});
		return constantTimeEqual(otp, expectedOtp);
	} catch (error) {
		return false;
	}
}
