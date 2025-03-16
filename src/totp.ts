import { HOTP } from "./hotp";

export const TOTP = {
	generate: generateTOTP,
	verify: verifyTOTP,
};

/**
 * Generates a TOTP code according to RFC6238
 * @param options - Options object containing:
 *   - secret: Base32 encoded secret key
 *   - time: Time in seconds since Unix epoch (default: current time)
 *   - step: Time step in seconds (default: 30)
 *   - length: Length of the OTP code (default: 6)
 * @returns Promise resolving to the TOTP code
 */
async function generateTOTP(options: {
	secret: string;
	time?: number;
	step?: number;
	length?: number;
}): Promise<string> {
	const {
		secret,
		time = Math.floor(Date.now() / 1000),
		step = 30,
		length = 6,
	} = options;

	// Validate inputs
	if (step <= 0 || !Number.isInteger(step)) {
		throw new Error("Step must be a positive integer");
	}

	// Trim the secret to handle whitespace consistently
	const trimmedSecret = secret.trim();
	if (trimmedSecret === "") {
		throw new Error("Secret cannot be empty or whitespace only");
	}

	// Calculate counter value (number of time steps)
	const counter = Math.floor(time / step);

	return HOTP.generate({ secret: trimmedSecret, counter, length });
}

/**
 * Verifies a TOTP code
 * @param options - Options object containing:
 *   - secret: Base32 encoded secret key
 *   - otp: OTP code to verify
 *   - time: Time in seconds since Unix epoch (default: current time)
 *   - step: Time step in seconds (default: 30)
 *   - length: Length of the OTP code (default: 6)
 *   - window: Number of time steps to check before and after the current one (default: 1)
 * @returns Promise resolving to true if OTP is valid, false otherwise
 */
async function verifyTOTP(options: {
	secret: string;
	otp: string;
	time?: number;
	step?: number;
	length?: number;
	window?: number;
}): Promise<boolean> {
	const {
		secret,
		otp,
		time = Math.floor(Date.now() / 1000),
		step = 30,
		length = 6,
		window = 1,
	} = options;

	// Validate inputs
	if (window < 0 || !Number.isInteger(window)) {
		throw new Error("Window must be a non-negative integer");
	}

	// Trim the secret to handle whitespace consistently
	const trimmedSecret = secret.trim();
	if (trimmedSecret === "") {
		return false;
	}

	// Calculate current counter value
	const counter = Math.floor(time / step);

	// Check OTP for current counter and within the window
	for (let i = -window; i <= window; i++) {
		const currentCounter = counter + i;
		if (
			await HOTP.verify({
				secret: trimmedSecret,
				counter: currentCounter,
				otp,
				length,
			})
		) {
			return true;
		}
	}

	return false;
}
