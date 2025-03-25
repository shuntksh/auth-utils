import { describe, expect } from "bun:test";
import { fc, test } from "fast-check-bun-test";

import { base32 } from "./base32";
import { HOTP } from "./hotp";

describe("HOTP Generation and Verification", () => {
	// Test vectors from RFC 4226 Appendix D
	const secret = "12345678901234567890";
	const testVectors = [
		{ counter: 0, expected: "755224" },
		{ counter: 1, expected: "287082" },
		{ counter: 2, expected: "359152" },
		{ counter: 3, expected: "969429" },
		{ counter: 4, expected: "338314" },
		{ counter: 5, expected: "254676" },
		{ counter: 6, expected: "287922" },
		{ counter: 7, expected: "162583" },
		{ counter: 8, expected: "399871" },
		{ counter: 9, expected: "520489" },
	];

	test("should generate correct HOTP codes", async () => {
		// Convert ASCII secret to base32 for our implementation
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		for (const { counter, expected } of testVectors) {
			const hotp = await HOTP.generate({ secret: base32Secret, counter });
			expect(hotp).toBe(expected);
		}
	});

	test("should verify valid HOTP codes", async () => {
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		for (const { counter, expected } of testVectors) {
			const isValid = await HOTP.verify({
				secret: base32Secret,
				counter,
				otp: expected,
			});
			expect(isValid).toBe(true);
		}
	});

	test("should reject invalid HOTP codes", async () => {
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		const isValid = await HOTP.verify({
			secret: base32Secret,
			counter: 0,
			otp: "123456",
		});
		expect(isValid).toBe(false);
	});

	test("should handle invalid inputs gracefully", async () => {
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		// Invalid OTP format
		const isValid1 = await HOTP.verify({
			secret: base32Secret,
			counter: 0,
			otp: "12345",
		});
		expect(isValid1).toBe(false);

		// Invalid OTP characters
		const isValid2 = await HOTP.verify({
			secret: base32Secret,
			counter: 0,
			otp: "abcdef",
		});
		expect(isValid2).toBe(false);
	});

	test("property: generated HOTP should be verified", async () => {
		await fc.assert(
			fc.asyncProperty(
				// Use alphanumeric strings only to avoid issues with special characters
				fc
					.string({ minLength: 1 })
					.map((s) => s.replace(/[^a-zA-Z0-9]/g, "A")),
				fc.integer({ min: 0, max: 1000 }),
				fc.integer({ min: 6, max: 10 }),
				async (rawSecret, counter, length) => {
					const encoder = new TextEncoder();
					const secretBuffer = encoder.encode(rawSecret);
					const base32Secret = base32.fromBuffer(secretBuffer);

					const hotp = await HOTP.generate({
						secret: base32Secret,
						counter,
						length,
					});
					const isValid = await HOTP.verify({
						secret: base32Secret,
						counter,
						otp: hotp,
						length, // Pass the length parameter to HOTP.verify
					});
					return isValid === true;
				},
			),
		);
	});
});
