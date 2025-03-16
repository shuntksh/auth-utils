// @cspell:disable
import { describe, expect, setSystemTime, test } from "bun:test";
import { fc } from "fast-check-bun-test";

import { base32 } from "./encoding";
import { TOTP } from "./totp";

describe("TOTP Generation and Verification", () => {
	// Test vector from RFC 6238
	// Note: RFC 6238 uses different hash algorithms, but we're only implementing SHA-1
	const secret = "12345678901234567890";
	const testVectors = [
		{ time: 59, expected: "94287082" },
		{ time: 1111111109, expected: "07081804" },
		{ time: 1111111111, expected: "14050471" },
		{ time: 1234567890, expected: "89005924" },
		{ time: 2000000000, expected: "69279037" },
		{ time: 20000000000, expected: "65353130" },
	];

	test("should generate correct TOTP codes", async () => {
		// Convert ASCII secret to base32 for our implementation
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		for (const { time, expected } of testVectors) {
			const totp = await TOTP.generate({
				secret: base32Secret,
				time,
				step: 30,
				length: 8,
			});
			expect(totp).toBe(expected);
		}
	});

	test("should verify valid TOTP codes", async () => {
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		for (const { time, expected } of testVectors) {
			const isValid = await TOTP.verify({
				secret: base32Secret,
				otp: expected,
				time,
				step: 30,
				length: 8,
				window: 0,
			});
			expect(isValid).toBe(true);
		}
	});

	test("should handle time window correctly", async () => {
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		// Test with time window = 1 (current and previous/next step)
		const time = 1111111109;
		const prevTime = time - 30;
		const nextTime = time + 30;

		// Generate TOTP for the exact time
		const totp = await TOTP.generate({
			secret: base32Secret,
			time,
			step: 30,
			length: 8,
		});

		// Verify with different times within the window
		const isValidExact = await TOTP.verify({
			secret: base32Secret,
			otp: totp,
			time,
			step: 30,
			length: 8,
			window: 1,
		});
		const isValidPrev = await TOTP.verify({
			secret: base32Secret,
			otp: totp,
			time: prevTime,
			step: 30,
			length: 8,
			window: 0,
		});
		const isValidNext = await TOTP.verify({
			secret: base32Secret,
			otp: totp,
			time: nextTime,
			step: 30,
			length: 8,
			window: 0,
		});

		expect(isValidExact).toBe(true);
		expect(isValidPrev).toBe(false); // Should fail with window = 0
		expect(isValidNext).toBe(false); // Should fail with window = 0

		// Now test with window = 1
		const isValidPrevWithWindow = await TOTP.verify({
			secret: base32Secret,
			otp: totp,
			time: prevTime,
			step: 30,
			length: 8,
			window: 1,
		});
		const isValidNextWithWindow = await TOTP.verify({
			secret: base32Secret,
			otp: totp,
			time: nextTime,
			step: 30,
			length: 8,
			window: 1,
		});

		expect(isValidPrevWithWindow).toBe(true);
		expect(isValidNextWithWindow).toBe(true);
	});

	test("should use current time when not specified", async () => {
		const encoder = new TextEncoder();
		const secretBuffer = encoder.encode(secret);
		const base32Secret = base32.fromBuffer(secretBuffer);

		// Set a fake time for testing
		const fakeTime = new Date(1111111109 * 1000);
		setSystemTime(fakeTime);

		try {
			// Generate TOTP without specifying time (should use current time)
			const totp = await TOTP.generate({
				secret: base32Secret,
				time: undefined,
				step: 30,
				length: 8,
			});
			const expected = "07081804"; // Expected TOTP for time 1111111109

			expect(totp).toBe(expected);

			// Verify TOTP without specifying time
			const isValid = await TOTP.verify({
				secret: base32Secret,
				otp: expected,
				time: undefined,
				step: 30,
				length: 8,
				window: 0,
			});
			expect(isValid).toBe(true);
		} finally {
			// Reset the time
			setSystemTime();
		}
	});

	test("property: generated TOTP should be verified within same time step", async () => {
		await fc.assert(
			fc.asyncProperty(
				// Use alphanumeric strings only to avoid issues with special characters
				fc
					.string({ minLength: 1 })
					.map((s) => s.replace(/[^a-zA-Z0-9]/g, "A")),
				fc.integer({ min: 0, max: 2000000000 }),
				fc.integer({ min: 10, max: 60 }),
				fc.integer({ min: 6, max: 10 }),
				async (rawSecret, time, step, length) => {
					const encoder = new TextEncoder();
					const secretBuffer = encoder.encode(rawSecret);
					const base32Secret = base32.fromBuffer(secretBuffer);

					const totp = await TOTP.generate({
						secret: base32Secret,
						time,
						step,
						length,
					});
					const isValid = await TOTP.verify({
						secret: base32Secret,
						otp: totp,
						time,
						step,
						length,
						window: 0,
					});

					return isValid === true;
				},
			),
		);
	});
});
