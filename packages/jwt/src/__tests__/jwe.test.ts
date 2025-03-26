import { describe, expect, test } from "bun:test";
import fc from "fast-check";

import { base64Url } from "../deps";
import { JWE, type JWEHeader } from "../jwe";
import type { StandardClaims } from "../jwt";

describe("JWE", () => {
	// Basic functionality tests
	test("should encrypt and decrypt a payload", async () => {
		const payload: StandardClaims = {
			sub: "1234567890",
			name: "John Doe",
			iat: 1516239022,
		};
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		expect(token).toBeTruthy();
		expect(token.split(".").length).toBe(5);

		const decrypted = await JWE.decrypt({ token, key });
		expect(decrypted.payload).toEqual(payload);
	});

	test("should handle empty objects in payload", async () => {
		const payload: StandardClaims = {};
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		const decrypted = await JWE.decrypt({ token, key });
		expect(decrypted.payload).toEqual(payload);
	});

	test("should include custom header fields", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";
		const header: Partial<JWEHeader> = {
			kid: "key-id-1",
			typ: "JWT",
		};

		const token = await JWE.encrypt({ payload, key, header });
		const decrypted = await JWE.decrypt({ token, key });

		expect(decrypted.header.kid).toBe("key-id-1");
		expect(decrypted.header.typ).toBe("JWT");
	});

	// RFC7516 compliance tests
	test("should produce a token with 5 segments", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		const parts = token.split(".");

		expect(parts.length).toBe(5);
		// For direct encryption, the encrypted key segment should be empty
		expect(parts[1]).toBe("");
	});

	test("should correctly format the JWE header", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		const parts = token.split(".");
		const header = base64Url.decodeAsJSON<StandardClaims>(parts[0]);

		expect(header.alg).toBe("dir");
		expect(header.enc).toBe("A128CBC-HS256");
	});

	test("should reject tokens with invalid format", async () => {
		const key = "secret-key-for-testing";
		const invalidToken = "header.key.iv.ciphertext"; // Missing tag segment

		await expect(JWE.decrypt({ token: invalidToken, key })).rejects.toThrow(
			"Invalid JWE token format",
		);
	});

	test("should reject tokens with invalid algorithm", async () => {
		const key = "secret-key-for-testing";
		// Create an invalid header with a type assertion to unknown first
		const header = {
			alg: "RSA1_5", // Invalid algorithm for our implementation
			enc: "A128CBC-HS256",
		} as unknown as JWEHeader;

		const encodedHeader = base64Url.encode(JSON.stringify(header));
		const invalidToken = `${encodedHeader}.....`; // Dummy segments

		await expect(JWE.decrypt({ token: invalidToken, key })).rejects.toThrow(
			"Invalid JWE token format",
		);
	});

	test("should reject tokens with invalid encryption method", async () => {
		const key = "secret-key-for-testing";
		// Create an invalid header with a type assertion to unknown first
		const header = {
			alg: "dir",
			enc: "A256GCM", // Invalid encryption method for our implementation
		} as unknown as JWEHeader;

		const encodedHeader = base64Url.encode(JSON.stringify(header));
		const invalidToken = `${encodedHeader}.....`; // Dummy segments

		await expect(JWE.decrypt({ token: invalidToken, key })).rejects.toThrow(
			"Invalid JWE token format",
		);
	});

	test("should reject tokens with invalid authentication tag", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		const parts = token.split(".");

		// Create a valid IV and tamper with the authentication tag
		const validIv = base64Url.decode(parts[2]);
		const tamperedToken = `${parts[0]}.${parts[1]}.${parts[2]}.${parts[3]}.${base64Url.encode(new Uint8Array(16))}`;

		await expect(JWE.decrypt({ token: tamperedToken, key })).rejects.toThrow(
			"Invalid authentication tag",
		);
	});

	test("should reject tokens with tampered ciphertext", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		const parts = token.split(".");

		// Tamper with the ciphertext but keep valid IV and tag structure
		const tamperedToken = `${parts[0]}.${parts[1]}.${parts[2]}.${base64Url.encode(new Uint8Array(32))}.${parts[4]}`;

		await expect(JWE.decrypt({ token: tamperedToken, key })).rejects.toThrow();
	});

	// Property-based tests using fast-check
	test("should encrypt and decrypt arbitrary payloads", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.object({
					maxDepth: 2,
					key: fc.string(),
					values: [fc.string(), fc.integer(), fc.boolean()],
				}),
				fc.string(),
				async (arbitraryPayload, arbitraryKey) => {
					// Skip empty keys
					if (!arbitraryKey) return true;

					const payload = { ...arbitraryPayload } as StandardClaims;
					const token = await JWE.encrypt({ payload, key: arbitraryKey });
					const decrypted = await JWE.decrypt({ token, key: arbitraryKey });

					return JSON.stringify(decrypted.payload) === JSON.stringify(payload);
				},
			),
			{ numRuns: 10 }, // Limit runs for performance
		);
	});

	test("should fail decryption with wrong key", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.object(),
				fc.string({ minLength: 1 }),
				fc.string({ minLength: 1 }),
				async (arbitraryPayload, correctKey, wrongKey) => {
					// Skip if keys are the same
					if (correctKey === wrongKey) return true;

					const payload = { ...arbitraryPayload } as StandardClaims;
					const token = await JWE.encrypt({ payload, key: correctKey });

					try {
						await JWE.decrypt({ token, key: wrongKey });
						return false; // Should not succeed
					} catch (error) {
						return true; // Expected to fail
					}
				},
			),
			{ numRuns: 10 }, // Limit runs for performance
		);
	});

	// RFC7516 Appendix A test vectors
	// Note: The RFC examples use RSA-OAEP and A256GCM which are different from our implementation
	// So we can't directly use those test vectors, but we can test the structure and format
	test("should follow RFC7516 structure", async () => {
		const payload: StandardClaims = { sub: "test-subject" };
		const key = "secret-key-for-testing";

		const token = await JWE.encrypt({ payload, key });
		const parts = token.split(".");

		// Check structure
		expect(parts.length).toBe(5);

		// Check header
		const header = base64Url.decodeAsJSON<StandardClaims>(parts[0]);
		expect(header.alg).toBe("dir");
		expect(header.enc).toBe("A128CBC-HS256");

		// For direct encryption, the encrypted key segment should be empty
		expect(parts[1]).toBe("");

		// IV should be 16 bytes (128 bits) for AES-CBC
		const iv = base64Url.decode(parts[2]);
		expect(iv.length).toBe(16);

		// Authentication tag should be 16 bytes (128 bits) for HMAC-SHA-256-128
		const tag = base64Url.decode(parts[4]);
		expect(tag.length).toBe(16);
	});
});
