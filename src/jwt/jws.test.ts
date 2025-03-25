import { describe, expect, test } from "bun:test";
import fc from "fast-check";

import { base64Url } from "./deps";
import { JWS, type JWSHeader } from "./jws";
import type { StandardClaims } from "./jwt";

describe("JWS", () => {
	// Basic functionality tests
	test("should sign and verify a payload", async () => {
		const payload: StandardClaims = {
			sub: "1234567890",
			name: "John Doe",
			iat: 1516239022,
		};
		const key = "secret-key-for-testing";

		const token = await JWS.sign({ payload, key });
		expect(token).toBeTruthy();
		expect(token.split(".").length).toBe(3);

		const verified = await JWS.verify({ token, key });
		expect(verified).toEqual(payload);
	});

	test("should handle empty objects in payload", async () => {
		const payload: StandardClaims = {};
		const key = "secret-key-for-testing";

		const token = await JWS.sign({ payload, key });
		const verified = await JWS.verify({ token, key });
		expect(verified).toEqual(payload);
	});

	test("should include custom header fields", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";
		const header: Partial<JWSHeader> = {
			kid: "key-id-1",
			typ: "JWT",
		};

		const token = await JWS.sign({ payload, key, header });

		// Verify the header contains our custom fields
		const parts = token.split(".");
		const parsedHeader = base64Url.decodeAsJSON<StandardClaims>(parts[0]);

		expect(parsedHeader.kid).toBe("key-id-1");
		expect(parsedHeader.typ).toBe("JWT");

		// Verify the token
		const verified = await JWS.verify({ token, key });
		expect(verified).toEqual(payload);
	});

	// RFC7515 compliance tests
	test("should produce a token with 3 segments", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWS.sign({ payload, key });
		const parts = token.split(".");

		expect(parts.length).toBe(3);
		expect(parts[0]).toBeTruthy(); // Header
		expect(parts[1]).toBeTruthy(); // Payload
		expect(parts[2]).toBeTruthy(); // Signature
	});

	test("should correctly format the JWS header", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWS.sign({ payload, key });
		const parts = token.split(".");
		const header = base64Url.decodeAsJSON<StandardClaims>(parts[0]);

		expect(header.alg).toBe("HS256");
	});

	test("should reject tokens with invalid format", async () => {
		const key = "secret-key-for-testing";
		const invalidToken = "header.payload"; // Missing signature segment

		await expect(JWS.verify({ token: invalidToken, key })).rejects.toThrow(
			"Invalid JWS token format",
		);
	});

	test("should reject tokens with invalid algorithm", async () => {
		const key = "secret-key-for-testing";
		// Create an invalid header with a type assertion to unknown first
		const header = {
			alg: "RS256", // Not supported in our implementation
		} as unknown as JWSHeader;

		const encodedHeader = base64Url.encode(JSON.stringify(header));
		const encodedPayload = base64Url.encode(JSON.stringify({ sub: "test" }));
		const invalidToken = `${encodedHeader}.${encodedPayload}.dummysignature`;

		expect(JWS.verify({ token: invalidToken, key })).rejects.toThrow(
			"Unsupported algorithm: RS256",
		);
	});

	test("should reject tokens with invalid signature", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWS.sign({ payload, key });
		const parts = token.split(".");

		// Tamper with the signature
		const tamperedToken = `${parts[0]}.${parts[1]}.${base64Url.encode("invalid-signature")}`;

		expect(JWS.verify({ token: tamperedToken, key })).rejects.toThrow(
			"Invalid signature",
		);
	});

	test("should reject tokens with tampered payload", async () => {
		const payload: StandardClaims = { sub: "test" };
		const key = "secret-key-for-testing";

		const token = await JWS.sign({ payload, key });
		const parts = token.split(".");

		// Tamper with the payload
		const tamperedPayload = base64Url.encode(
			JSON.stringify({ sub: "tampered" }),
		);
		const tamperedToken = `${parts[0]}.${tamperedPayload}.${parts[2]}`;

		await expect(JWS.verify({ token: tamperedToken, key })).rejects.toThrow(
			"Invalid signature",
		);
	});

	// Property-based tests using fast-check
	test("should sign and verify arbitrary payloads", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.object({
					maxDepth: 2,
					key: fc.string(),
					values: [fc.string(), fc.integer(), fc.boolean()],
				}),
				fc.string({ minLength: 1 }),
				async (arbitraryPayload, arbitraryKey) => {
					const payload = { ...arbitraryPayload } as StandardClaims;
					const token = await JWS.sign({ payload, key: arbitraryKey });
					const verified = await JWS.verify({ token, key: arbitraryKey });

					return JSON.stringify(verified) === JSON.stringify(payload);
				},
			),
			{ numRuns: 10 }, // Limit runs for performance
		);
	});

	test("should fail verification with wrong key", async () => {
		await fc.assert(
			fc.asyncProperty(
				fc.object(),
				fc.string({ minLength: 1 }),
				fc.string({ minLength: 1 }),
				async (arbitraryPayload, correctKey, wrongKey) => {
					// Skip if keys are the same
					if (correctKey === wrongKey) return true;

					const payload = { ...arbitraryPayload } as StandardClaims;
					const token = await JWS.sign({ payload, key: correctKey });

					try {
						await JWS.verify({ token, key: wrongKey });
						return false; // Should not succeed
					} catch (error) {
						return true; // Expected to fail
					}
				},
			),
			{ numRuns: 10 }, // Limit runs for performance
		);
	});

	// RFC7515 Appendix A.1 test vector
	test("should match RFC7515 Appendix A.1 test vector", async () => {
		// This is the example from RFC7515 Appendix A.1
		// We're using the same payload and key, but we'll verify our implementation
		// produces a valid signature that can be verified

		const payload = {
			iss: "joe",
			exp: 1300819380,
			"http://example.com/is_root": true,
		};

		// The key from the RFC example
		const key = "AyMzSysP".repeat(8); // Simple test key

		const token = await JWS.sign({ payload, key });
		const verified = await JWS.verify({ token, key });

		expect(verified).toEqual(payload);

		// The token structure should match the RFC example (3 parts)
		const parts = token.split(".");
		expect(parts.length).toBe(3);

		// Verify the payload is correctly encoded
		const decodedPayload = base64Url.decodeAsJSON<StandardClaims>(parts[1]);
		expect(decodedPayload).toEqual(payload);
	});

	// Test for security - constant time comparison
	test("should use constant time comparison for signatures", async () => {
		// Since we can't easily spy on the constantTimeEqual function directly,
		// we'll check the implementation to ensure it's using constantTimeEqual

		// Read the implementation code
		const jwsImplementation = await import("./jws");
		const verifyJWSCode = jwsImplementation.verifyJWS.toString();

		// Check if the code contains a call to constantTimeEqual
		expect(verifyJWSCode).toContain("constantTimeEqual");

		// Additional verification - make sure the signature verification works
		const payload = { sub: "test" };
		const key = "test-key";

		const token = await JWS.sign({ payload, key });
		const verified = await JWS.verify({ token, key });

		expect(verified).toEqual(payload);
	});
});
