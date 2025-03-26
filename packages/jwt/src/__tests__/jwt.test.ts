import { describe, expect, test } from "bun:test";
import fc from "fast-check";

import { base64Url } from "../deps";
import type { JWKKeySet, OctKey } from "../jwk";
import { JWT } from "../jwt";

describe("JWT", () => {
	const testKey = "test-secret-key-for-jwt-operations";
	const testPayload = {
		sub: "1234567890",
		name: "Test User",
		iat: Math.floor(Date.now() / 1000),
		exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour from now
		iss: "test-issuer",
		aud: "test-audience",
	};

	describe("sign and verify", () => {
		test("should sign and verify a token", async () => {
			const token = await JWT.sign({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-1" },
			});

			expect(token).toBeString();
			expect(token.split(".").length).toBe(3);

			// Create a JWK Set with the test key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-1",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(true);
			expect(result.payload.sub).toBe(testPayload.sub);
			expect(result.payload.name).toBe(testPayload.name);
		});

		test("should verify a token with multiple keys in a JWK Set", async () => {
			// Create a token with a key ID
			const token = await JWT.sign({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-2" },
			});

			// Create a JWK Set with multiple keys
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode("wrong-key")),
						kid: "wrong-key-id",
						alg: "HS256",
						use: "sig",
					},
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-2",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(true);
			expect(result.payload.sub).toBe(testPayload.sub);
			expect(result.payload.name).toBe(testPayload.name);
		});

		test("should fail verification with JWK Set when no matching key is found", async () => {
			// Create a token with a key ID
			const token = await JWT.sign({
				payload: testPayload,
				key: testKey,
				header: { kid: "non-existent-key" },
			});

			// Create a JWK Set without the matching key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode("wrong-key")),
						kid: "wrong-key-id",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("No matching key found in JWK Set");
		});

		test("should fail verification with wrong key in JWK Set", async () => {
			const token = await JWT.sign({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-wrong" },
			});

			// Create a JWK Set with a wrong key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode("wrong-key")),
						kid: "test-key-wrong",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("Invalid signature");
		});

		test("should fail verification with wrong audience", async () => {
			const token = await JWT.sign({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-audience" },
			});

			// Create a JWK Set with the test key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-audience",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "wrong-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("audience");
		});

		test("should fail verification with wrong issuer", async () => {
			const token = await JWT.sign({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-issuer" },
			});

			// Create a JWK Set with the test key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-issuer",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "wrong-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("issuer");
		});

		test("should fail verification with expired token", async () => {
			const expiredPayload = {
				...testPayload,
				exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour ago
			};

			const token = await JWT.sign({
				payload: expiredPayload,
				key: testKey,
				header: { kid: "test-key-expired" },
			});

			// Create a JWK Set with the test key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-expired",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("expired");
		});

		test("should handle token with future nbf claim", async () => {
			const futurePayload = {
				...testPayload,
				nbf: Math.floor(Date.now() / 1000) + 3600, // 1 hour in the future
			};

			const token = await JWT.sign({
				payload: futurePayload,
				key: testKey,
				header: { kid: "test-key-future" },
			});

			// Create a JWK Set with the test key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-future",
						alg: "HS256",
						use: "sig",
					},
				],
			};

			const result = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("not yet valid");

			// Should pass with sufficient clock tolerance
			const resultWithTolerance = await JWT.verify({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
				clockTolerance: 3700, // More than 1 hour
			});

			expect(resultWithTolerance.valid).toBe(true);
		});
	});

	describe("encrypt and decrypt", () => {
		test("should encrypt and decrypt a token", async () => {
			const token = await JWT.encrypt({
				payload: testPayload,
				key: testKey,
			});

			expect(token).toBeString();
			expect(token.split(".").length).toBe(5);

			const result = await JWT.decrypt({
				token,
				key: testKey,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(true);
			expect(result.payload.sub).toBe(testPayload.sub);
			expect(result.payload.name).toBe(testPayload.name);
		});

		test("should decrypt a token with a JWK", async () => {
			// Create a token with a key ID
			const token = await JWT.encrypt({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-3" },
			});

			// Create a JWK from the test key
			const jwk: OctKey = {
				kty: "oct",
				k: base64Url.encode(new TextEncoder().encode(testKey)),
				kid: "test-key-3",
				alg: "dir",
				use: "enc",
			};

			const result = await JWT.decrypt({
				token,
				key: jwk,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(true);
			expect(result.payload.sub).toBe(testPayload.sub);
			expect(result.payload.name).toBe(testPayload.name);
		});

		test("should decrypt a token with a JWK Set", async () => {
			// Create a token with a key ID
			const token = await JWT.encrypt({
				payload: testPayload,
				key: testKey,
				header: { kid: "test-key-4" },
			});

			// Create a JWK Set with multiple keys
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode("wrong-key")),
						kid: "wrong-key-id",
						alg: "dir",
						use: "enc",
					},
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode(testKey)),
						kid: "test-key-4",
						alg: "dir",
						use: "enc",
					},
				],
			};

			const result = await JWT.decrypt({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(true);
			expect(result.payload.sub).toBe(testPayload.sub);
			expect(result.payload.name).toBe(testPayload.name);
		});

		test("should fail decryption with JWK Set when no matching key is found", async () => {
			// Create a token with a key ID
			const token = await JWT.encrypt({
				payload: testPayload,
				key: testKey,
				header: { kid: "non-existent-key" },
			});

			// Create a JWK Set without the matching key
			const jwkSet: JWKKeySet = {
				keys: [
					{
						kty: "oct",
						k: base64Url.encode(new TextEncoder().encode("wrong-key")),
						kid: "wrong-key-id",
						alg: "dir",
						use: "enc",
					},
				],
			};

			const result = await JWT.decrypt({
				token,
				key: jwkSet,
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
			expect(result.error).toContain("No matching key found in JWK Set");
		});

		test("should fail decryption with wrong key", async () => {
			const token = await JWT.encrypt({
				payload: testPayload,
				key: testKey,
			});

			const result = await JWT.decrypt({
				token,
				key: "wrong-key",
				audience: "test-audience",
				issuer: "test-issuer",
			});

			expect(result.valid).toBe(false);
		});
	});

	describe("decode", () => {
		test("should decode a token without verification", () => {
			const parts = [
				"eyJhbGciOiJIUzI1NiJ9", // {"alg":"HS256"}
				"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IlRlc3QgVXNlciJ9", // {"sub":"1234567890","name":"Test User"}
				"signature-not-verified",
			];
			const token = parts.join(".");

			const decoded = JWT.decode(token);
			expect(decoded.header.alg).toBe("HS256");
			expect(decoded.payload.sub).toBe("1234567890");
			expect(decoded.payload.name).toBe("Test User");
		});

		test("should throw on invalid token format", () => {
			expect(() => JWT.decode("invalid-token")).toThrow("Invalid JWT format");
		});
	});

	describe("property-based tests", () => {
		// Arbitrary for generating valid payloads
		const validPayloadArb = fc.record({
			sub: fc.string(),
			name: fc.string(),
			iat: fc.integer({ min: 0 }),
			exp: fc.integer({ min: Math.floor(Date.now() / 1000) + 1000 }), // Future expiration
			iss: fc.string(),
			aud: fc.string(),
		});

		// Arbitrary for generating valid keys
		const validKeyArb = fc.string({ minLength: 16 });

		test("sign and verify should be symmetric operations", async () => {
			await fc.assert(
				fc.asyncProperty(validPayloadArb, validKeyArb, async (payload, key) => {
					// Create a token with a key ID
					const token = await JWT.sign({
						payload,
						key,
						header: { kid: "test-key-prop" },
					});

					// Create a JWK Set with the key
					const jwkSet: JWKKeySet = {
						keys: [
							{
								kty: "oct",
								k: base64Url.encode(new TextEncoder().encode(key)),
								kid: "test-key-prop",
								alg: "HS256",
								use: "sig",
							},
						],
					};

					const result = await JWT.verify({
						token,
						key: jwkSet,
						audience: payload.aud,
						issuer: payload.iss,
					});
					return result.valid && result.payload.sub === payload.sub;
				}),
				{ numRuns: 10 }, // Limit runs for test performance
			);
		});

		test("encrypt and decrypt should be symmetric operations", async () => {
			await fc.assert(
				fc.asyncProperty(validPayloadArb, validKeyArb, async (payload, key) => {
					const token = await JWT.encrypt({ payload, key });
					const result = await JWT.decrypt({
						token,
						key,
						audience: payload.aud,
						issuer: payload.iss,
					});
					return result.valid && result.payload.sub === payload.sub;
				}),
				{ numRuns: 10 }, // Limit runs for test performance
			);
		});
	});
});
