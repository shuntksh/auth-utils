// @cspell:disable

import { describe, expect, it, mock } from "bun:test";

import { base64Url } from "./deps";
import type { ECKey, JWKKeySet, OctKey, RSAKey } from "./jwk";
import { JWK } from "./jwk";

describe("JWK", () => {
	describe("parse", () => {
		it("should parse a valid RSA JWK", () => {
			const jwk: RSAKey = {
				kty: "RSA",
				n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
				e: "AQAB",
				alg: "RS256",
				kid: "2011-04-29",
			};

			const parsed = JWK.parse(jwk);
			expect(parsed).toEqual(jwk);
		});

		it("should parse a valid EC JWK", () => {
			const jwk: ECKey = {
				kty: "EC",
				crv: "P-256",
				x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
				y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
				use: "enc",
				kid: "1",
			};

			const parsed = JWK.parse(jwk);
			expect(parsed).toEqual(jwk);
		});

		it("should parse a valid oct JWK", () => {
			const jwk: OctKey = {
				kty: "oct",
				k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				kid: "HMAC key",
			};

			const parsed = JWK.parse(jwk);
			expect(parsed).toEqual(jwk);
		});

		it("should throw an error for a JWK with missing kty", () => {
			const jwk = {
				k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				kid: "HMAC key",
			};

			expect(() => JWK.parse(jwk)).toThrow(
				"Invalid JWK: missing required field 'kty'",
			);
		});

		it("should throw an error for a JWK with unsupported kty", () => {
			const jwk = {
				kty: "UNSUPPORTED",
				k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
				kid: "HMAC key",
			};

			expect(() => JWK.parse(jwk)).toThrow(
				"Invalid JWK: unsupported key type 'UNSUPPORTED'",
			);
		});

		it("should throw an error for an RSA JWK with missing required fields", () => {
			const jwk = {
				kty: "RSA",
				kid: "2011-04-29",
			};

			expect(() => JWK.parse(jwk)).toThrow(
				"Invalid RSA JWK: missing required fields 'n' and/or 'e'",
			);
		});

		it("should throw an error for an EC JWK with missing required fields", () => {
			const jwk = {
				kty: "EC",
				kid: "1",
			};

			expect(() => JWK.parse(jwk)).toThrow(
				"Invalid EC JWK: missing required fields 'crv', 'x', and/or 'y'",
			);
		});

		it("should throw an error for an oct JWK with missing required fields", () => {
			const jwk = {
				kty: "oct",
				kid: "HMAC key",
			};

			expect(() => JWK.parse(jwk)).toThrow(
				"Invalid oct JWK: missing required field 'k'",
			);
		});
	});

	describe("findKey", () => {
		const keySet: JWKKeySet = {
			keys: [
				{
					kty: "RSA",
					n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
					e: "AQAB",
					alg: "RS256",
					kid: "2011-04-29",
					use: "sig",
				},
				{
					kty: "EC",
					crv: "P-256",
					x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
					y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
					use: "enc",
					kid: "1",
				},
				{
					kty: "oct",
					k: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow",
					kid: "HMAC key",
					alg: "HS256",
				},
			],
		};

		it("should find a key by kid", () => {
			const key = JWK.findKey(keySet, { kid: "2011-04-29" });
			expect(key).toEqual(keySet.keys[0]);
		});

		it("should find a key by kty", () => {
			const key = JWK.findKey(keySet, { kty: "EC" });
			expect(key).toEqual(keySet.keys[1]);
		});

		it("should find a key by use", () => {
			const key = JWK.findKey(keySet, { use: "enc" });
			expect(key).toEqual(keySet.keys[1]);
		});

		it("should find a key by alg", () => {
			const key = JWK.findKey(keySet, { alg: "HS256" });
			expect(key).toEqual(keySet.keys[2]);
		});

		it("should find a key by multiple criteria", () => {
			const key = JWK.findKey(keySet, { kty: "RSA", use: "sig" });
			expect(key).toEqual(keySet.keys[0]);
		});

		it("should return undefined if no key matches", () => {
			const key = JWK.findKey(keySet, { kid: "non-existent" });
			expect(key).toBeUndefined();
		});
	});

	describe("verify", () => {
		// Create a simple JWT for testing
		const createTestJWT = async (
			payload: Record<string, unknown>,
			key: string,
		): Promise<string> => {
			const header = { alg: "HS256", typ: "JWT" };
			const encodedHeader = base64Url.encode(JSON.stringify(header));
			const encodedPayload = base64Url.encode(JSON.stringify(payload));
			const signingInput = `${encodedHeader}.${encodedPayload}`;

			const keyBytes = new TextEncoder().encode(key);
			const cryptoKey = await crypto.subtle.importKey(
				"raw",
				keyBytes,
				{ name: "HMAC", hash: { name: "SHA-256" } },
				false,
				["sign"],
			);

			const signatureBuffer = await crypto.subtle.sign(
				"HMAC",
				cryptoKey,
				new TextEncoder().encode(signingInput),
			);

			const encodedSignature = base64Url.encode(
				new Uint8Array(signatureBuffer),
			);
			return `${signingInput}.${encodedSignature}`;
		};

		it("should verify a valid JWT with an oct key", async () => {
			const secretKey = "secret";
			const payload = { sub: "1234567890", name: "John Doe", iat: 1516239022 };
			const token = await createTestJWT(payload, secretKey);

			const jwk: OctKey = {
				kty: "oct",
				k: base64Url.encode(new TextEncoder().encode(secretKey)),
				alg: "HS256",
			};

			const result = await JWK.verify({ token, key: jwk });
			expect(result.valid).toBe(true);
			expect(result.payload).toEqual(payload);
		});

		it("should reject a JWT with an invalid signature", async () => {
			const secretKey = "secret";
			const payload = { sub: "1234567890", name: "John Doe", iat: 1516239022 };
			const token = await createTestJWT(payload, secretKey);

			// Use a different key for verification
			const jwk: OctKey = {
				kty: "oct",
				k: base64Url.encode(new TextEncoder().encode("wrong-secret")),
				alg: "HS256",
			};

			const result = await JWK.verify({ token, key: jwk });
			expect(result.valid).toBe(false);
			expect(result.error).toBe("Invalid signature");
		});

		it("should reject a JWT with an invalid format", async () => {
			const jwk: OctKey = {
				kty: "oct",
				k: base64Url.encode(new TextEncoder().encode("secret")),
				alg: "HS256",
			};

			const result = await JWK.verify({ token: "invalid.token", key: jwk });
			expect(result.valid).toBe(false);
			expect(result.error).toBe("Invalid JWS token format");
		});

		it("should reject a JWT with an unsupported algorithm", async () => {
			const header = { alg: "RS256", typ: "JWT" };
			const payload = { sub: "1234567890", name: "John Doe", iat: 1516239022 };
			const encodedHeader = base64Url.encode(JSON.stringify(header));
			const encodedPayload = base64Url.encode(JSON.stringify(payload));
			const token = `${encodedHeader}.${encodedPayload}.signature`;

			const jwk: OctKey = {
				kty: "oct",
				k: base64Url.encode(new TextEncoder().encode("secret")),
				alg: "HS256",
			};

			const result = await JWK.verify({ token, key: jwk });
			expect(result.valid).toBe(false);
			expect(result.error).toContain("Unsupported key type");
		});
	});

	describe("JWK.createRemoteKeySet", () => {
		it("should fetch and parse a remote JWK Set", async () => {
			// Mock the fetch function
			const mockFetch = mock(() =>
				Promise.resolve({
					ok: true,
					json: () =>
						Promise.resolve({
							keys: [
								{
									kty: "RSA",
									n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
									e: "AQAB",
									alg: "RS256",
									kid: "2011-04-29",
								},
							],
						}),
				}),
			);
			global.fetch = mockFetch as unknown as typeof fetch;

			const keySet = await JWK.createRemoteKeySet(
				"https://example.com/.well-known/jwks.json",
			);
			expect(keySet.keys).toHaveLength(1);
			expect(keySet.keys[0].kty).toBe("RSA");
			expect(keySet.keys[0].kid).toBe("2011-04-29");
		});

		it("should handle fetch errors", async () => {
			// Mock the fetch function to throw an error
			const mockFetchError = mock(() =>
				Promise.reject(new Error("Network error")),
			);
			global.fetch = mockFetchError as unknown as typeof fetch;

			await expect(
				JWK.createRemoteKeySet("https://example.com/.well-known/jwks.json"),
			).rejects.toThrow("Failed to create remote key set: Network error");
		});

		it("should handle non-OK responses", async () => {
			// Mock the fetch function to return a non-OK response
			const mockFetchNotFound = mock(() =>
				Promise.resolve({
					ok: false,
					status: 404,
					statusText: "Not Found",
				}),
			);
			global.fetch = mockFetchNotFound as unknown as typeof fetch;

			await expect(
				JWK.createRemoteKeySet("https://example.com/.well-known/jwks.json"),
			).rejects.toThrow(
				"Failed to create remote key set: Failed to fetch JWK Set: 404 Not Found",
			);
		});

		it("should handle invalid JWK Sets", async () => {
			// Mock the fetch function to return an invalid JWK Set
			const mockFetchInvalid = mock(() =>
				Promise.resolve({
					ok: true,
					json: () => Promise.resolve({}),
				}),
			);
			global.fetch = mockFetchInvalid as unknown as typeof fetch;

			await expect(
				JWK.createRemoteKeySet("https://example.com/.well-known/jwks.json"),
			).rejects.toThrow(
				"Failed to create remote key set: Invalid JWK Set: missing or invalid 'keys' array",
			);
		});

		it("should skip invalid keys in a JWK Set", async () => {
			// Mock the fetch function to return a JWK Set with an invalid key
			const mockFetchInvalidKey = mock(() =>
				Promise.resolve({
					ok: true,
					json: () =>
						Promise.resolve({
							keys: [
								{
									kty: "RSA",
									n: "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
									e: "AQAB",
									alg: "RS256",
									kid: "2011-04-29",
								},
								{
									kty: "RSA",
									// Missing required fields n and e
									kid: "invalid-key",
								},
							],
						}),
				}),
			);
			global.fetch = mockFetchInvalidKey as unknown as typeof fetch;

			const keySet = await JWK.createRemoteKeySet(
				"https://example.com/.well-known/jwks.json",
			);
			expect(keySet.keys).toHaveLength(1);
			expect(keySet.keys[0].kid).toBe("2011-04-29");
		});
	});
});
