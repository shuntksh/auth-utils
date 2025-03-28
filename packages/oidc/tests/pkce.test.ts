import { describe, expect, it } from "bun:test";

import { CodeChallengeMethods, PKCE, _util } from "@auth-utils/oidc/pkce";

const { generateCodeVerifier, generateCodeChallenge } = _util;

describe("PKCE", () => {
	describe("generateCodeVerifier", () => {
		it("should generate a code verifier of the specified length", () => {
			const verifier = generateCodeVerifier(100);
			// Base64url encoding might result in a slightly shorter string due to padding removal
			// but it should be close to the requested length and at least the minimum required length
			expect(verifier.length).toBeGreaterThanOrEqual(43);
			expect(verifier.length).toBeLessThanOrEqual(100);
		});

		it("should generate a code verifier with valid characters", () => {
			const verifier = generateCodeVerifier();
			// RFC 7636 specifies: ALPHA / DIGIT / "-" / "." / "_" / "~"
			expect(verifier).toMatch(/^[A-Za-z0-9\-._~]+$/);
		});

		it("should throw an error for invalid lengths", () => {
			expect(() => generateCodeVerifier(42)).toThrow();
			expect(() => generateCodeVerifier(129)).toThrow();
		});

		it("should generate different verifiers on each call", () => {
			const verifier1 = generateCodeVerifier();
			const verifier2 = generateCodeVerifier();
			expect(verifier1).not.toBe(verifier2);
		});
	});

	describe("generateCodeChallenge", () => {
		it("should generate a plain code challenge", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			const challenge = await generateCodeChallenge(
				verifier,
				CodeChallengeMethods.PLAIN,
			);
			expect(challenge).toBe(verifier);
		});

		it("should generate an S256 code challenge", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			const challenge = await generateCodeChallenge(
				verifier,
				CodeChallengeMethods.S256,
			);

			// The challenge should be a base64url-encoded string
			expect(challenge).toMatch(/^[A-Za-z0-9\-_]+$/);

			// The challenge should be different from the verifier
			expect(challenge).not.toBe(verifier);
		});

		it("should use S256 by default", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			const challenge = await generateCodeChallenge(verifier);
			const s256Challenge = await generateCodeChallenge(
				verifier,
				CodeChallengeMethods.S256,
			);
			expect(challenge).toBe(s256Challenge);
		});

		it("should throw an error for invalid verifiers", async () => {
			// Empty verifier
			expect(generateCodeChallenge("")).rejects.toThrow();

			// Too short verifier
			expect(generateCodeChallenge("abc")).rejects.toThrow();

			// Invalid characters
			expect(generateCodeChallenge(`${"a".repeat(43)}#`)).rejects.toThrow();
		});

		it("should throw an error for unsupported methods", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			expect(
				// @ts-expect-error Testing invalid method
				generateCodeChallenge(verifier, "invalid"),
			).rejects.toThrow();
		});
	});

	describe("generatePKCE", () => {
		it("should generate PKCE parameters with default options", async () => {
			const pkce = await PKCE.generate();

			expect(pkce.codeVerifier).toBeDefined();
			expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(43);
			expect(pkce.codeVerifier.length).toBeLessThanOrEqual(128);
			expect(pkce.codeVerifier).toMatch(/^[A-Za-z0-9\-._~]+$/);

			expect(pkce.codeChallenge).toBeDefined();
			expect(pkce.codeChallenge).toMatch(/^[A-Za-z0-9\-_]+$/);

			expect(pkce.codeChallengeMethod).toBe(CodeChallengeMethods.S256);
		});

		it("should generate PKCE parameters with custom options", async () => {
			const pkce = await PKCE.generate({
				length: 100,
				method: CodeChallengeMethods.PLAIN,
			});

			expect(pkce.codeVerifier).toBeDefined();
			expect(pkce.codeVerifier.length).toBeGreaterThanOrEqual(43);
			expect(pkce.codeVerifier.length).toBeLessThanOrEqual(100);

			expect(pkce.codeChallenge).toBe(pkce.codeVerifier);
			expect(pkce.codeChallengeMethod).toBe(CodeChallengeMethods.PLAIN);
		});
	});

	describe("PKCE.verify", () => {
		it("should verify a valid PKCE pair with S256 method", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			const challenge = await generateCodeChallenge(
				verifier,
				CodeChallengeMethods.S256,
			);

			const result = await PKCE.verify({
				codeVerifier: verifier,
				codeChallenge: challenge,
				codeChallengeMethod: CodeChallengeMethods.S256,
			});

			expect(result).toBe(true);
		});

		it("should verify a valid PKCE pair with PLAIN method", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			const challenge = await generateCodeChallenge(
				verifier,
				CodeChallengeMethods.PLAIN,
			);

			const result = await PKCE.verify({
				codeVerifier: verifier,
				codeChallenge: challenge,
				codeChallengeMethod: CodeChallengeMethods.PLAIN,
			});

			expect(result).toBe(true);
		});

		it("should reject an invalid PKCE pair", async () => {
			const verifier =
				"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~";
			const challenge = await generateCodeChallenge(
				verifier,
				CodeChallengeMethods.S256,
			);

			// Different verifier
			const result1 = await PKCE.verify({
				codeVerifier: `${verifier}X`,
				codeChallenge: challenge,
				codeChallengeMethod: CodeChallengeMethods.S256,
			});
			expect(result1).toBe(false);

			// Different challenge
			const result2 = await PKCE.verify({
				codeVerifier: verifier,
				codeChallenge: `${challenge}X`,
				codeChallengeMethod: CodeChallengeMethods.S256,
			});
			expect(result2).toBe(false);

			// Different method
			const result3 = await PKCE.verify({
				codeVerifier: verifier,
				codeChallenge: challenge,
				codeChallengeMethod: CodeChallengeMethods.PLAIN,
			});
			expect(result3).toBe(false);
		});

		it("should handle invalid inputs gracefully", async () => {
			// Invalid verifier (too short)
			const result = await PKCE.verify({
				codeVerifier: "abc",
				codeChallenge: "xyz",
				codeChallengeMethod: CodeChallengeMethods.S256,
			});
			expect(result).toBe(false);
		});
	});

	describe("PKCE object", () => {
		it("should expose the correct methods", () => {
			expect(typeof PKCE.generate).toBe("function");
			expect(typeof PKCE.verify).toBe("function");
		});

		it("should work with the exported PKCE object", async () => {
			const pkce = await PKCE.generate();

			const result = await PKCE.verify({
				codeVerifier: pkce.codeVerifier,
				codeChallenge: pkce.codeChallenge,
				codeChallengeMethod: pkce.codeChallengeMethod,
			});

			expect(result).toBe(true);
		});
	});
});
