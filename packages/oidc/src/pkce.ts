import { base64Url, constantTimeEqual, OIDCError } from "./deps";

/**
 * RFC 7636: Proof Key for Code Exchange is a security extension to OAuth 2.0
 * that allows clients to prove possession of a secret by using a code challenge.
 * It is used to prevent CSRF and authorization code injection attacks.
 */
export const PKCE = {
	generate: generatePKCE,
	verify: verifyPKCE,
} as const;

/**
 * Code challenge methods as defined in RFC 7636
 */
export const CodeChallengeMethods = {
	/**
	 * Plain method - code challenge is the same as code verifier
	 * Note: This is less secure and should only be used if S256 is not supported
	 */
	PLAIN: "plain",

	/**
	 * S256 method - code challenge is the base64url encoding of the SHA-256 hash of the code verifier
	 * This is the recommended method for security
	 */
	S256: "S256",
} as const;

export type CodeChallengeMethod =
	(typeof CodeChallengeMethods)[keyof typeof CodeChallengeMethods];

/**
 * PKCE parameters interface
 */
export interface PKCEParams {
	/**
	 * The code verifier - a high-entropy cryptographic random string
	 */
	codeVerifier: string;

	/**
	 * The code challenge - derived from the code verifier
	 */
	codeChallenge: string;

	/**
	 * The method used to derive the code challenge from the code verifier
	 */
	codeChallengeMethod: CodeChallengeMethod;
}

/**
 * Generates a cryptographically random code verifier
 *
 * @param length - Length of the code verifier (between 43 and 128 characters as per RFC 7636)
 * @returns A random code verifier string
 */
function generateCodeVerifier(length = 128): string {
	// RFC 7636 requires a minimum length of 43 characters and maximum of 128
	if (length < 43 || length > 128) {
		throw new OIDCError(
			"Code verifier length must be between 43 and 128 characters",
		);
	}

	// Generate random bytes
	const randomBytes = new Uint8Array(length);
	crypto.getRandomValues(randomBytes);

	// Convert to base64url and ensure it only contains allowed characters
	// RFC 7636 specifies code verifier = [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~"
	// Base64Url already uses a compatible character set, but we'll ensure it's the right length
	const base64Encoded = base64Url.encode(randomBytes);

	// Trim to the requested length, ensuring we don't go below 43 chars
	return base64Encoded.substring(0, Math.max(43, length));
}

/**
 * Generates a code challenge from a code verifier using the specified method
 *
 * @param codeVerifier - The code verifier to derive the challenge from
 * @param method - The method to use for deriving the challenge (S256 or plain)
 * @returns The code challenge
 */
async function generateCodeChallenge(
	codeVerifier: string,
	method: CodeChallengeMethod = CodeChallengeMethods.S256,
): Promise<string> {
	if (!codeVerifier) {
		throw new OIDCError("Code verifier is required");
	}

	// Validate code verifier format according to RFC 7636
	// ABNF: code-verifier = 43*128unreserved
	// unreserved = ALPHA / DIGIT / "-" / "." / "_" / "~"
	const validVerifierPattern = /^[A-Za-z0-9\-._~]{43,128}$/;
	if (!validVerifierPattern.test(codeVerifier)) {
		throw new OIDCError(
			"Code verifier must only contain alphanumeric characters, hyphens, periods, underscores, and tildes, and be between 43 and 128 characters long",
		);
	}

	if (method === CodeChallengeMethods.PLAIN) {
		// For plain method, the challenge is the verifier itself
		return codeVerifier;
	}

	if (method === CodeChallengeMethods.S256) {
		// For S256 method, the challenge is the base64url encoding of the SHA-256 hash of the verifier
		const encoder = new TextEncoder();
		const data = encoder.encode(codeVerifier);
		const hash = await crypto.subtle.digest("SHA-256", data);
		return base64Url.encode(new Uint8Array(hash));
	}

	throw new OIDCError(`Unsupported code challenge method: ${method}`);
}

/**
 * Generates PKCE parameters (code verifier and code challenge)
 *
 * @param options - Options for PKCE generation
 * @param options.length - Length of the code verifier (between 43 and 128 characters)
 * @param options.method - Method to use for deriving the code challenge
 * @returns Promise resolving to PKCE parameters
 */
async function generatePKCE(options?: {
	length?: number;
	method?: CodeChallengeMethod;
}): Promise<PKCEParams> {
	const length = options?.length ?? 128;
	const method = options?.method ?? CodeChallengeMethods.S256;

	if (length < 43 || length > 128) {
		throw new OIDCError(
			"Code verifier length must be between 43 and 128 characters",
		);
	}

	if (
		method !== CodeChallengeMethods.PLAIN &&
		method !== CodeChallengeMethods.S256
	) {
		throw new OIDCError(`Unsupported code challenge method: ${method}`);
	}

	const codeVerifier = generateCodeVerifier(length);
	const codeChallenge = await generateCodeChallenge(codeVerifier, method);

	return {
		codeVerifier,
		codeChallenge,
		codeChallengeMethod: method,
	};
}

/**
 * Verifies that a code challenge matches a code verifier
 *
 * @param options - Verification options
 * @param options.codeVerifier - The code verifier to check
 * @param options.codeChallenge - The code challenge to verify
 * @param options.codeChallengeMethod - The method used to derive the challenge
 * @returns Promise resolving to a boolean indicating whether verification succeeded
 */
async function verifyPKCE(options: {
	codeVerifier: string;
	codeChallenge: string;
	codeChallengeMethod: CodeChallengeMethod;
}): Promise<boolean> {
	const { codeVerifier, codeChallenge, codeChallengeMethod } = options;

	try {
		// Generate a challenge from the provided verifier
		const generatedChallenge = await generateCodeChallenge(
			codeVerifier,
			codeChallengeMethod,
		);

		// Compare the generated challenge with the provided challenge
		// Using constant-time comparison to prevent timing attacks
		return constantTimeEqual(generatedChallenge, codeChallenge);
	} catch (error) {
		// If any error occurs during verification, consider it a failure
		return false;
	}
}

export const _util = {
	generateCodeChallenge,
	generateCodeVerifier,
};
