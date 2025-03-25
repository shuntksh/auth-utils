import { JWTError, base64Url } from "./deps";
import { JWE, type JWEHeader } from "./jwe";
import { JWK, type JWKKeySet, type Key } from "./jwk";
import { JWS, type JWSHeader } from "./jws";

/**
 * Standard JWT Claims
 */
export interface StandardClaims {
	iss?: string; // Issuer
	sub?: string; // Subject
	aud?: string | string[]; // Audience
	exp?: number; // Expiration Time
	nbf?: number; // Not Before
	iat?: number; // Issued At
	jti?: string; // JWT ID
	[key: string]: unknown; // Allow for custom claims
}

/**
 * JWT Verification Options
 */
export interface VerifyOptions {
	audience?: string | string[];
	issuer?: string;
	subject?: string;
	clockTolerance?: number; // Seconds of tolerance for exp and nbf claims
}

/**
 * JWT Verification Result
 */
export interface VerifyResult {
	valid: boolean;
	header: JWSHeader | JWEHeader;
	payload: StandardClaims;
	error?: string;
}

/**
 * RFC 7519: JSON Web Token (JWT)
 *
 * This module provides functionality for working with JSON Web Tokens:
 * - sign: Creates a signed JWT token using JWS
 * - verify: Verifies a JWT token's signature and claims
 * - encrypt: Creates an encrypted JWT token using JWE
 * - decrypt: Decrypts and verifies a JWT token
 * - decode: Decodes a JWT token without verification
 */
export const JWT = {
	sign,
	verify,
	encrypt,
	decrypt,
	decode,
	verifyClaims,
} as const;

/**
 * Signs a payload and creates a JWT token
 * @param options - Options object containing:
 *   - payload: The payload to sign
 *   - key: The secret key
 *   - header: Optional additional header parameters
 * @returns Promise resolving to the signed JWT token
 *
 * Implements RFC 7519 Section 7.1 - JWT Creation
 */
export async function sign(options: {
	payload: StandardClaims;
	key: string | ArrayBuffer | Uint8Array;
	header?: Partial<JWSHeader>;
}): Promise<string> {
	const { payload, key, header } = options;

	// Add issued at time if not present
	if (payload.iat === undefined) {
		payload.iat = Math.floor(Date.now() / 1000);
	}

	return JWS.sign({ payload, key, header });
}

/**
 * Verifies a JWT token's signature and claims
 * @param options - Options object containing:
 *   - token: The JWT token to verify
 *   - key: The JWK Set containing verification keys
 *   - audience: The expected audience
 *   - issuer: The expected issuer
 *   - subject: The expected subject
 *   - clockTolerance: The clock tolerance in seconds
 * @returns Promise resolving to the verification result
 *
 * Implements RFC 7519 Section 7.2 - JWT Validation
 */
export async function verify(
	options: {
		token: string;
		key: JWKKeySet;
	} & VerifyOptions,
): Promise<VerifyResult> {
	const { token, key, ...verifyOptions } = options;

	try {
		// Split the token to get the header for the result
		const parts = token.split(".");
		if (parts.length !== 3) {
			return {
				valid: false,
				header: { alg: "HS256" },
				payload: {},
				error: "Invalid JWT format",
			};
		}

		const header = base64Url.decodeAsJSON<JWSHeader>(parts[0]);
		const payload = base64Url.decodeAsJSON<StandardClaims>(parts[1]);

		// Find the appropriate key in the JWK Set
		const matchingKey = JWK.findKey(key, {
			kid: header.kid,
			use: "sig",
		});

		if (!matchingKey) {
			return {
				valid: false,
				header,
				payload,
				error: `No matching key found in JWK Set${header.kid ? ` for kid: ${header.kid}` : ""}`,
			};
		}

		// Verify the signature using the JWK
		const jwkResult = await JWK.verify({ token, key: matchingKey });

		if (!jwkResult.valid) {
			return jwkResult;
		}

		// Verify the claims
		const claimCheck = verifyClaims({
			payload: jwkResult.payload,
			...verifyOptions,
		});

		if (!claimCheck.success) {
			return {
				valid: false,
				header: jwkResult.header,
				payload: jwkResult.payload,
				error: claimCheck.error,
			};
		}

		return {
			valid: true,
			header: jwkResult.header,
			payload: jwkResult.payload,
		};
	} catch (error) {
		// Get the header and payload for the error result if possible
		let header: JWSHeader = { alg: "HS256" };
		let payload: StandardClaims = {};

		try {
			const parts = token.split(".");
			if (parts.length >= 2) {
				header = base64Url.decodeAsJSON<JWSHeader>(parts[0]);
				payload = base64Url.decodeAsJSON<StandardClaims>(parts[1]);
			}
		} catch {
			// If we can't parse the header or payload, use the defaults
		}

		return {
			valid: false,
			header,
			payload,
			error: (error as Error).message,
		};
	}
}

/**
 * Encrypts a payload and creates a JWE token
 * @param options - Options object containing:
 *   - payload: The payload to encrypt
 *   - key: The secret key
 *   - header: Optional additional header parameters
 * @returns Promise resolving to the encrypted JWE token
 *
 * Implements RFC 7519 Section 6.2 - Encryption of JWT Claims
 */
export async function encrypt(options: {
	payload: StandardClaims;
	key: string | ArrayBuffer | Uint8Array;
	header?: Partial<JWEHeader>;
}): Promise<string> {
	const { payload, key, header } = options;

	// Add issued at time if not present
	if (payload.iat === undefined) {
		payload.iat = Math.floor(Date.now() / 1000);
	}

	return JWE.encrypt({ payload, key, header });
}

/**
 * Decrypts a JWE token and verifies its claims
 * @param options - Options object containing:
 *   - token: The JWE token to decrypt
 *   - key: The secret key or JWK or JWK Set
 *   - audience: The expected audience
 *   - issuer: The expected issuer
 *   - subject: The expected subject
 *   - clockTolerance: The clock tolerance in seconds
 * @returns Promise resolving to the verification result
 *
 * Implements RFC 7519 Sections 6.2 and 7.2 - Decryption and Validation
 */
export async function decrypt(
	options: {
		token: string;
		key: string | ArrayBuffer | Uint8Array | Key | JWKKeySet;
	} & VerifyOptions,
): Promise<VerifyResult> {
	const { token, key, ...verifyOptions } = options;

	try {
		// Parse the JWE token to get the header
		const parts = token.split(".");
		if (parts.length !== 5) {
			return {
				valid: false,
				header: { alg: "dir", enc: "A128CBC-HS256" },
				payload: {},
				error: "Invalid JWE token format",
			};
		}

		const encodedHeader = parts[0];
		const header = base64Url.decodeAsJSON<JWEHeader>(encodedHeader);

		// If key is a JWK Set, find the appropriate key
		let decryptionKey = key;
		if (typeof key === "object" && "keys" in key) {
			const keySet = key as JWKKeySet;
			const matchingKey = JWK.findKey(keySet, {
				kid: header.kid,
				use: "enc",
			});

			if (!matchingKey) {
				return {
					valid: false,
					header,
					payload: {},
					error: `No matching key found in JWK Set${header.kid ? ` for kid: ${header.kid}` : ""}`,
				};
			}

			// For JWK, we need to extract the raw key material
			if (matchingKey.kty === "oct") {
				decryptionKey = base64Url.decode(matchingKey.k);
			} else {
				return {
					valid: false,
					header,
					payload: {},
					error: `Unsupported key type for JWE decryption: ${matchingKey.kty}`,
				};
			}
		} else if (typeof decryptionKey === "object" && "kty" in decryptionKey) {
			// Single JWK
			const jwk = decryptionKey as Key;
			if (jwk.kty === "oct" && typeof jwk.k === "string") {
				decryptionKey = base64Url.decode(jwk.k);
			} else {
				return {
					valid: false,
					header,
					payload: {},
					error: `Unsupported key type for JWE decryption or missing key material: ${jwk.kty}`,
				};
			}
		}

		// Decrypt the token with the appropriate key
		// Ensure decryptionKey is a valid type for JWE.decrypt
		if (
			typeof decryptionKey !== "string" &&
			!(decryptionKey instanceof ArrayBuffer) &&
			!(decryptionKey instanceof Uint8Array)
		) {
			return {
				valid: false,
				header,
				payload: {},
				error: "Invalid key type for JWE decryption",
			};
		}

		const decrypted = await JWE.decrypt({ token, key: decryptionKey });

		// Verify the claims
		const claimCheck = verifyClaims({
			payload: decrypted.payload,
			...verifyOptions,
		});

		if (!claimCheck.success) {
			return {
				valid: false,
				header: decrypted.header,
				payload: decrypted.payload,
				error: claimCheck.error,
			};
		}

		return {
			valid: true,
			header: decrypted.header,
			payload: decrypted.payload,
		};
	} catch (error) {
		// For JWE tokens, we can't easily extract the header and payload on error
		return {
			valid: false,
			header: { alg: "dir", enc: "A128CBC-HS256" },
			payload: {},
			error: (error as Error).message,
		};
	}
}

/**
 * Decodes a JWT token without verifying the signature
 * @param token - The JWT token to decode
 * @returns The decoded header and payload
 * @throws Error if the token format is invalid
 *
 * Implements RFC 7519 Section 7.2 (partial, without validation)
 */
export function decode(token: string): {
	header: JWSHeader;
	payload: StandardClaims;
} {
	const parts = token.split(".");
	if (parts.length !== 3) {
		throw new JWTError("Invalid JWT format");
	}

	const [headerB64, payloadB64] = parts;

	try {
		const header = base64Url.decodeAsJSON<JWSHeader>(headerB64);
		const payload = base64Url.decodeAsJSON<StandardClaims>(payloadB64);

		return { header, payload };
	} catch (error) {
		throw new JWTError(`Failed to decode JWT: ${(error as Error).message}`);
	}
}

/**
 * Verifies the standard claim set in a JWT payload
 * @param options - Options object containing:
 *   - payload: The JWT payload
 *   - audience: The expected audience
 *   - issuer: The expected issuer
 *   - subject: The expected subject
 *   - clockTolerance: The clock tolerance in seconds (default: 0)
 * @returns Object indicating if the claims are valid and any error message
 *
 * Implements RFC 7519 Section 4.1 - Registered Claim Names Validation
 */
export function verifyClaims(
	options: {
		payload: StandardClaims;
	} & VerifyOptions,
): { success: boolean; error?: string } {
	const { payload, audience, issuer, subject, clockTolerance = 0 } = options;
	const now = Math.floor(Date.now() / 1000);

	if (payload.exp !== undefined && now > payload.exp + clockTolerance) {
		return { success: false, error: "Token has expired" };
	}

	if (payload.nbf !== undefined && now < payload.nbf - clockTolerance) {
		return { success: false, error: "Token is not yet valid" };
	}

	if (audience && payload.aud) {
		const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
		const expectedAudiences = Array.isArray(audience) ? audience : [audience];
		const hasMatchingAudience = audiences.some((aud) =>
			expectedAudiences.includes(aud),
		);
		if (!hasMatchingAudience) {
			return {
				success: false,
				error: "Token audience does not match expected audience",
			};
		}
	}

	if (issuer && payload.iss !== issuer) {
		return {
			success: false,
			error: "Token issuer does not match expected issuer",
		};
	}

	if (subject && payload.sub !== subject) {
		return {
			success: false,
			error: "Token subject does not match expected subject",
		};
	}

	return { success: true };
}
