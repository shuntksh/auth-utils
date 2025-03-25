/**
 * RFC 7517 JSON Web Key (JWK)
 *
 * This module provides functionality for working with JSON Web Keys:
 * - parse: Parses a JWK from a JSON string or object
 * - verify: Verifies a JWS signature using a JWK
 * - createRemoteKeySet: Fetches a JWK Set from a remote URL
 * - findKey: Finds a key in a JWK Set by key ID or other criteria
 */

import { JWTError, base64Url } from "./deps";
import type { JWSHeader } from "./jws";
import type { StandardClaims } from "./jwt";

/**
 * Key Types as defined in RFC 7518 Section 6.1
 */
export type JWKKeyType = "RSA" | "EC" | "oct";

/**
 * Key Operations as defined in RFC 7517 Section 4.3
 */
export type JWKKeyOperation =
	| "sign"
	| "verify"
	| "encrypt"
	| "decrypt"
	| "wrapKey"
	| "unwrapKey"
	| "deriveKey"
	| "deriveBits";

/**
 * Common JWK parameters as defined in RFC 7517 Section 4
 */
export interface Key {
	/** Key Type (required) */
	kty: JWKKeyType;
	/** Key ID (optional) */
	kid?: string;
	/** Key Use (optional) */
	use?: "sig" | "enc";
	/** Key Operations (optional) */
	key_ops?: JWKKeyOperation[];
	/** Algorithm (optional) */
	alg?: string;
	/** X.509 URL (optional) */
	x5u?: string;
	/** X.509 Certificate Chain (optional) */
	x5c?: string[];
	/** X.509 Certificate SHA-1 Thumbprint (optional) */
	x5t?: string;
	/** X.509 Certificate SHA-256 Thumbprint (optional) */
	"x5t#S256"?: string;
	/** Additional properties */
	[key: string]: unknown;
}

/**
 * RSA JWK parameters as defined in RFC 7518 Section 6.3
 */
export interface RSAKey extends Key {
	kty: "RSA";
	/** Modulus */
	n: string;
	/** Exponent */
	e: string;
	/** Private Exponent (private key only) */
	d?: string;
	/** First Prime Factor (private key only) */
	p?: string;
	/** Second Prime Factor (private key only) */
	q?: string;
	/** First Factor CRT Exponent (private key only) */
	dp?: string;
	/** Second Factor CRT Exponent (private key only) */
	dq?: string;
	/** First CRT Coefficient (private key only) */
	qi?: string;
	/** Other Primes Info (private key only) */
	oth?: Array<{
		/** Prime Factor */
		r: string;
		/** Factor CRT Exponent */
		d: string;
		/** Factor CRT Coefficient */
		t: string;
	}>;
}

/**
 * EC JWK parameters as defined in RFC 7518 Section 6.2
 */
export interface ECKey extends Key {
	kty: "EC";
	/** Curve */
	crv: "P-256" | "P-384" | "P-521";
	/** X Coordinate */
	x: string;
	/** Y Coordinate */
	y: string;
	/** ECC Private Key (private key only) */
	d?: string;
}

/**
 * Symmetric JWK parameters as defined in RFC 7518 Section 6.4
 */
export interface OctKey extends Key {
	kty: "oct";
	/** Key Value */
	k: string;
}

/**
 * Union type for all supported JWK types
 */
export type JWKKey = RSAKey | ECKey | OctKey;

/**
 * JWK Set as defined in RFC 7517 Section 5
 */
export interface JWKKeySet {
	/** Array of JWK objects */
	keys: JWKKey[];
}

/**
 * Key finder options
 */
export interface KeyFinderOptions {
	/** Key ID to match */
	kid?: string;
	/** Key Type to match */
	kty?: JWKKeyType;
	/** Key Use to match */
	use?: "sig" | "enc";
	/** Algorithm to match */
	alg?: string;
}

/**
 * Verification options
 */
export interface VerifyOptions {
	/** JWS token to verify */
	token: string;
	/** JWK to use for verification */
	key: JWKKey;
}

/**
 * Verification result
 */
export interface VerifyResult {
	/** Whether the verification was successful */
	valid: boolean;
	/** The decoded header */
	header: JWSHeader;
	/** The decoded payload */
	payload: StandardClaims;
	/** Error message if verification failed */
	error?: string;
}

/**
 * Parses a JWK from a JSON string or object
 * @param jwk - JWK as a JSON string or object
 * @returns Parsed JWK
 * @throws Error if the JWK is invalid
 */
function parse(jwk: string | object): JWKKey {
	const key = typeof jwk === "string" ? JSON.parse(jwk) : jwk;

	// Validate required fields
	if (!key.kty) {
		throw new JWTError("Invalid JWK: missing required field 'kty'");
	}

	// Validate key type
	if (!["RSA", "EC", "oct"].includes(key.kty)) {
		throw new JWTError(`Invalid JWK: unsupported key type '${key.kty}'`);
	}

	// Validate key-specific required fields
	switch (key.kty) {
		case "RSA":
			if (!key.n || !key.e) {
				throw new JWTError(
					"Invalid RSA JWK: missing required fields 'n' and/or 'e'",
				);
			}
			break;
		case "EC":
			if (!key.crv || !key.x || !key.y) {
				throw new JWTError(
					"Invalid EC JWK: missing required fields 'crv', 'x', and/or 'y'",
				);
			}
			break;
		case "oct":
			if (!key.k) {
				throw new JWTError("Invalid oct JWK: missing required field 'k'");
			}
			break;
	}

	return key as JWKKey;
}

/**
 * Verifies a JWS signature using a JWK
 * @param options - Verification options
 * @returns Verification result
 */
async function verify(options: VerifyOptions): Promise<VerifyResult> {
	const { token, key } = options;

	try {
		// Split the token into its components
		const parts = token.split(".");
		if (parts.length !== 3) {
			return {
				valid: false,
				header: { alg: "HS256" },
				payload: {},
				error: "Invalid JWS token format",
			};
		}

		const [encodedHeader, encodedPayload, encodedSignature] = parts;

		// Decode and parse the header
		const header = base64Url.decodeAsJSON<JWSHeader>(encodedHeader);

		// Create the JWS Signing Input
		const signingInput = `${encodedHeader}.${encodedPayload}`;

		// Verify based on key type and algorithm
		let isValid = false;

		if (key.kty === "oct" && header.alg === "HS256") {
			// HMAC-SHA256 verification
			isValid = await verifyHmacSignature({
				key: key as OctKey,
				signingInput,
				signature: encodedSignature,
			});
		} else if (key.kty === "RSA" && header.alg?.startsWith("RS")) {
			// RSA verification
			isValid = await verifyRsaSignature({
				key: key as RSAKey,
				signingInput,
				signature: encodedSignature,
				algorithm: header.alg,
			});
		} else if (key.kty === "EC" && header.alg?.startsWith("ES")) {
			// ECDSA verification
			isValid = await verifyEcSignature({
				key: key as ECKey,
				signingInput,
				signature: encodedSignature,
				algorithm: header.alg,
			});
		} else {
			return {
				valid: false,
				header,
				payload: {},
				error: `Unsupported key type (${key.kty}) or algorithm (${header.alg})`,
			};
		}

		if (!isValid) {
			return {
				valid: false,
				header,
				payload: base64Url.decodeAsJSON<StandardClaims>(encodedPayload),
				error: "Invalid signature",
			};
		}

		// Decode and return the payload
		return {
			valid: true,
			header,
			payload: base64Url.decodeAsJSON<StandardClaims>(encodedPayload),
		};
	} catch (error) {
		return {
			valid: false,
			header: { alg: "HS256" },
			payload: {},
			error: (error as Error).message,
		};
	}
}

/**
 * Verifies an HMAC signature
 * @param options - Verification options
 * @returns Whether the signature is valid
 */
async function verifyHmacSignature(options: {
	key: OctKey;
	signingInput: string;
	signature: string;
}): Promise<boolean> {
	const { key, signingInput, signature } = options;

	// Decode the key
	const keyBytes = base64Url.decode(key.k);

	// Import the key
	const cryptoKey = await crypto.subtle.importKey(
		"raw",
		keyBytes,
		{ name: "HMAC", hash: { name: "SHA-256" } },
		false,
		["verify"],
	);

	// Verify the signature
	return crypto.subtle.verify(
		"HMAC",
		cryptoKey,
		base64Url.decode(signature),
		new TextEncoder().encode(signingInput),
	);
}

/**
 * Verifies an RSA signature
 * @param options - Verification options
 * @returns Whether the signature is valid
 */
async function verifyRsaSignature(options: {
	key: RSAKey;
	signingInput: string;
	signature: string;
	algorithm: string;
}): Promise<boolean> {
	const { key, signingInput, signature, algorithm } = options;

	// Determine the hash algorithm
	let hashAlgorithm: string;
	switch (algorithm) {
		case "RS256":
			hashAlgorithm = "SHA-256";
			break;
		case "RS384":
			hashAlgorithm = "SHA-384";
			break;
		case "RS512":
			hashAlgorithm = "SHA-512";
			break;
		default:
			throw new JWTError(`Unsupported RSA algorithm: ${algorithm}`);
	}

	// Import the key
	const cryptoKey = await crypto.subtle.importKey(
		"jwk",
		{
			kty: key.kty,
			n: key.n,
			e: key.e,
			alg: algorithm,
			ext: true,
		},
		{ name: "RSASSA-PKCS1-v1_5", hash: { name: hashAlgorithm } },
		false,
		["verify"],
	);

	// Verify the signature
	return crypto.subtle.verify(
		"RSASSA-PKCS1-v1_5",
		cryptoKey,
		base64Url.decode(signature),
		new TextEncoder().encode(signingInput),
	);
}

/**
 * Verifies an ECDSA signature
 * @param options - Verification options
 * @returns Whether the signature is valid
 */
async function verifyEcSignature(options: {
	key: ECKey;
	signingInput: string;
	signature: string;
	algorithm: string;
}): Promise<boolean> {
	const { key, signingInput, signature, algorithm } = options;

	// Determine the hash algorithm
	let hashAlgorithm: string;
	switch (algorithm) {
		case "ES256":
			hashAlgorithm = "SHA-256";
			break;
		case "ES384":
			hashAlgorithm = "SHA-384";
			break;
		case "ES512":
			hashAlgorithm = "SHA-512";
			break;
		default:
			throw new JWTError(`Unsupported ECDSA algorithm: ${algorithm}`);
	}

	// Import the key
	const cryptoKey = await crypto.subtle.importKey(
		"jwk",
		{
			kty: key.kty,
			crv: key.crv,
			x: key.x,
			y: key.y,
			alg: algorithm,
			ext: true,
		},
		{ name: "ECDSA", namedCurve: key.crv },
		false,
		["verify"],
	);

	// Verify the signature
	return crypto.subtle.verify(
		{ name: "ECDSA", hash: { name: hashAlgorithm } },
		cryptoKey,
		base64Url.decode(signature),
		new TextEncoder().encode(signingInput),
	);
}

/**
 * Finds a key in a JWK Set by key ID or other criteria
 * @param keySet - JWK Set to search
 * @param options - Key finder options
 * @returns Found key or undefined if not found
 */
export function findKey(
	keySet: JWKKeySet,
	options: KeyFinderOptions,
): JWKKey | undefined {
	const { kid, kty, use, alg } = options;

	return keySet.keys.find((key) => {
		// Match by key ID if provided
		if (kid && key.kid !== kid) {
			return false;
		}

		// Match by key type if provided
		if (kty && key.kty !== kty) {
			return false;
		}

		// Match by key use if provided
		if (use && key.use !== use) {
			return false;
		}

		// Match by algorithm if provided
		if (alg && key.alg !== alg) {
			return false;
		}

		return true;
	});
}

/**
 * Fetches a JWK Set from a remote URL
 * @param url - URL to fetch the JWK Set from
 * @returns Promise resolving to the JWK Set
 * @throws Error if the fetch fails or the response is invalid
 */
const createRemoteKeySet = async (url: string): Promise<JWKKeySet> => {
	try {
		// Fetch the JWK Set
		const response = await fetch(url);

		// Check if the response is OK
		if (!response.ok) {
			throw new JWTError(
				`Failed to fetch JWK Set: ${response.status} ${response.statusText}`,
			);
		}

		// Parse the response as JSON
		const jwks = await response.json();

		// Validate the JWK Set
		if (!jwks.keys || !Array.isArray(jwks.keys)) {
			throw new JWTError("Invalid JWK Set: missing or invalid 'keys' array");
		}

		// Validate each key in the set
		const validatedKeys: JWKKey[] = [];
		for (const key of jwks.keys) {
			try {
				validatedKeys.push(JWK.parse(key));
			} catch (error) {
				console.warn(
					`Skipping invalid key in JWK Set: ${(error as Error).message}`,
				);
			}
		}

		return { keys: validatedKeys };
	} catch (error) {
		throw new JWTError(
			`Failed to create remote key set: ${(error as Error).message}`,
		);
	}
};

export const JWK = {
	createRemoteKeySet,
	parse,
	verify,
	findKey,
} as const;
