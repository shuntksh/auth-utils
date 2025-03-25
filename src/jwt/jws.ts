import { sha256 } from "./crypto";
import { JWTError, base64Url, constantTimeEqual, keyToBuffer } from "./deps";
import type { StandardClaims } from "./jwt";

/**
 * JWS Header interface
 */
export interface JWSHeader {
	alg: "HS256";
	typ?: string;
	kid?: string;
	[key: string]: unknown;
}

/**
 * RFC7515 JSON Web Signature (JWS)
 *
 * This implementation follows the JWS Compact Serialization format as defined in RFC7515.
 * It currently supports HMAC SHA-256 (HS256) for signature generation and verification.
 */
export const JWS = {
	sign: signJWS,
	verify: verifyJWS,
} as const;

/**
 * Signs a payload using HMAC SHA-256 and produces a JWS token
 *
 * @param options - Options object containing:
 *   - key: The key as string, ArrayBuffer, or Uint8Array
 *   - payload: The payload to sign (StandardClaims object)
 *   - header: Optional additional header parameters
 * @returns A JWS token string in compact serialization format
 */
export async function signJWS(options: {
	key: string | ArrayBuffer | Uint8Array;
	payload: StandardClaims;
	header?: Partial<JWSHeader>;
}): Promise<string> {
	const { key, payload, header = {} } = options;

	// Create the JWS Protected Header
	const protectedHeader: JWSHeader = {
		alg: "HS256",
		...header,
	};

	// Base64Url encode the header
	const encodedHeader = base64Url.encode(JSON.stringify(protectedHeader));

	// Base64Url encode the payload
	const encodedPayload = base64Url.encode(JSON.stringify(payload));

	// Create the JWS Signing Input
	const signingInput = `${encodedHeader}.${encodedPayload}`;

	// Convert the key to a BufferSource
	const keyBuffer = keyToBuffer(key);

	// Sign the input using HMAC SHA-256
	const signatureBuffer = await sha256({
		key: keyBuffer,
		message: new TextEncoder().encode(signingInput),
	});

	// Base64Url encode the signature
	const encodedSignature = base64Url.encode(new Uint8Array(signatureBuffer));

	// Return the JWS Compact Serialization
	return `${signingInput}.${encodedSignature}`;
}

/**
 * Verifies a JWS token and returns the payload if valid
 *
 * @param options - Options object containing:
 *   - token: The JWS token to verify
 *   - key: The key as string, ArrayBuffer, or Uint8Array
 * @returns The verified payload (StandardClaims object)
 * @throws Error if the token is invalid or verification fails
 */
export async function verifyJWS(options: {
	token: string;
	key: string | ArrayBuffer | Uint8Array;
}): Promise<StandardClaims> {
	const { token, key } = options;

	// Split the token into its components
	const parts = token.split(".");
	if (parts.length !== 3) {
		throw new JWTError("Invalid JWS token format");
	}

	const [encodedHeader, encodedPayload, encodedSignature] = parts;

	// Decode and parse the header
	const header = base64Url.decodeAsJSON<JWSHeader>(encodedHeader);

	// Verify the algorithm is supported
	if (header.alg !== "HS256") {
		throw new JWTError(`Unsupported algorithm: ${header.alg}`);
	}

	// Create the JWS Signing Input
	const signingInput = `${encodedHeader}.${encodedPayload}`;

	// Convert the key to a BufferSource
	const keyBuffer = keyToBuffer(key);

	// Generate the expected signature
	const expectedSignatureBuffer = await sha256({
		key: keyBuffer,
		message: new TextEncoder().encode(signingInput),
	});

	// Decode the actual signature from base64url to bytes
	const actualSignatureBytes = base64Url.decode(encodedSignature);

	// Get the expected signature bytes
	const expectedSignatureBytes = new Uint8Array(expectedSignatureBuffer);

	// Verify the signature using constant-time comparison
	if (!constantTimeEqual(actualSignatureBytes, expectedSignatureBytes)) {
		throw new JWTError("Invalid signature");
	}

	// Decode and return the payload
	return base64Url.decodeAsJSON<StandardClaims>(encodedPayload);
}
