import { AES_CBC_128, sha256 } from "./crypto";
import { JWTError, base64Url, constantTimeEqual, keyToBuffer } from "./deps";

import type { StandardClaims } from "./jwt";

/**
 * JWE Header interface with JWE specific header parameters for the project
 */
export interface JWEHeader {
	alg: "dir"; // direct use of a shared symmetric key
	enc: "A128CBC-HS256"; // AES-CBC with HMAC-SHA-256
	zip?: "DEF"; // DEFLATE compression
	typ?: string; // type of the content
	cty?: string; // content type
	crit?: string[]; // critical header parameters
	kid?: string; // key identifier
	[key: string]: unknown;
}

/**
 * JWE Decryption Result
 */
export interface DecryptResult {
	header: JWEHeader;
	payload: StandardClaims;
}

const JWE_ALG = "dir" as const;
const JWE_ENC = "A128CBC-HS256" as const;

/**
 * JWE is a utility for encrypting and decrypting payloads using JWE tokens
 * Implements RFC7516 - JSON Web Encryption (JWE)
 *
 * This implementation supports:
 * - Algorithm (alg): "dir" (Direct Encryption with a shared symmetric key)
 * - Encryption (enc): "A128CBC-HS256" (AES-CBC-128 + HMAC-SHA-256)
 *
 * The JWE token format is: header.encryptedKey.iv.ciphertext.tag
 * For "dir" algorithm, the encryptedKey part is empty.
 */
export const JWE = {
	encrypt: encryptJWE,
	decrypt: decryptJWE,
} as const;

/**
 * Encrypts a payload as a JWE token according to RFC7516
 * @param options - Options object containing:
 *   - payload: The payload to encrypt
 *   - key: The secret key as string, ArrayBuffer, or Uint8Array
 *   - header: Optional additional header fields
 * @returns Promise resolving to the JWE token
 * @throws Error if payload or key is missing
 */
export async function encryptJWE(options: {
	payload: StandardClaims;
	key: string | ArrayBuffer | Uint8Array;
	header?: Partial<JWEHeader>;
}): Promise<string> {
	const { payload, key, header = {} } = options;

	if (!payload) throw new JWTError("Payload is required");
	if (!key) throw new JWTError("Key is required");

	// Prepare the header
	const jweHeader: JWEHeader = {
		alg: JWE_ALG,
		enc: JWE_ENC,
		...header,
	};

	// Convert key to BufferSource and derive key
	// For A128CBC-HS256, we need a 256-bit key (32 bytes)
	// First half (16 bytes) for HMAC-SHA-256, second half (16 bytes) for AES-CBC-128
	const keyBuffer = keyToBuffer(key);
	const derivedKey = await deriveKey({
		keyMaterial: keyBuffer,
		info: "JWE-Encryption",
	});

	// Split the key as per RFC7518 Section 5.2.2.1
	const derivedArray = new Uint8Array(derivedKey);
	const macKeyArray = derivedArray.slice(0, 16); // First 128 bits for HMAC
	const encKeyArray = derivedArray.slice(16); // Second 128 bits for AES-CBC

	// Create encoder for text encoding
	const encoder = new TextEncoder();

	// Generate a random IV (128 bits) as per RFC7518 Section 5.2.2.2
	const iv = crypto.getRandomValues(new Uint8Array(16));

	// Encode the header - serialize to JSON first
	const encodedHeader = base64Url.encode(JSON.stringify(jweHeader));

	// Encrypt the payload using AES-CBC-128
	const payloadBuffer = encoder.encode(JSON.stringify(payload));
	const encryptedBuffer = await AES_CBC_128.encrypt({
		key: encKeyArray,
		iv,
		message: payloadBuffer,
	});
	const encryptedText = base64Url.encode(new Uint8Array(encryptedBuffer));

	// Encode the initialization vector (IV)
	const encodedIv = base64Url.encode(iv);

	// Prepare Additional Authenticated Data (AAD) as per RFC7518 Section 5.2.2.1
	// AAD is the ASCII bytes of the encoded header
	const aadBuffer = encoder.encode(encodedHeader);

	// Create AL (Associated Data Length) as per RFC7518
	// AL is a 64-bit big-endian representation of the bit length of AAD
	const alBuffer = new Uint8Array(8);
	const aadLength = aadBuffer.length * 8; // Length in bits
	const dataView = new DataView(alBuffer.buffer);
	dataView.setBigUint64(0, BigInt(aadLength), false);

	// Concatenate for authentication as per RFC7518 Section 5.2.2.1
	const authInput = new Uint8Array(
		aadBuffer.length + iv.length + encryptedBuffer.byteLength + alBuffer.length,
	);
	authInput.set(aadBuffer, 0);
	authInput.set(iv, aadBuffer.length);
	authInput.set(new Uint8Array(encryptedBuffer), aadBuffer.length + iv.length);
	authInput.set(
		alBuffer,
		aadBuffer.length + iv.length + encryptedBuffer.byteLength,
	);

	// Generate the HMAC-SHA-256 tag
	const signedBuffer = await sha256({
		key: macKeyArray,
		message: authInput,
	});

	// Generate the authentication tag (truncate to 128 bits) as per RFC7518
	const tag = new Uint8Array(signedBuffer).slice(0, 16);
	const encodedTag = base64Url.encode(tag);

	// No encrypted key for direct encryption (alg="dir")
	const encodedEncryptedKey = "";

	// Return the complete JWE token in compact serialization format
	return `${encodedHeader}.${encodedEncryptedKey}.${encodedIv}.${encryptedText}.${encodedTag}`;
}

/**
 * Decrypts a base64url encoded JWE token according to RFC7516
 * @param options - Options object containing:
 *   - token: The JWE token to decrypt
 *   - key: The secret key as string, ArrayBuffer, or Uint8Array
 * @returns Promise resolving to the decryption result
 * @throws Error if decryption fails or token is invalid
 */
export async function decryptJWE(options: {
	token: string;
	key: string | ArrayBuffer | Uint8Array;
}): Promise<DecryptResult> {
	const { token, key } = options;

	// Parse the JWE token (compact serialization format)
	const parts = token.split(".");
	if (parts.length !== 5) {
		throw new JWTError("Invalid JWE token format");
	}

	const [
		encodedHeader,
		encodedEncryptedKey,
		encodedIv,
		encryptedText,
		encodedTag,
	] = parts;

	// Decode the header
	const header = base64Url.decodeAsJSON<JWEHeader>(encodedHeader);

	// Verify algorithm and encryption method
	if (header.alg !== JWE_ALG) {
		throw new JWTError(`Unsupported algorithm: ${header.alg}`);
	}
	if (header.enc !== JWE_ENC) {
		throw new JWTError(`Unsupported encryption method: ${header.enc}`);
	}

	// For "dir" algorithm, the encrypted key should be empty
	if (encodedEncryptedKey !== "") {
		throw new JWTError("Invalid encrypted key for direct encryption");
	}

	// Convert key to BufferSource and derive key
	const keyBuffer = keyToBuffer(key);
	const derivedKey = await deriveKey({
		keyMaterial: keyBuffer,
		info: "JWE-Encryption",
	});

	// Split the key as per RFC7518 Section 5.2.2.1
	const derivedArray = new Uint8Array(derivedKey);
	const macKeyArray = derivedArray.slice(0, 16); // First 128 bits for HMAC
	const encKeyArray = derivedArray.slice(16); // Second 128 bits for AES-CBC

	// Decode IV, tag, and ciphertext
	const iv = base64Url.decode(encodedIv);
	const tag = base64Url.decode(encodedTag);
	const encryptedData = base64Url.decode(encryptedText);

	// Verify IV length (must be 16 bytes for AES-CBC)
	if (iv.length !== 16) {
		throw new JWTError("Invalid IV length");
	}

	// Verify tag length (must be 16 bytes for A128CBC-HS256)
	if (tag.length !== 16) {
		throw new JWTError("Invalid authentication tag length");
	}

	// Verify the authentication tag as per RFC7518 Section 5.2.2.1
	const encoder = new TextEncoder();
	const aadBuffer = encoder.encode(encodedHeader);
	const alBuffer = new Uint8Array(8);
	const aadLength = aadBuffer.length * 8;
	const dataView = new DataView(alBuffer.buffer);
	dataView.setBigUint64(0, BigInt(aadLength), false);

	const authInput = new Uint8Array(
		aadBuffer.length + iv.length + encryptedData.length + alBuffer.length,
	);
	authInput.set(aadBuffer, 0);
	authInput.set(iv, aadBuffer.length);
	authInput.set(encryptedData, aadBuffer.length + iv.length);
	authInput.set(alBuffer, aadBuffer.length + iv.length + encryptedData.length);

	const signedBuffer = await sha256({
		key: macKeyArray,
		message: authInput,
	});
	const calculatedTag = new Uint8Array(signedBuffer).slice(0, 16);

	// Constant-time tag comparison to prevent timing attacks
	if (!constantTimeEqual(tag, calculatedTag)) {
		throw new JWTError("Invalid authentication tag");
	}

	// Decrypt the payload using AES-CBC-128
	try {
		const decryptedBuffer = await AES_CBC_128.decrypt({
			key: encKeyArray,
			iv,
			message: encryptedData,
		});

		// Decode the payload
		const decoder = new TextDecoder();
		const decryptedText = decoder.decode(decryptedBuffer);
		try {
			const payload = JSON.parse(decryptedText) as StandardClaims;
			return { header, payload };
		} catch (error) {
			throw new JWTError("Invalid JSON payload");
		}
	} catch (error) {
		throw new JWTError(`Decryption failed: ${(error as Error).message}`);
	}
}

/**
 * Derives a 256-bit key using HKDF
 * @param options - Options object containing:
 *   - keyMaterial: The input key material as BufferSource
 *   - info: The context-specific info
 * @returns 32-byte (256-bit) derived key as ArrayBuffer
 */
async function deriveKey(options: {
	keyMaterial: BufferSource;
	info: string;
}): Promise<ArrayBuffer> {
	const { keyMaterial, info } = options;
	// keyMaterial is already a BufferSource (ArrayBuffer or Uint8Array) from keyToBuffer
	const key = await crypto.subtle.importKey(
		"raw",
		keyMaterial, // Use directly, no need to normalize further
		"HKDF",
		false,
		["deriveBits"],
	);
	const derivedBits = await crypto.subtle.deriveBits(
		{
			name: "HKDF",
			hash: "SHA-256",
			salt: new Uint8Array(16), // Zero-filled salt for determinism
			info: new TextEncoder().encode(info),
		},
		key,
		256, // 256 bits
	);
	return derivedBits;
}
