import { base64Url } from "@/utils/encoding";
import { CBOR } from "./cbor";
import type {
	CBORValue,
	COSEEncrypt,
	COSEEncrypt0,
	COSEKey,
	COSEMac,
	COSEMac0,
	COSESign,
	COSESign1,
	HeaderMap,
} from "./types";

export enum COSETag {
	COSE_Encrypt = 96,
	COSE_Encrypt0 = 16,
	COSE_Mac = 97,
	COSE_Mac0 = 17,
	COSE_Sign = 98,
	COSE_Sign1 = 18,
}

export enum COSEHeader {
	alg = 1,
	crit = 2,
	ctyp = 3,
	kid = 4,
	iv = 5,
	partial_iv = 6,
	counter_signature = 7,
	salt = 8,
	counter_signature0 = 9,
	x5chain = 33,
	x5t = 34,
}

export enum COSEAlgorithm {
	AES_CCM_16_128_128 = 30,
	AES_CCM_16_128_256 = 31,
	AES_CCM_16_64_128 = 10,
	AES_CCM_16_64_256 = 12,
	AES_CCM_64_128_128 = 32,
	AES_CCM_64_128_256 = 33,
	AES_CCM_64_64_128 = 13,
	AES_CCM_64_64_256 = 14,
	AES_GCM_128 = 1,
	AES_GCM_192 = 2,
	AES_GCM_256 = 3,
	ChaCha20_Poly1305 = 24,
	direct = -6,
	EdDSA = -8,
	ES256 = -7,
	ES384 = -35,
	ES512 = -36,
	HMAC_256_256 = 5,
	HMAC_256_64 = 4,
	HMAC_384_384 = 6,
	HMAC_512_512 = 7,
	PS256 = -37,
	PS384 = -38,
	PS512 = -39,
	RS256 = -257,
	RS384 = -258,
	RS512 = -259,
}

/**
 * RFC 8152: CBOR Object Signing and Encryption (COSE)
 */
export const COSE = {
	importPublicKey,
	encodeSign1,
	decodeSign1,
	encodeSign,
	decodeSign,
	encodeMac0,
	decodeMac0,
	encodeMac,
	decodeMac,
	encodeEncrypt0,
	decodeEncrypt0,
	encodeEncrypt,
	decodeEncrypt,
	encodeKey,
	decodeKey,
} as const;

export async function importPublicKey(options: {
	alg: COSEAlgorithm;
	coseKey: Map<number, number | ArrayBuffer>;
}): Promise<CryptoKey> {
	const { alg, coseKey } = options;
	const kty = coseKey.get(1);
	if (typeof kty !== "number") {
		throw new Error("Invalid or missing key type in COSE key");
	}

	if (kty === 2) {
		// EC2
		const crv = coseKey.get(-1);
		if (typeof crv !== "number" || crv !== 1) {
			throw new Error("Invalid curve for ES256; expected P-256");
		}
		const x = coseKey.get(-2);
		const y = coseKey.get(-3);
		if (!(x instanceof ArrayBuffer) || !(y instanceof ArrayBuffer)) {
			throw new Error("Invalid EC key parameters");
		}
		const jwk: JsonWebKey = {
			kty: "EC",
			crv: "P-256",
			x: base64Url.encode(x),
			y: base64Url.encode(y),
		};
		return await crypto.subtle.importKey(
			"jwk",
			jwk,
			{ name: "ECDSA", namedCurve: "P-256" },
			false,
			["verify"],
		);
	}
	if (kty === 3) {
		// RSA
		const n = coseKey.get(-1);
		const e = coseKey.get(-2);
		if (!(n instanceof ArrayBuffer) || !(e instanceof ArrayBuffer)) {
			throw new Error("Invalid RSA key parameters");
		}
		const jwk: JsonWebKey = {
			kty: "RSA",
			n: base64Url.encode(n),
			e: base64Url.encode(e),
		};
		return await crypto.subtle.importKey(
			"jwk",
			jwk,
			{ name: "RSASSA-PKCS1-v1_5" },
			false,
			["verify"],
		);
	}
	throw new Error(`Unsupported key type: ${kty}`);
}

function validateProtectedHeader(header: HeaderMap): void {
	if (!(COSEHeader.alg in header)) {
		throw new Error("Protected header must contain 'alg' parameter");
	}
	const alg = header[COSEHeader.alg];
	if (typeof alg !== "number" || !(alg in COSEAlgorithm)) {
		throw new Error("Invalid or unsupported algorithm in protected header");
	}
}

function ensureArrayBuffer(value: CBORValue): ArrayBuffer {
	if (!(value instanceof ArrayBuffer)) {
		throw new Error("Expected ArrayBuffer");
	}
	return value;
}

/**
 * Validates a COSE_Key structure (RFC 8152 §7).
 */
function validateCOSEKey(key: Map<number, number | ArrayBuffer>): void {
	const kty = key.get(1);
	const alg = key.get(3);
	if (typeof kty !== "number") {
		throw new Error("COSE_Key must contain 'kty' (1) as a number");
	}
	if (typeof alg !== "number" || !(alg in COSEAlgorithm)) {
		throw new Error("COSE_Key must contain valid 'alg' (3)");
	}
	if (kty === 2) {
		// EC2
		if (!key.has(-1) || !key.has(-2) || !key.has(-3)) {
			throw new Error("EC2 key missing required parameters (crv, x, y)");
		}
	} else if (kty === 3) {
		// RSA
		if (!key.has(-1) || !key.has(-2)) {
			throw new Error("RSA key missing required parameters (n, e)");
		}
	}
}

/**
 * Encodes a COSE_Key structure (untagged).
 * @param key - The COSE_Key to encode.
 * @returns The CBOR-encoded key as an ArrayBuffer.
 */
function encodeKey(key: COSEKey): ArrayBuffer {
	const keyMap = new Map<number, number | ArrayBuffer>(
		Object.entries(key).map(([k, v]) => [Number(k), v]),
	);
	validateCOSEKey(keyMap);
	return CBOR.encode(Object.fromEntries(keyMap));
}

/**
 * Decodes a COSE_Key structure (untagged).
 * @param data - The CBOR-encoded key data.
 * @returns The decoded COSE_Key as a Map.
 */
function decodeKey(data: ArrayBuffer): Map<number, number | ArrayBuffer> {
	const [keyMap, _] = CBOR.decodeMapToMap<number, number | ArrayBuffer>(
		data,
		0,
		(key): key is number => typeof key === "number",
		(value): value is number | ArrayBuffer =>
			typeof value === "number" || value instanceof ArrayBuffer,
	);
	validateCOSEKey(keyMap);
	return keyMap;
}

function encodeSign1(sign1: COSESign1): ArrayBuffer {
	validateProtectedHeader(sign1.protected);
	const protectedHeader = CBOR.encode(sign1.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer,
		sign1.unprotected,
		sign1.payload,
		sign1.signature,
	];
	return CBOR.encode({ tag: COSETag.COSE_Sign1, value });
}

function decodeSign1(data: ArrayBuffer): COSESign1 {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Sign1) {
		throw new Error(
			`Expected COSE_Sign1 tag ${COSETag.COSE_Sign1}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		ArrayBuffer,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader,
		unprotected: decoded[1],
		payload: decoded[2],
		signature: ensureArrayBuffer(decoded[3]),
	};
}

function encodeSign(sign: COSESign): ArrayBuffer {
	validateProtectedHeader(sign.protected);
	const protectedHeader = CBOR.encode(sign.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer,
		sign.unprotected,
		sign.payload,
		sign.signatures.map((sig) => {
			validateProtectedHeader(sig.protected);
			return [
				new Uint8Array(CBOR.encode(sig.protected)).buffer,
				sig.unprotected,
				sig.signature,
			];
		}),
	];
	return CBOR.encode({ tag: COSETag.COSE_Sign, value });
}

function decodeSign(data: ArrayBuffer): COSESign {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Sign) {
		throw new Error(
			`Expected COSE_Sign tag ${COSETag.COSE_Sign}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader,
		unprotected: decoded[1],
		payload: decoded[2],
		signatures: decoded[3].map((sig) => {
			const sigProtected = CBOR.decode(sig[0]) as HeaderMap;
			validateProtectedHeader(sigProtected);
			return {
				protected: sigProtected,
				unprotected: sig[1],
				signature: ensureArrayBuffer(sig[2]),
			};
		}),
	};
}

function encodeMac0(mac0: COSEMac0): ArrayBuffer {
	validateProtectedHeader(mac0.protected);
	const protectedHeader = CBOR.encode(mac0.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer,
		mac0.unprotected,
		mac0.payload,
		mac0.tag,
	];
	return CBOR.encode({ tag: COSETag.COSE_Mac0, value });
}

function decodeMac0(data: ArrayBuffer): COSEMac0 {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Mac0) {
		throw new Error(
			`Expected COSE_Mac0 tag ${COSETag.COSE_Mac0}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		ArrayBuffer,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader,
		unprotected: decoded[1],
		payload: decoded[2],
		tag: ensureArrayBuffer(decoded[3]),
	};
}

function encodeMac(mac: COSEMac): ArrayBuffer {
	validateProtectedHeader(mac.protected);
	const protectedHeader = CBOR.encode(mac.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer,
		mac.unprotected,
		mac.payload,
		mac.recipients.map((rec) => {
			validateProtectedHeader(rec.protected);
			return [
				new Uint8Array(CBOR.encode(rec.protected)).buffer,
				rec.unprotected,
				rec.tag,
			];
		}),
	];
	return CBOR.encode({ tag: COSETag.COSE_Mac, value });
}

function decodeMac(data: ArrayBuffer): COSEMac {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Mac) {
		throw new Error(
			`Expected COSE_Mac tag ${COSETag.COSE_Mac}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer | null,
		Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader,
		unprotected: decoded[1],
		payload: decoded[2],
		recipients: decoded[3].map((rec) => {
			const recProtected = CBOR.decode(rec[0]) as HeaderMap;
			validateProtectedHeader(recProtected);
			return {
				protected: recProtected,
				unprotected: rec[1],
				tag: ensureArrayBuffer(rec[2]),
			};
		}),
	};
}

function encodeEncrypt0(encrypt0: COSEEncrypt0): ArrayBuffer {
	validateProtectedHeader(encrypt0.protected);
	const protectedHeader = CBOR.encode(encrypt0.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer,
		encrypt0.unprotected,
		encrypt0.ciphertext,
	];
	return CBOR.encode({ tag: COSETag.COSE_Encrypt0, value });
}

function decodeEncrypt0(data: ArrayBuffer): COSEEncrypt0 {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Encrypt0) {
		throw new Error(
			`Expected COSE_Encrypt0 tag ${COSETag.COSE_Encrypt0}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [ArrayBuffer, HeaderMap, ArrayBuffer];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader,
		unprotected: decoded[1],
		ciphertext: ensureArrayBuffer(decoded[2]),
	};
}

function encodeEncrypt(encrypt: COSEEncrypt): ArrayBuffer {
	validateProtectedHeader(encrypt.protected);
	const protectedHeader = CBOR.encode(encrypt.protected);
	const value = [
		new Uint8Array(protectedHeader).buffer,
		encrypt.unprotected,
		encrypt.ciphertext,
		encrypt.recipients.map((rec) => {
			validateProtectedHeader(rec.protected);
			return [
				new Uint8Array(CBOR.encode(rec.protected)).buffer,
				rec.unprotected,
				rec.encrypted_key,
			];
		}),
	];
	return CBOR.encode({ tag: COSETag.COSE_Encrypt, value });
}

function decodeEncrypt(data: ArrayBuffer): COSEEncrypt {
	const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
	if (tagged.tag !== COSETag.COSE_Encrypt) {
		throw new Error(
			`Expected COSE_Encrypt tag ${COSETag.COSE_Encrypt}, got ${tagged.tag}`,
		);
	}
	const decoded = tagged.value as [
		ArrayBuffer,
		HeaderMap,
		ArrayBuffer,
		Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
	];
	const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
	validateProtectedHeader(protectedHeader);
	return {
		protected: protectedHeader,
		unprotected: decoded[1],
		ciphertext: ensureArrayBuffer(decoded[2]),
		recipients: decoded[3].map((rec) => {
			const recProtected = CBOR.decode(rec[0]) as HeaderMap;
			validateProtectedHeader(recProtected);
			return {
				protected: recProtected,
				unprotected: rec[1],
				encrypted_key: ensureArrayBuffer(rec[2]),
			};
		}),
	};
}
