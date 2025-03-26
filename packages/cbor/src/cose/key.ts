import { CBOR } from "../cbor";
import { decodeValue } from "../cbor/decode";
import type { CBORValue } from "../types";
import { COSEAlgorithm } from "../types";

// COSE_Key Structure (RFC 8152 §7)
export interface COSEKey {
	1: number; // kty (e.g., 2 = EC2, 3 = RSA)
	3: number; // alg (COSEAlgorithm)
	[-1]?: number | ArrayBuffer; // crv (EC) or n (RSA modulus)
	[-2]?: ArrayBuffer; // x (EC) or e (RSA exponent)
	[-3]?: ArrayBuffer; // y (EC)
}

export const Key = {
	/**
	 * Encodes a COSE_Key structure (untagged).
	 * @param key - The COSE_Key to encode.
	 * @returns The CBOR-encoded key as an ArrayBuffer.
	 */
	encode(key: COSEKey): ArrayBuffer {
		const keyMap = new Map<number, number | ArrayBuffer>(
			Object.entries(key).map(([k, v]) => [Number(k), v]),
		);
		validateCOSEKey(keyMap);
		return CBOR.encode(Object.fromEntries(keyMap));
	},

	/**
	 * Decodes a COSE_Key structure (untagged).
	 * @param data - The CBOR-encoded key data.
	 * @returns The decoded COSE_Key as a Map.
	 */
	decode(data: ArrayBuffer): Map<number, number | ArrayBuffer> {
		const [keyMap, _] = decodeMapToMap<number, number | ArrayBuffer>(
			data,
			0,
			(key): key is number => typeof key === "number",
			(value): value is number | ArrayBuffer =>
				typeof value === "number" || value instanceof ArrayBuffer,
		);
		validateCOSEKey(keyMap);
		return keyMap;
	},
};

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
 * Decodes a CBOR map directly into a JavaScript Map with specified key/value types.
 * Tailored for WebAuthn COSE keys (numeric keys, number/ArrayBuffer values).
 *
 * @param buffer - The buffer to decode.
 * @param startOffset - The offset to start decoding from.
 * @param keyValidator - The validator for the keys.
 * @param valueValidator - The validator for the values.
 * @returns The decoded map.
 */
export function decodeMapToMap<K extends string | number, V extends CBORValue>(
	buffer: ArrayBuffer,
	startOffset = 0,
	keyValidator: (key: string | number) => key is K = (key): key is K => true,
	valueValidator: (value: CBORValue) => value is V = (value): value is V =>
		true,
): [Map<K, V>, number] {
	const [obj, newOffset] = decodeValue(buffer, startOffset);
	if (
		typeof obj !== "object" ||
		obj === null ||
		"tag" in obj ||
		Array.isArray(obj)
	) {
		throw new Error("Expected CBOR map");
	}
	const map = new Map<K, V>();
	for (const [key, value] of Object.entries(obj)) {
		const parsedKey =
			Number(key) === Number.parseInt(key, 10) ? Number(key) : key;
		if (!keyValidator(parsedKey)) {
			throw new Error(`Invalid map key: ${parsedKey}`);
		}
		if (!valueValidator(value)) {
			throw new Error(`Invalid map value for key ${parsedKey}: ${value}`);
		}
		map.set(parsedKey as K, value as V);
	}
	return [map, newOffset - startOffset];
}
