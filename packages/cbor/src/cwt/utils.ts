import { base64Url } from "@/shared/src/encoding";
import { CBOR } from "../cbor";
import type { CBORValue, COSE_Key, CWTClaims } from "../types";
import { COSEAlgorithm, CWTClaimKeys } from "../types";

const claimKeys = Object.values(CWTClaimKeys) as number[];
const isValidClaimKey = (key: number) => claimKeys.includes(key);

// Encode claims to CBOR, mapping standard claims to numeric keys
export function encodeClaims(claims: CWTClaims): ArrayBuffer {
	const encodedMap = new Map<number | string, CBORValue>();

	if (claims.iss !== undefined) {
		if (typeof claims.iss !== "string")
			throw new TypeError("iss must be a string");
		encodedMap.set(CWTClaimKeys.iss, claims.iss);
	}
	if (claims.sub !== undefined) {
		if (typeof claims.sub !== "string")
			throw new TypeError("sub must be a string");
		encodedMap.set(CWTClaimKeys.sub, claims.sub);
	}
	if (claims.aud !== undefined) {
		if (typeof claims.aud === "string") {
			encodedMap.set(CWTClaimKeys.aud, claims.aud);
		} else if (
			Array.isArray(claims.aud) &&
			claims.aud.every((s) => typeof s === "string")
		) {
			encodedMap.set(CWTClaimKeys.aud, claims.aud);
		} else {
			throw new TypeError("aud must be a string or an array of strings");
		}
	}
	if (claims.exp !== undefined) {
		if (typeof claims.exp !== "number")
			throw new TypeError("exp must be a number");
		encodedMap.set(CWTClaimKeys.exp, claims.exp);
	}
	if (claims.nbf !== undefined) {
		if (typeof claims.nbf !== "number")
			throw new TypeError("nbf must be a number");
		encodedMap.set(CWTClaimKeys.nbf, claims.nbf);
	}
	if (claims.iat !== undefined) {
		if (typeof claims.iat !== "number")
			throw new TypeError("iat must be a number");
		encodedMap.set(CWTClaimKeys.iat, claims.iat);
	}
	if (claims.cti !== undefined) {
		if (!(claims.cti instanceof ArrayBuffer))
			throw new TypeError("cti must be an ArrayBuffer");
		encodedMap.set(CWTClaimKeys.cti, claims.cti);
	}

	for (const [key, value] of Object.entries(claims)) {
		if (!isValidClaimKey(Number(key)) && value !== undefined) {
			encodedMap.set(key, value);
		}
	}

	return CBOR.encode(Object.fromEntries(encodedMap));
}

// Decode CBOR buffer to CWT claims
export function decodeClaims(buffer: ArrayBuffer): CWTClaims {
	const decodedMap = CBOR.decode(buffer) as unknown as Map<
		number | string,
		CBORValue
	>;
	const claims: CWTClaims = {};

	for (const [key, value] of decodedMap) {
		if (typeof key === "number") {
			switch (key) {
				case CWTClaimKeys.iss:
					if (typeof value !== "string")
						throw new TypeError("iss must be a string");
					claims.iss = value;
					break;
				case CWTClaimKeys.sub:
					if (typeof value !== "string")
						throw new TypeError("sub must be a string");
					claims.sub = value;
					break;
				case CWTClaimKeys.aud:
					if (typeof value === "string") {
						claims.aud = value;
					} else if (
						Array.isArray(value) &&
						value.every((s) => typeof s === "string")
					) {
						claims.aud = value as string[];
					} else {
						throw new TypeError("aud must be a string or an array of strings");
					}
					break;
				case CWTClaimKeys.exp:
					if (typeof value !== "number")
						throw new TypeError("exp must be a number");
					claims.exp = value;
					break;
				case CWTClaimKeys.nbf:
					if (typeof value !== "number")
						throw new TypeError("nbf must be a number");
					claims.nbf = value;
					break;
				case CWTClaimKeys.iat:
					if (typeof value !== "number")
						throw new TypeError("iat must be a number");
					claims.iat = value;
					break;
				case CWTClaimKeys.cti:
					if (!(value instanceof ArrayBuffer))
						throw new TypeError("cti must be an ArrayBuffer");
					claims.cti = value;
					break;
				default:
					claims[key.toString()] = value; // Non-standard numeric keys as strings
			}
		} else {
			claims[key] = value; // Custom string keys
		}
	}

	return claims;
}

// Import COSEKey as CryptoKey (extended for symmetric encryption)
export async function importCOSEKey(
	key: COSE_Key,
	usage: "sign" | "verify" | "encrypt" | "decrypt",
): Promise<CryptoKey> {
	// Symmetric key (e.g., for HMAC or AES-CCM)
	if (key[1] === 4) {
		// kty: Symmetric
		const k = key[-1] as ArrayBuffer;
		if (!k) throw new Error("Symmetric key parameter 'k' is missing");
		const alg = key[3] as COSEAlgorithm;

		if (
			alg === COSEAlgorithm.HMAC_256_256 ||
			alg === COSEAlgorithm.HMAC_256_64
		) {
			return crypto.subtle.importKey(
				"raw",
				k,
				{ name: "HMAC", hash: "SHA-256" },
				false,
				[usage === "sign" || usage === "encrypt" ? "sign" : "verify"],
			);
		}

		if (alg === COSEAlgorithm.AES_CCM_16_64_128) {
			return crypto.subtle.importKey("raw", k, { name: "AES-CCM" }, false, [
				usage === "encrypt" ? "encrypt" : "decrypt",
			]);
		}

		throw new Error("Unsupported symmetric algorithm");
	}

	// Asymmetric key (EC2, e.g., for ECDSA)
	if (key[1] === 2) {
		// kty: EC2
		const crv = key[-1];
		if (crv !== 1) throw new Error("Only P-256 curve is supported"); // P-256
		const x = key[-2] as ArrayBuffer;
		const y = key[-3] as ArrayBuffer;

		const jwk: JsonWebKey = {
			kty: "EC",
			crv: "P-256",
			x: base64Url.encode(x),
			y: base64Url.encode(y),
		};

		if (usage === "sign") {
			const d = key[-4] as ArrayBuffer;
			if (!d) throw new Error("Private key parameter 'd' is missing");
			jwk.d = base64Url.encode(d);
			return crypto.subtle.importKey(
				"jwk",
				jwk,
				{ name: "ECDSA", namedCurve: "P-256" },
				false,
				["sign"],
			);
		}

		if (usage === "verify") {
			return crypto.subtle.importKey(
				"jwk",
				jwk,
				{ name: "ECDSA", namedCurve: "P-256" },
				false,
				["verify"],
			);
		}

		throw new Error("EC2 keys are not used for encryption in this context");
	}

	throw new Error("Unsupported key type");
}
