import { base64Url } from "@/utils/encoding";
import { Encrypt } from "./cose-encrypt";
import { Encrypt0 } from "./cose-encrypt0";
import { Key } from "./cose-key";
import { Mac } from "./cose-mac";
import { Mac0 } from "./cose-mac0";
import { Sign } from "./cose-sign";
import { Sign1 } from "./cose-sign1";

/**
 * RFC 8152: CBOR Object Signing and Encryption (COSE)
 */
export const COSE = {
	Key,
	Encrypt,
	Encrypt0,
	Mac,
	Mac0,
	Sign,
	Sign1,
} as const;

export async function importPublicKey(
	coseKey: Map<number, number | ArrayBuffer>,
): Promise<CryptoKey> {
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
