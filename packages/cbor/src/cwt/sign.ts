import { CBOR } from "../cbor";
import { COSE } from "../cose";
import type { COSE_Key, COSE_Sign1, CWTClaims, HeaderMap } from "../types";
import { COSEHeader } from "../types";
import { decodeClaims, encodeClaims, importCOSEKey } from "./utils";

export const SignedCWT = {
	create,
	validate,
} as const;

// Create a signed CWT (COSE_Sign1)
export async function create(
	claims: CWTClaims,
	key: COSE_Key,
	protectedHeader: HeaderMap = {},
	unprotectedHeader: HeaderMap = {},
	useCWTTag = false,
): Promise<ArrayBuffer> {
	const payload = encodeClaims(claims);

	if (!protectedHeader[COSEHeader.alg]) {
		protectedHeader[COSEHeader.alg] = key[3]; // Use alg from key
	}

	const sigStructure = [
		"Signature1",
		CBOR.encode(protectedHeader),
		new ArrayBuffer(0), // External AAD
		payload,
	];
	const toBeSigned = CBOR.encode(sigStructure);

	const cryptoKey = await importCOSEKey(key, "sign");
	const signature = await crypto.subtle.sign(
		{ name: "ECDSA", hash: "SHA-256" },
		cryptoKey,
		toBeSigned,
	);

	const sign1: COSE_Sign1 = {
		protected: protectedHeader,
		unprotected: unprotectedHeader,
		payload,
		signature,
	};

	let cwt = COSE.Sign1.encode(sign1);
	if (useCWTTag) {
		const tag = new Uint8Array([0x61]); // CWT CBOR tag
		const cwtBuffer = new Uint8Array(tag.byteLength + cwt.byteLength);
		cwtBuffer.set(tag, 0);
		cwtBuffer.set(new Uint8Array(cwt), tag.byteLength);
		cwt = cwtBuffer.buffer;
	}

	return cwt;
}

// Validate a signed CWT (COSE_Sign1)
export async function validate(
	cwt: ArrayBuffer,
	key: COSE_Key,
): Promise<CWTClaims> {
	const dataView = new DataView(cwt);
	let offset = 0;

	if (dataView.getUint8(0) === 0x61) {
		offset = 1;
	}

	const sign1 = COSE.Sign1.decode(cwt.slice(offset));
	const { protected: protectedHeader, payload, signature } = sign1;

	const sigStructure = [
		"Signature1",
		CBOR.encode(protectedHeader),
		new ArrayBuffer(0),
		payload,
	];
	const toBeVerified = CBOR.encode(sigStructure);

	const cryptoKey = await importCOSEKey(key, "verify");
	const isValid = await crypto.subtle.verify(
		{ name: "ECDSA", hash: "SHA-256" },
		cryptoKey,
		signature,
		toBeVerified,
	);

	if (!isValid) throw new Error("Invalid signature");

	if (!payload) throw new Error("Missing payload");

	return decodeClaims(payload);
}
