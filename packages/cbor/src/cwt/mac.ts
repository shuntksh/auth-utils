import { CBOR } from "../cbor";
import { COSE } from "../cose";
import type { COSE_Key, COSE_Mac0, CWTClaims, HeaderMap } from "../types";
import { COSEHeader } from "../types";
import { decodeClaims, encodeClaims, importCOSEKey } from "./utils";

export const MACedCWT = {
	create,
	validate,
} as const;

// Create a MACed CWT (COSE_Mac0)
export async function create(
	claims: CWTClaims,
	key: COSE_Key,
	protectedHeader: HeaderMap = {},
	unprotectedHeader: HeaderMap = {},
	useCWTTag = false,
): Promise<ArrayBuffer> {
	const payload = encodeClaims(claims);

	if (!protectedHeader[COSEHeader.alg]) {
		protectedHeader[COSEHeader.alg] = key[3];
	}

	const macStructure = [
		"MAC0",
		CBOR.encode(protectedHeader),
		new ArrayBuffer(0),
		payload,
	];
	const toBeMACed = CBOR.encode(macStructure);

	const cryptoKey = await importCOSEKey(key, "sign");
	const tag = await crypto.subtle.sign("HMAC", cryptoKey, toBeMACed);

	const mac0: COSE_Mac0 = {
		protected: protectedHeader,
		unprotected: unprotectedHeader,
		payload,
		tag,
	};

	let cwt = COSE.Mac0.encode(mac0);
	if (useCWTTag) {
		const tag = new Uint8Array([0x61]);
		const cwtBuffer = new Uint8Array(tag.byteLength + cwt.byteLength);
		cwtBuffer.set(tag, 0);
		cwtBuffer.set(new Uint8Array(cwt), tag.byteLength);
		cwt = cwtBuffer.buffer;
	}

	return cwt;
}

// Validate a MACed CWT (COSE_Mac0)
export async function validate(
	cwt: ArrayBuffer,
	key: COSE_Key,
): Promise<CWTClaims> {
	const dataView = new DataView(cwt);
	let offset = 0;

	if (dataView.getUint8(0) === 0x61) {
		offset = 1;
	}

	const mac0 = COSE.Mac0.decode(cwt.slice(offset));
	const { protected: protectedHeader, payload, tag } = mac0;

	const macStructure = [
		"MAC0",
		CBOR.encode(protectedHeader),
		new ArrayBuffer(0),
		payload,
	];
	const toBeVerified = CBOR.encode(macStructure);

	const cryptoKey = await importCOSEKey(key, "verify");
	const isValid = await crypto.subtle.verify(
		"HMAC",
		cryptoKey,
		tag,
		toBeVerified,
	);

	if (!isValid) throw new Error("Invalid MAC");

	if (!payload) throw new Error("Missing payload");

	return decodeClaims(payload);
}
