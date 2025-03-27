import { COSE } from "../cose";
import type { COSE_Encrypt0, COSE_Key, CWTClaims, HeaderMap } from "../types";
import { COSEHeader } from "../types";
import { decodeClaims, encodeClaims, importCOSEKey } from "./utils";

export const EncryptedCWT = {
	encrypt,
	decrypt,
};

// Create an encrypted CWT (COSE_Encrypt0) - RFC 8392, Section 7.1
export async function encrypt(
	claims: CWTClaims,
	key: COSE_Key,
	protectedHeader: HeaderMap = {},
	unprotectedHeader: HeaderMap = {},
	useCWTTag = false,
): Promise<ArrayBuffer> {
	const plaintext = encodeClaims(claims);

	if (!protectedHeader[COSEHeader.alg]) {
		protectedHeader[COSEHeader.alg] = key[3]; // Use alg from key (e.g., AES-CCM-16-64-128)
	}

	// Generate a random IV (nonce) as per RFC 8152, Section 5
	const ivLength = 13; // 13 bytes for AES-CCM as per Appendix A.5
	const iv = crypto.getRandomValues(new Uint8Array(ivLength));
	unprotectedHeader[COSEHeader.iv] = iv.buffer;

	// Encrypt the plaintext
	const cryptoKey = await importCOSEKey(key, "encrypt");
	const ciphertext = await crypto.subtle.encrypt(
		{
			name: "AES-CCM",
			iv,
			additionalData: new ArrayBuffer(0), // External AAD per RFC 8152
			tagLength: 64, // 64-bit tag as per Appendix A.5
		},
		cryptoKey,
		plaintext,
	);

	const encrypt0: COSE_Encrypt0 = {
		protected: protectedHeader,
		unprotected: unprotectedHeader,
		ciphertext,
	};

	let cwt = COSE.Encrypt0.encode(encrypt0);
	if (useCWTTag) {
		const tag = new Uint8Array([0x61]); // CWT CBOR tag
		const cwtBuffer = new Uint8Array(tag.byteLength + cwt.byteLength);
		cwtBuffer.set(tag, 0);
		cwtBuffer.set(new Uint8Array(cwt), tag.byteLength);
		cwt = cwtBuffer.buffer;
	}

	return cwt;
}

// Validate an encrypted CWT (COSE_Encrypt0) - RFC 8392, Section 7.2
export async function decrypt(
	cwt: ArrayBuffer,
	key: COSE_Key,
): Promise<CWTClaims> {
	const dataView = new DataView(cwt);
	let offset = 0;

	if (dataView.getUint8(0) === 0x61) {
		offset = 1;
	}

	const encrypt0 = COSE.Encrypt0.decode(cwt.slice(offset));
	const { protected: protectedHeader, unprotected, ciphertext } = encrypt0;

	const iv = unprotected[COSEHeader.iv];
	if (!(iv instanceof ArrayBuffer))
		throw new Error("IV must be an ArrayBuffer");

	const cryptoKey = await importCOSEKey(key, "decrypt");
	const plaintext = await crypto.subtle.decrypt(
		{
			name: "AES-CCM",
			iv,
			additionalData: new ArrayBuffer(0),
			tagLength: 64,
		},
		cryptoKey,
		ciphertext,
	);

	return decodeClaims(plaintext);
}
