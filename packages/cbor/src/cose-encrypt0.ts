import { CBOR } from "./cbor";
import { ensureArrayBuffer, validateProtectedHeader } from "./cose-utils";
import type { CBORValue, HeaderMap } from "./types";

export interface COSEEncrypt0 {
	protected: HeaderMap;
	unprotected: HeaderMap;
	ciphertext: ArrayBuffer;
}

export const COSE_ENCRYPT0_TAG = 16;

export const Encrypt0 = {
	tag: COSE_ENCRYPT0_TAG,

	encode(encrypt0: COSEEncrypt0): ArrayBuffer {
		validateProtectedHeader(encrypt0.protected);
		const protectedHeader = CBOR.encode(encrypt0.protected);
		const value = [
			new Uint8Array(protectedHeader).buffer,
			encrypt0.unprotected,
			encrypt0.ciphertext,
		];
		return CBOR.encode({ tag: COSE_ENCRYPT0_TAG, value });
	},

	decode(data: ArrayBuffer): COSEEncrypt0 {
		const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
		if (tagged.tag !== COSE_ENCRYPT0_TAG) {
			throw new Error(
				`Expected COSE_Encrypt0 tag ${COSE_ENCRYPT0_TAG}, got ${tagged.tag}`,
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
	},
};
