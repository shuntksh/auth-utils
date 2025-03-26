import { CBOR } from "./cbor";
import { ensureArrayBuffer, validateProtectedHeader } from "./cose-utils";
import type { CBORValue, HeaderMap } from "./types";

export interface COSESign1 {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	signature: ArrayBuffer;
}

export const COSE_SIGN1_TAG = 16;

export const Sign1 = {
	tag: COSE_SIGN1_TAG,

	encode(sign1: COSESign1): ArrayBuffer {
		validateProtectedHeader(sign1.protected);
		const protectedHeader = CBOR.encode(sign1.protected);
		const value = [
			new Uint8Array(protectedHeader).buffer,
			sign1.unprotected,
			sign1.payload,
			sign1.signature,
		];
		return CBOR.encode({ tag: COSE_SIGN1_TAG, value });
	},

	decode(data: ArrayBuffer): COSESign1 {
		const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
		if (tagged.tag !== COSE_SIGN1_TAG) {
			throw new Error(
				`Expected COSE_Sign1 tag ${COSE_SIGN1_TAG}, got ${tagged.tag}`,
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
	},
} as const;
