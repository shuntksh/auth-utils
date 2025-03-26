import { CBOR } from "../cbor";
import type { CBORValue, HeaderMap } from "../types";
import { ensureArrayBuffer, validateProtectedHeader } from "./utils";

export interface COSEMac0 {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	tag: ArrayBuffer;
}

export const COSE_MAC0_TAG = 17;

export const Mac0 = {
	tag: COSE_MAC0_TAG,

	encode(mac0: COSEMac0): ArrayBuffer {
		validateProtectedHeader(mac0.protected);
		const protectedHeader = CBOR.encode(mac0.protected);
		const value = [
			new Uint8Array(protectedHeader).buffer,
			mac0.unprotected,
			mac0.payload,
			mac0.tag,
		];
		return CBOR.encode({ tag: COSE_MAC0_TAG, value });
	},

	decode(data: ArrayBuffer): COSEMac0 {
		const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
		if (tagged.tag !== COSE_MAC0_TAG) {
			throw new Error(
				`Expected COSE_Mac0 tag ${COSE_MAC0_TAG}, got ${tagged.tag}`,
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
	},
};
