import { CBOR } from "../cbor";
import type { CBORValue, HeaderMap } from "../types";
import { ensureArrayBuffer, validateProtectedHeader } from "./utils";

/** COSE MACed Data Object */
export interface COSE_Mac {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	recipients: Array<{
		protected: HeaderMap;
		unprotected: HeaderMap;
		tag: ArrayBuffer;
	}>;
}

export const COSE_MAC_TAG = 97;

export const Mac = {
	tag: COSE_MAC_TAG,
	encode(mac: COSE_Mac): ArrayBuffer {
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
		return CBOR.encode({ tag: COSE_MAC_TAG, value });
	},

	decode(data: ArrayBuffer): COSE_Mac {
		const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
		if (tagged.tag !== COSE_MAC_TAG) {
			throw new Error(
				`Expected COSE_Mac tag ${COSE_MAC_TAG}, got ${tagged.tag}`,
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
	},
};
