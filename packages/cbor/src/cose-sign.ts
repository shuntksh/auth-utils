import { CBOR } from "./cbor";
import { ensureArrayBuffer, validateProtectedHeader } from "./cose-utils";
import type { CBORValue, HeaderMap } from "./types";

export interface COSESign {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	signatures: Array<{
		protected: HeaderMap;
		unprotected: HeaderMap;
		signature: ArrayBuffer;
	}>;
}

export const COSE_SIGN_TAG = 98;

export const Sign = {
	tag: COSE_SIGN_TAG,

	encode(sign: COSESign): ArrayBuffer {
		validateProtectedHeader(sign.protected);
		const protectedHeader = CBOR.encode(sign.protected);
		const value = [
			new Uint8Array(protectedHeader).buffer,
			sign.unprotected,
			sign.payload,
			sign.signatures.map((sig) => {
				validateProtectedHeader(sig.protected);
				return [
					new Uint8Array(CBOR.encode(sig.protected)).buffer,
					sig.unprotected,
					sig.signature,
				];
			}),
		];
		return CBOR.encode({ tag: COSE_SIGN_TAG, value });
	},

	decode(data: ArrayBuffer): COSESign {
		const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
		if (tagged.tag !== COSE_SIGN_TAG) {
			throw new Error(
				`Expected COSE_Sign tag ${COSE_SIGN_TAG}, got ${tagged.tag}`,
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
			signatures: decoded[3].map((sig) => {
				const sigProtected = CBOR.decode(sig[0]) as HeaderMap;
				validateProtectedHeader(sigProtected);
				return {
					protected: sigProtected,
					unprotected: sig[1],
					signature: ensureArrayBuffer(sig[2]),
				};
			}),
		};
	},
};
