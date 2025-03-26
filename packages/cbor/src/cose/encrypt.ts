import { CBOR } from "../cbor";
import type { CBORValue, HeaderMap } from "../types";
import { ensureArrayBuffer, validateProtectedHeader } from "./utils";

export interface COSEEncrypt {
	protected: HeaderMap;
	unprotected: HeaderMap;
	ciphertext: ArrayBuffer;
	recipients: Array<{
		protected: HeaderMap;
		unprotected: HeaderMap;
		encrypted_key: ArrayBuffer;
	}>;
}

export const COSE_ENCRYPT_TAG = 96;

export const Encrypt = {
	tag: COSE_ENCRYPT_TAG,

	encode(encrypt: COSEEncrypt): ArrayBuffer {
		validateProtectedHeader(encrypt.protected);
		const protectedHeader = CBOR.encode(encrypt.protected);
		const value = [
			new Uint8Array(protectedHeader).buffer,
			encrypt.unprotected,
			encrypt.ciphertext,
			encrypt.recipients.map((rec) => {
				validateProtectedHeader(rec.protected);
				return [
					new Uint8Array(CBOR.encode(rec.protected)).buffer,
					rec.unprotected,
					rec.encrypted_key,
				];
			}),
		];
		return CBOR.encode({ tag: COSE_ENCRYPT_TAG, value });
	},

	decode(data: ArrayBuffer): COSEEncrypt {
		const tagged = CBOR.decode(data) as { tag: number; value: CBORValue };
		if (tagged.tag !== COSE_ENCRYPT_TAG) {
			throw new Error(
				`Expected COSE_Encrypt tag ${COSE_ENCRYPT_TAG}, got ${tagged.tag}`,
			);
		}
		const decoded = tagged.value as [
			ArrayBuffer,
			HeaderMap,
			ArrayBuffer,
			Array<[ArrayBuffer, HeaderMap, ArrayBuffer]>,
		];
		const protectedHeader = CBOR.decode(decoded[0]) as HeaderMap;
		validateProtectedHeader(protectedHeader);
		return {
			protected: protectedHeader,
			unprotected: decoded[1],
			ciphertext: ensureArrayBuffer(decoded[2]),
			recipients: decoded[3].map((rec) => {
				const recProtected = CBOR.decode(rec[0]) as HeaderMap;
				validateProtectedHeader(recProtected);
				return {
					protected: recProtected,
					unprotected: rec[1],
					encrypted_key: ensureArrayBuffer(rec[2]),
				};
			}),
		};
	},
};
