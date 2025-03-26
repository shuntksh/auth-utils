export const CBOR_MAJOR_TYPES = {
	UNSIGNED_INTEGER: 0, // 0..2^64-1 inclusive
	NEGATIVE_INTEGER: 1,
	BYTE_STRING: 2,
	TEXT_STRING: 3,
	ARRAY: 4,
	MAP: 5,
	TAG: 6,
	FLOAT: 7,
} as const;

export const CBOR_FLOAT_ADDITIONAL_INFO = {
	FALSE: 20,
	TRUE: 21,
	NULL: 22,
	UNDEFINED: 23,
	SIMPLE_VALUE: 24,
	HALF_PRECISION: 25,
	SINGLE_PRECISION: 26,
	DOUBLE_PRECISION: 27,
	BREAK: 31,
} as const;

export type CBORValue =
	| number
	| ArrayBuffer
	| string
	| CBORValue[]
	| { [key: string | number]: CBORValue }
	| { tag: number; value: CBORValue }
	| boolean
	| null
	| undefined;

// COSE_Key Structure (RFC 8152 §7)
export interface COSEKey {
	1: number; // kty (e.g., 2 = EC2, 3 = RSA)
	3: number; // alg (COSEAlgorithm)
	[-1]?: number | ArrayBuffer; // crv (EC) or n (RSA modulus)
	[-2]?: ArrayBuffer; // x (EC) or e (RSA exponent)
	[-3]?: ArrayBuffer; // y (EC)
}

export type HeaderMap = Record<number, CBORValue>;

export interface COSESign1 {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	signature: ArrayBuffer;
}

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

export interface COSEMac0 {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	tag: ArrayBuffer;
}

export interface COSEMac {
	protected: HeaderMap;
	unprotected: HeaderMap;
	payload: ArrayBuffer | null;
	recipients: Array<{
		protected: HeaderMap;
		unprotected: HeaderMap;
		tag: ArrayBuffer;
	}>;
}

export interface COSEEncrypt0 {
	protected: HeaderMap;
	unprotected: HeaderMap;
	ciphertext: ArrayBuffer;
}

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
