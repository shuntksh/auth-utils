export type { COSEEncrypt } from "./cose-encrypt";
export type { COSEEncrypt0 } from "./cose-encrypt0";
export type { COSEMac } from "./cose-mac";
export type { COSEMac0 } from "./cose-mac0";
export type { COSESign } from "./cose-sign";
export type { COSESign1 } from "./cose-sign1";

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

export enum COSEHeader {
	alg = 1,
	crit = 2,
	ctyp = 3,
	kid = 4,
	iv = 5,
	partial_iv = 6,
	counter_signature = 7,
	salt = 8,
	counter_signature0 = 9,
	x5chain = 33,
	x5t = 34,
}

export enum COSEAlgorithm {
	AES_CCM_16_128_128 = 30,
	AES_CCM_16_128_256 = 31,
	AES_CCM_16_64_128 = 10,
	AES_CCM_16_64_256 = 12,
	AES_CCM_64_128_128 = 32,
	AES_CCM_64_128_256 = 33,
	AES_CCM_64_64_128 = 13,
	AES_CCM_64_64_256 = 14,
	AES_GCM_128 = 1,
	AES_GCM_192 = 2,
	AES_GCM_256 = 3,
	CHACHA20_POLY1305 = 24,
	direct = -6,
	EDDSA = -8,
	ES256 = -7,
	ES384 = -35,
	ES512 = -36,
	HMAC_256_256 = 5,
	HMAC_256_64 = 4,
	HMAC_384_384 = 6,
	HMAC_512_512 = 7,
	PS256 = -37,
	PS384 = -38,
	PS512 = -39,
	RS256 = -257,
	RS384 = -258,
	RS512 = -259,
}

export type HeaderMap = Record<number, CBORValue>;
