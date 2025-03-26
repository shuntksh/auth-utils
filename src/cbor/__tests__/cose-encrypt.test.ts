import { describe, expect } from "bun:test";
import { test } from "fast-check-bun-test";

import { Encrypt } from "../cose-encrypt";
import type { COSEEncrypt } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

describe("COSE_Encrypt", () => {
	test("should encode and decode COSE_Encrypt with minimal fields", () => {
		const encrypt: COSEEncrypt = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.AES_GCM_128,
			},
			unprotected: {},
			ciphertext: new Uint8Array([1, 2, 3, 4]).buffer,
			recipients: [
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.AES_GCM_128,
					},
					unprotected: {},
					encrypted_key: new Uint8Array([5, 6, 7, 8]).buffer,
				},
			],
		};

		const encoded = Encrypt.encode(encrypt);
		const decoded = Encrypt.decode(encoded);
		expect(decoded).toEqual(encrypt);
	});

	test("should encode and decode COSE_Encrypt with multiple recipients", () => {
		const encrypt: COSEEncrypt = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.AES_GCM_128,
				[COSEHeader.iv]: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
					.buffer,
			},
			unprotected: {},
			ciphertext: new Uint8Array([1, 2, 3]).buffer,
			recipients: [
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.AES_GCM_128,
					},
					unprotected: {
						[COSEHeader.kid]: new Uint8Array([1]).buffer,
					},
					encrypted_key: new Uint8Array([2, 3, 4]).buffer,
				},
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.AES_GCM_192,
					},
					unprotected: {
						[COSEHeader.kid]: new Uint8Array([2]).buffer,
					},
					encrypted_key: new Uint8Array([5, 6, 7]).buffer,
				},
			],
		};

		const encoded = Encrypt.encode(encrypt);
		const decoded = Encrypt.decode(encoded);
		expect(decoded).toEqual(encrypt);
	});
});
