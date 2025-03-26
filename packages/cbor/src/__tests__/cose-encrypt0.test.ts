import { describe, expect } from "bun:test";
import { test } from "fast-check-bun-test";

import { Encrypt0 } from "../cose/encrypt0";
import type { COSEEncrypt0 } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

describe("COSE_Encrypt0", () => {
	test("should encode and decode COSE_Encrypt0 with minimal fields", () => {
		const encrypt0: COSEEncrypt0 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.AES_GCM_128,
			},
			unprotected: {},
			ciphertext: new Uint8Array([1, 2, 3, 4]).buffer,
		};

		const encoded = Encrypt0.encode(encrypt0);
		const decoded = Encrypt0.decode(encoded);
		expect(decoded).toEqual(encrypt0);
	});

	test("should encode and decode COSE_Encrypt0 with all fields", () => {
		const encrypt0: COSEEncrypt0 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.AES_GCM_128,
				[COSEHeader.iv]: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12])
					.buffer,
			},
			unprotected: {
				[COSEHeader.kid]: new Uint8Array([1, 2, 3]).buffer,
			},
			ciphertext: new Uint8Array([4, 5, 6]).buffer,
		};

		const encoded = Encrypt0.encode(encrypt0);
		const decoded = Encrypt0.decode(encoded);
		expect(decoded).toEqual(encrypt0);
	});
});
