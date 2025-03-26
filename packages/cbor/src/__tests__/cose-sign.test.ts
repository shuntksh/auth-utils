import { describe, expect } from "bun:test";
import { test } from "fast-check-bun-test";

import { Sign } from "../cose-sign";
import type { COSESign } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

describe("COSE_Sign", () => {
	test("should encode and decode COSE_Sign with minimal fields", () => {
		const sign: COSESign = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.ES256,
			},
			unprotected: {},
			payload: null,
			signatures: [
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.ES256,
					},
					unprotected: {},
					signature: new Uint8Array([1, 2, 3, 4]).buffer,
				},
			],
		};

		const encoded = Sign.encode(sign);
		const decoded = Sign.decode(encoded);
		expect(decoded).toEqual(sign);
	});

	test("should encode and decode COSE_Sign with multiple signatures", () => {
		const sign: COSESign = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.ES256,
			},
			unprotected: {},
			payload: new Uint8Array([1, 2, 3]).buffer,
			signatures: [
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.ES256,
					},
					unprotected: {
						[COSEHeader.kid]: new Uint8Array([1]).buffer,
					},
					signature: new Uint8Array([2, 3, 4]).buffer,
				},
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.ES384,
					},
					unprotected: {
						[COSEHeader.kid]: new Uint8Array([2]).buffer,
					},
					signature: new Uint8Array([5, 6, 7]).buffer,
				},
			],
		};

		const encoded = Sign.encode(sign);
		const decoded = Sign.decode(encoded);
		expect(decoded).toEqual(sign);
	});
});
