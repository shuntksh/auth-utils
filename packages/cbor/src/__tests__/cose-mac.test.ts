import { describe, expect } from "bun:test";
import { test } from "fast-check-bun-test";

import { Mac } from "../cose-mac";
import type { COSEMac } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

describe("COSE_Mac", () => {
	test("should encode and decode COSE_Mac with minimal fields", () => {
		const mac: COSEMac = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.HMAC_256_256,
			},
			unprotected: {},
			payload: null,
			recipients: [
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.HMAC_256_256,
					},
					unprotected: {},
					tag: new Uint8Array([1, 2, 3, 4]).buffer,
				},
			],
		};

		const encoded = Mac.encode(mac);
		const decoded = Mac.decode(encoded);
		expect(decoded).toEqual(mac);
	});

	test("should encode and decode COSE_Mac with multiple recipients", () => {
		const mac: COSEMac = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.HMAC_256_256,
			},
			unprotected: {},
			payload: new Uint8Array([1, 2, 3]).buffer,
			recipients: [
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.HMAC_256_256,
					},
					unprotected: {
						[COSEHeader.kid]: new Uint8Array([1]).buffer,
					},
					tag: new Uint8Array([2, 3, 4]).buffer,
				},
				{
					protected: {
						[COSEHeader.alg]: COSEAlgorithm.HMAC_384_384,
					},
					unprotected: {
						[COSEHeader.kid]: new Uint8Array([2]).buffer,
					},
					tag: new Uint8Array([5, 6, 7]).buffer,
				},
			],
		};

		const encoded = Mac.encode(mac);
		const decoded = Mac.decode(encoded);
		expect(decoded).toEqual(mac);
	});
});
