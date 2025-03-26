import { describe, expect } from "bun:test";
import { test } from "fast-check-bun-test";

import { Mac0 } from "../cose-mac0";
import type { COSEMac0 } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

describe("COSE_Mac0", () => {
	test("should encode and decode COSE_Mac0 with minimal fields", () => {
		const mac0: COSEMac0 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.HMAC_256_256,
			},
			unprotected: {},
			payload: null,
			tag: new Uint8Array([1, 2, 3, 4]).buffer,
		};

		const encoded = Mac0.encode(mac0);
		const decoded = Mac0.decode(encoded);
		expect(decoded).toEqual(mac0);
	});

	test("should encode and decode COSE_Mac0 with all fields", () => {
		const mac0: COSEMac0 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.HMAC_256_256,
			},
			unprotected: {
				[COSEHeader.kid]: new Uint8Array([1, 2, 3]).buffer,
			},
			payload: new Uint8Array([4, 5, 6]).buffer,
			tag: new Uint8Array([7, 8, 9]).buffer,
		};

		const encoded = Mac0.encode(mac0);
		const decoded = Mac0.decode(encoded);
		expect(decoded).toEqual(mac0);
	});
});
