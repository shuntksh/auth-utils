import { describe, expect } from "bun:test";
import { test } from "fast-check-bun-test";
import { Sign1 } from "../cose/sign1";
import type { COSESign1 } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

describe("COSE_Sign1", () => {
	test("should encode and decode COSE_Sign1 with minimal fields", () => {
		const sign1: COSESign1 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.ES256,
			},
			unprotected: {},
			payload: null,
			signature: new Uint8Array([1, 2, 3, 4]).buffer,
		};

		const encoded = Sign1.encode(sign1);
		const decoded = Sign1.decode(encoded);
		expect(decoded).toEqual(sign1);
	});

	test("should encode and decode COSE_Sign1 with all fields", () => {
		const sign1: COSESign1 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.ES256,
				[COSEHeader.crit]: [COSEHeader.alg],
				[COSEHeader.ctyp]: "application/cbor",
			},
			unprotected: {
				[COSEHeader.kid]: new Uint8Array([1, 2, 3]).buffer,
			},
			payload: new Uint8Array([5, 6, 7, 8]).buffer,
			signature: new Uint8Array([9, 10, 11, 12]).buffer,
		};

		const encoded = Sign1.encode(sign1);
		const decoded = Sign1.decode(encoded);
		expect(decoded).toEqual(sign1);
	});

	test("should handle COSE_Sign1 with various payload types", () => {
		const sign1: COSESign1 = {
			protected: {
				[COSEHeader.alg]: COSEAlgorithm.ES256,
			},
			unprotected: {},
			payload: new TextEncoder().encode("Hello, World!").buffer as ArrayBuffer,
			signature: new Uint8Array([1, 2, 3, 4]).buffer,
		};

		const encoded = Sign1.encode(sign1);
		const decoded = Sign1.decode(encoded);
		expect(decoded).toEqual(sign1);
	});

	test("should throw error for missing algorithm", () => {
		const sign1: COSESign1 = {
			protected: {},
			unprotected: {},
			payload: null,
			signature: new Uint8Array([1, 2, 3, 4]).buffer,
		};

		expect(() => Sign1.encode(sign1)).toThrow(
			"Protected header must contain 'alg' parameter",
		);
	});

	test("should throw error for invalid algorithm", () => {
		const sign1: COSESign1 = {
			protected: {
				[COSEHeader.alg]: 999, // Invalid algorithm
			},
			unprotected: {},
			payload: null,
			signature: new Uint8Array([1, 2, 3, 4]).buffer,
		};

		expect(() => Sign1.encode(sign1)).toThrow(
			"Invalid or unsupported algorithm in protected header",
		);
	});
});
