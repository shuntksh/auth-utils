import { describe, expect } from "bun:test";
import { fc, test } from "fast-check-bun-test";

import { COSE } from "../src/cose";
import { COSEAlgorithm, COSEHeader } from "../src/types";

describe("COSE", () => {
	describe("Property-based tests", () => {
		// Helper function to generate random header maps
		const headerMapArbitrary = fc.record({
			[COSEHeader.alg]: fc.oneof(
				fc.constant(COSEAlgorithm.ES256),
				fc.constant(COSEAlgorithm.ES384),
				fc.constant(COSEAlgorithm.ES512),
				fc.constant(COSEAlgorithm.EDDSA),
				fc.constant(COSEAlgorithm.RS256),
				fc.constant(COSEAlgorithm.RS384),
				fc.constant(COSEAlgorithm.RS512),
				fc.constant(COSEAlgorithm.PS256),
				fc.constant(COSEAlgorithm.PS384),
				fc.constant(COSEAlgorithm.PS512),
				fc.constant(COSEAlgorithm.HMAC_256_256),
				fc.constant(COSEAlgorithm.HMAC_384_384),
				fc.constant(COSEAlgorithm.HMAC_512_512),
				fc.constant(COSEAlgorithm.AES_GCM_128),
				fc.constant(COSEAlgorithm.AES_GCM_192),
				fc.constant(COSEAlgorithm.AES_GCM_256),
				fc.constant(COSEAlgorithm.CHACHA20_POLY1305),
				fc.constant(COSEAlgorithm.direct),
			),
			[COSEHeader.crit]: fc.oneof(
				fc.array(fc.integer()),
				fc.constant(undefined),
			),
			[COSEHeader.ctyp]: fc.oneof(fc.string(), fc.constant(undefined)),
			[COSEHeader.kid]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[COSEHeader.iv]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[COSEHeader.partial_iv]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[COSEHeader.counter_signature]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[COSEHeader.salt]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[COSEHeader.x5chain]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
			[COSEHeader.x5t]: fc.oneof(
				fc.uint8Array().map((arr) => arr.buffer),
				fc.constant(undefined),
			),
		});

		// Helper function to generate random binary data
		const binaryDataArbitrary = fc.oneof(
			fc.uint8Array().map((arr) => arr.buffer),
			fc.constant(null),
		);

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				payload: binaryDataArbitrary,
				signature: fc.uint8Array().map((arr) => arr.buffer),
			}),
		])("should handle any valid COSE_Sign1 structure", (sign1) => {
			const encoded = COSE.Sign1.encode(sign1);
			const decoded = COSE.Sign1.decode(encoded);
			expect(decoded).toEqual(sign1);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				payload: binaryDataArbitrary,
				signatures: fc.array(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						signature: fc.uint8Array().map((arr) => arr.buffer),
					}),
					{ minLength: 1, maxLength: 5 },
				),
			}),
		])("should handle any valid COSE_Sign structure", (sign) => {
			const encoded = COSE.Sign.encode(sign);
			const decoded = COSE.Sign.decode(encoded);
			expect(decoded).toEqual(sign);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				payload: binaryDataArbitrary,
				tag: fc.uint8Array().map((arr) => arr.buffer),
			}),
		])("should handle any valid COSE_Mac0 structure", (mac0) => {
			const encoded = COSE.Mac0.encode(mac0);
			const decoded = COSE.Mac0.decode(encoded);
			expect(decoded).toEqual(mac0);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				payload: binaryDataArbitrary,
				recipients: fc.array(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						tag: fc.uint8Array().map((arr) => arr.buffer),
					}),
					{ minLength: 1, maxLength: 5 },
				),
			}),
		])("should handle any valid COSE_Mac structure", (mac) => {
			const encoded = COSE.Mac.encode(mac);
			const decoded = COSE.Mac.decode(encoded);
			expect(decoded).toEqual(mac);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				payload: binaryDataArbitrary,
				recipients: fc.array(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						tag: fc.uint8Array().map((arr) => arr.buffer),
					}),
					{ minLength: 1, maxLength: 5 },
				),
			}),
		])("should handle any valid COSE_Mac structure", (mac) => {
			const encoded = COSE.Mac.encode(mac);
			const decoded = COSE.Mac.decode(encoded);
			expect(decoded).toEqual(mac);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				ciphertext: fc.uint8Array().map((arr) => arr.buffer),
			}),
		])("should handle any valid COSE_Encrypt0 structure", (encrypt0) => {
			const encoded = COSE.Encrypt0.encode(encrypt0);
			const decoded = COSE.Encrypt0.decode(encoded);
			expect(decoded).toEqual(encrypt0);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				ciphertext: fc.uint8Array().map((arr) => arr.buffer),
				recipients: fc.array(
					fc.record({
						protected: headerMapArbitrary,
						unprotected: headerMapArbitrary,
						encrypted_key: fc.uint8Array().map((arr) => arr.buffer),
					}),
					{ minLength: 1, maxLength: 5 },
				),
			}),
		])("should handle any valid COSE_Encrypt structure", (encrypt) => {
			const encoded = COSE.Encrypt.encode(encrypt);
			const decoded = COSE.Encrypt.decode(encoded);
			expect(decoded).toEqual(encrypt);
		});

		test.prop([
			fc.record({
				protected: fc.record({
					[COSEHeader.alg]: fc.constant(COSEAlgorithm.ES256),
					[COSEHeader.crit]: fc.array(fc.integer()),
					[COSEHeader.ctyp]: fc.string(),
					[COSEHeader.kid]: fc.uint8Array().map((arr) => arr.buffer),
					[COSEHeader.iv]: fc.uint8Array().map((arr) => arr.buffer),
				}),
				unprotected: fc.record({
					[COSEHeader.alg]: fc.integer(),
					[COSEHeader.crit]: fc.array(fc.integer()),
					[COSEHeader.ctyp]: fc.string(),
					[COSEHeader.kid]: fc.uint8Array().map((arr) => arr.buffer),
					[COSEHeader.iv]: fc.uint8Array().map((arr) => arr.buffer),
				}),
				payload: binaryDataArbitrary,
				signature: fc.uint8Array().map((arr) => arr.buffer),
			}),
		])("should handle edge cases for header maps", (sign1) => {
			const encoded = COSE.Sign1.encode(sign1);
			const decoded = COSE.Sign1.decode(encoded);
			expect(decoded).toEqual(sign1);
		});

		test.prop([
			fc.record({
				protected: headerMapArbitrary,
				unprotected: headerMapArbitrary,
				payload: fc.oneof(
					fc.constant(null),
					fc.constant(new Uint8Array().buffer),
					fc.constant(new Uint8Array([0]).buffer),
					fc.constant(new Uint8Array([255]).buffer),
					fc.constant(new Uint8Array(1000).fill(255).buffer),
				),
				signature: fc.uint8Array().map((arr) => arr.buffer),
			}),
		])("should handle edge cases for binary data", (sign1) => {
			const encoded = COSE.Sign1.encode(sign1);
			const decoded = COSE.Sign1.decode(encoded);
			expect(decoded).toEqual(sign1);
		});
	});
});
