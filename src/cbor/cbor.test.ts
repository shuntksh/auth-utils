import { describe, expect, test } from "bun:test";
import { fc } from "fast-check-bun-test";

import { CBOR } from "./cbor";

describe("CBOR", () => {
	describe("encode/decode", () => {
		test("should encode and decode unsigned integers", () => {
			const values = [0, 1, 23, 24, 255, 256, 65535, 65536, 4294967295];
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(decoded).toBe(value);
			}
		});

		test("should encode and decode negative integers", () => {
			const values = [
				-1, -10, -24, -25, -256, -257, -65536, -65537, -4294967296,
			];
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(decoded).toBe(value);
			}
		});

		test("should encode and decode special values", () => {
			const values = [true, false, null] as const;
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(decoded).toBe(value);
			}
		});

		test("should encode and decode text strings", () => {
			const values = ["", "a", "Hello, World!", "日本語"];
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(decoded).toBe(value);
			}
		});

		test("should encode and decode byte strings", () => {
			const values = [
				new Uint8Array([1, 2, 3, 4]).buffer,
				new Uint8Array([0, 255]).buffer,
				new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]).buffer,
			];
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(new Uint8Array(decoded as ArrayBuffer)).toEqual(
					new Uint8Array(value),
				);
			}
		});

		test("should encode and decode arrays", () => {
			const values = [
				[],
				[1, 2, 3],
				["a", "b", "c"],
				[1, "a", new Uint8Array([1, 2, 3]).buffer],
				[true, false, null],
				[-1, -10, 0, 10],
			];
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(decoded).toEqual(value);
			}
		});

		test("should encode and decode maps", () => {
			const values = [
				{},
				{ a: 1, b: 2 },
				{ Hello: "World", Number: 42 },
				{ Array: [1, 2, 3], String: "test" },
				{ Boolean: true, Null: null },
				{ Negative: -1, Zero: 0, Positive: 1 },
			];
			for (const value of values) {
				const encoded = CBOR.encode(value);
				const decoded = CBOR.decode(encoded);
				expect(decoded).toEqual(value);
			}
		});
	});

	describe("Property-based tests", () => {
		test("should handle any valid integer", () => {
			fc.assert(
				fc.property(
					fc.integer({
						min: Number.MIN_SAFE_INTEGER,
						max: Number.MAX_SAFE_INTEGER,
					}),
					(n) => {
						const encoded = CBOR.encode(n);
						const decoded = CBOR.decode(encoded);
						expect(decoded).toBe(n);
					},
				),
			);
		});

		test("should handle any valid string", () => {
			fc.assert(
				fc.property(fc.string(), (s) => {
					const encoded = CBOR.encode(s);
					const decoded = CBOR.decode(encoded);
					expect(decoded).toBe(s);
				}),
			);
		});

		test("should handle any valid byte array", () => {
			fc.assert(
				fc.property(fc.uint8Array({ minLength: 0, maxLength: 1000 }), (arr) => {
					const buffer = arr.buffer;
					const encoded = CBOR.encode(buffer);
					const decoded = CBOR.decode(encoded);
					expect(new Uint8Array(decoded as ArrayBuffer)).toEqual(arr);
				}),
			);
		});

		test("should handle nested arrays of any depth", () => {
			fc.assert(
				fc.property(
					fc.array(
						fc.oneof(
							fc.integer(),
							fc.string(),
							fc.boolean(),
							fc.constant(null),
						),
						{ minLength: 0, maxLength: 10 },
					),
					(arr) => {
						const encoded = CBOR.encode(arr);
						const decoded = CBOR.decode(encoded);
						expect(decoded).toEqual(arr);
					},
				),
			);
		});

		test("should handle complex nested objects", () => {
			fc.assert(
				fc.property(
					fc.record({
						key: fc.string(),
						values: fc.array(
							fc.oneof(
								fc.integer(),
								fc.string(),
								fc.boolean(),
								fc.constant(null),
								fc.array(fc.integer()),
								fc.record({
									nested: fc.string(),
									array: fc.array(fc.integer()),
								}),
							),
							{ minLength: 0, maxLength: 5 },
						),
					}),
					(obj) => {
						const encoded = CBOR.encode(obj);
						const decoded = CBOR.decode(encoded);
						expect(decoded).toEqual(obj);
					},
				),
			);
		});

		test("should handle edge cases for integers", () => {
			fc.assert(
				fc.property(
					fc.oneof(
						fc.constant(Number.MIN_SAFE_INTEGER),
						fc.constant(Number.MAX_SAFE_INTEGER),
						fc.constant(0),
						fc.constant(-1),
						fc.constant(1),
						fc.constant(Number.MAX_SAFE_INTEGER - 1),
						fc.constant(Number.MIN_SAFE_INTEGER + 1),
					),
					(n) => {
						const encoded = CBOR.encode(n);
						const decoded = CBOR.decode(encoded);
						expect(decoded).toBe(n);
					},
				),
			);
		});

		test("should handle edge cases for strings", () => {
			fc.assert(
				fc.property(
					fc.oneof(
						fc.constant(""),
						fc.constant(" "),
						fc.constant("\u0000"),
						fc.constant("\uFFFF"),
						fc.constant("日本語"),
						fc.constant("Hello, World!"),
						fc.constant("a".repeat(1000)),
					),
					(s) => {
						const encoded = CBOR.encode(s);
						const decoded = CBOR.decode(encoded);
						expect(decoded).toBe(s);
					},
				),
			);
		});

		test("should handle edge cases for byte arrays", () => {
			fc.assert(
				fc.property(
					fc.oneof(
						fc.constant(new Uint8Array()),
						fc.constant(new Uint8Array([0])),
						fc.constant(new Uint8Array([255])),
						fc.constant(new Uint8Array([0, 255])),
						fc.constant(new Uint8Array(1000).fill(255)),
					),
					(arr) => {
						const buffer = arr.buffer;
						const encoded = CBOR.encode(buffer);
						const decoded = CBOR.decode(encoded);
						expect(new Uint8Array(decoded as ArrayBuffer)).toEqual(arr);
					},
				),
			);
		});
	});

	describe("WebAuthn clientData", () => {
		test("should encode and decode clientData structure", () => {
			const clientData = {
				type: "webauthn.create",
				challenge: "challenge123",
				origin: "https://example.com",
				crossOrigin: false,
			};

			const encoded = CBOR.encode(clientData);
			const decoded = CBOR.decode(encoded) as typeof clientData;
			expect(decoded).toEqual(clientData);
		});

		test("should handle nested clientData structures", () => {
			const clientData = {
				type: "webauthn.create",
				challenge: "challenge123",
				origin: "https://example.com",
				crossOrigin: false,
				extensions: {
					appid: "https://example.com",
					credProps: true,
				},
			};

			const encoded = CBOR.encode(clientData);
			const decoded = CBOR.decode(encoded) as typeof clientData;
			expect(decoded).toEqual(clientData);
		});

		test("should handle clientData with binary data", () => {
			const clientData = {
				type: "webauthn.create",
				challenge: new Uint8Array([1, 2, 3, 4]).buffer,
				origin: "https://example.com",
				crossOrigin: false,
			};

			const encoded = CBOR.encode(clientData);
			const decoded = CBOR.decode(encoded) as typeof clientData;
			expect(new Uint8Array(decoded.challenge as ArrayBuffer)).toEqual(
				new Uint8Array([1, 2, 3, 4]),
			);
			expect(decoded.type).toBe("webauthn.create");
			expect(decoded.origin).toBe("https://example.com");
			expect(decoded.crossOrigin).toBe(false);
		});

		test("should handle various clientData structures", () => {
			fc.assert(
				fc.property(
					fc.record({
						type: fc.constant("webauthn.create"),
						challenge: fc.oneof(
							fc.string(),
							fc.uint8Array().map((arr) => arr.buffer),
						),
						origin: fc.string(),
						crossOrigin: fc.boolean(),
						extensions: fc.option(
							fc.record({
								appid: fc.string(),
								credProps: fc.boolean(),
							}),
						),
					}),
					(clientData) => {
						const encoded = CBOR.encode(clientData);
						const decoded = CBOR.decode(encoded) as typeof clientData;
						expect(decoded).toEqual(clientData);
					},
				),
			);
		});
	});
});
