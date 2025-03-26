import { describe, expect, test } from "bun:test";

import { CBOR } from "../cbor";
import type { CBORValue } from "../types";
describe("CBOR RFC Examples", () => {
	// Helper function to convert hex string to ArrayBuffer
	function hexToArrayBuffer(hex: string): ArrayBuffer {
		const bytes = new Uint8Array(
			hex.match(/.{1,2}/g)!.map((byte) => Number.parseInt(byte, 16)),
		);
		return bytes.buffer;
	}

	// Helper function to convert ArrayBuffer to hex string
	function arrayBufferToHex(buffer: ArrayBuffer): string {
		return Array.from(new Uint8Array(buffer))
			.map((b) => b.toString(16).padStart(2, "0"))
			.join("");
	}

	describe("Real Numbers", () => {
		test.each([
			[0, "00"],
			[1, "01"],
			[10, "0a"],
			[23, "17"],
			[24, "1818"],
			[25, "1819"],
			[100, "1864"],
			[1000, "1903e8"],
			[1000000, "1a000f4240"],
			[1000000000000, "1b000000e8d4a51000"],
			// [18446744073709551615, "1bffffffffffffffff"],
			[-1, "20"],
			[-10, "29"],
			[-100, "3863"],
			[-1000, "3903e7"],
		])("should encode/decode integer %p", (value, expectedHex) => {
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			expect(CBOR.decode(encoded)).toBe(value);
		});
	});

	describe("Floating Point Numbers", () => {
		test.each([
			[0.0, "f90000"],
			[-0.0, "f98000"],
			[1.0, "f93c00"],
			[1.5, "f93e00"],
			[65504.0, "f97bff"],
			[100000.0, "fa47c35000"],
			[3.4028234663852886e38, "fa7f7fffff"],
			[-4.0, "f9c400"],
			[Number.POSITIVE_INFINITY, "fb7ff0000000000000"],
			[Number.NaN, "fb7ff8000000000000"],
			[Number.NEGATIVE_INFINITY, "fbfff0000000000000"],
		])("should encode/decode float %p", (value, expectedHex) => {
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			const decoded = CBOR.decode(encoded);
			if (Number.isNaN(value)) {
				expect(Number.isNaN(decoded)).toBe(true);
			} else {
				expect(decoded).toBe(value);
			}
		});
	});

	describe("Simple Values", () => {
		test.each([
			[false, "f4"],
			[true, "f5"],
			[null, "f6"],
			[undefined, "f7"],
		])(
			"should encode/decode simple value %p",
			(value: CBORValue, expectedHex) => {
				const encoded = CBOR.encode(value);
				expect(arrayBufferToHex(encoded)).toBe(expectedHex);
				expect(CBOR.decode(encoded)).toBe(value);
			},
		);
	});

	describe("Byte Strings", () => {
		test.each([
			["", "40"],
			["01020304", "4401020304"],
		])("should encode/decode byte string %p", (hex, expectedHex) => {
			const value = hexToArrayBuffer(hex);
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			const decoded = CBOR.decode(encoded);
			expect(arrayBufferToHex(decoded as ArrayBuffer)).toBe(hex);
		});
	});

	describe("Text Strings", () => {
		test.each([
			["", "60"],
			["a", "6161"],
			["IETF", "6449455446"],
			['"\\', "62225c"],
			["ü", "62c3bc"],
			["水", "63e6b0b4"],
			["𐅑", "64f0908591"],
		])("should encode/decode text string %p", (value, expectedHex) => {
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			expect(CBOR.decode(encoded)).toBe(value);
		});
	});

	describe("Arrays", () => {
		test.each([
			[[], "80"],
			[[1, 2, 3], "83010203"],
			[[1, [2, 3], [4, 5]], "8301820203820405"],
		])("should encode/decode array %p", (value, expectedHex) => {
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			expect(CBOR.decode(encoded)).toEqual(value);
		});
	});

	describe("Maps", () => {
		test.each([
			[{}, "a0"],
			[{ 1: 2, 3: 4 }, "a201020304"],
			[{ a: 1, b: [2, 3] }, "a26161016162820203"],
			[
				{ a: "A", b: "B", c: "C", d: "D", e: "E" },
				"a56161614161626142616361436164614461656145",
			],
		])("should encode/decode map %p", (value, expectedHex) => {
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			expect(CBOR.decode(encoded)).toEqual(value);
		});
	});

	describe("Tagged Values", () => {
		test.each([
			[
				{ tag: 0, value: "2013-03-21T20:04:00Z" },
				"c074323031332d30332d32315432303a30343a30305a",
			],
			[{ tag: 1, value: 1363896240 }, "c11a514b67b0"],
			[{ tag: 23, value: hexToArrayBuffer("01020304") }, "d74401020304"],
			[{ tag: 24, value: hexToArrayBuffer("6449455446") }, "d818456449455446"],
			[
				{ tag: 32, value: "http://www.example.com" },
				"d82076687474703a2f2f7777772e6578616d706c652e636f6d",
			],
		])("should encode/decode tagged value %p", (value, expectedHex) => {
			const encoded = CBOR.encode(value);
			expect(arrayBufferToHex(encoded)).toBe(expectedHex);
			const decoded = CBOR.decode(encoded);
			if (value.value instanceof ArrayBuffer) {
				expect(arrayBufferToHex(decoded as ArrayBuffer)).toBe(
					arrayBufferToHex(value.value),
				);
			} else {
				expect(decoded).toEqual(value);
			}
		});
	});
});
