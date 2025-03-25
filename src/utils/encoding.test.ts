// @cspell:disable
import { describe, expect } from "bun:test";
import { fc, test } from "fast-check-bun-test";

import { base32, base64Url } from "./encoding";

describe("Base64URL Encoding/Decoding", () => {
	test("should correctly encode and decode strings", () => {
		const testCases = [
			{ input: "Hello, World!", expected: "SGVsbG8sIFdvcmxkIQ" },
			{ input: "JWT is cool", expected: "SldUIGlzIGNvb2w" },
			{ input: "特殊文字", expected: "54m55q6K5paH5a2X" },
			{ input: "", expected: "" },
		];

		for (const { input, expected } of testCases) {
			const encoded = base64Url.encode(input);
			expect(encoded).toBe(expected);

			const decoded = base64Url.decodeAsString(encoded);
			expect(decoded).toBe(input);
		}
	});

	test("should correctly encode and decode objects", () => {
		const testObject = { name: "John", age: 30, roles: ["admin", "user"] };
		const encoded = base64Url.encode(testObject);
		const decoded = base64Url.decodeAsString(encoded);

		expect(JSON.parse(decoded)).toEqual(testObject);
	});

	test.each([
		{
			input: "Hello+World",
			description: "String with '+' character",
		},
		{
			input: "Test/Data",
			description: "String with '/' character",
		},
		{
			input: "abc123==", // This will generate padding
			description: "String that generates '=' padding",
		},
		{
			input: "Special+Chars/With=Padding",
			description: "String with '+', '/', and potential '=' padding",
		},
		{
			input: "", // Edge case
			description: "Empty string",
		},
	])("should handle %input", ({ input }) => {
		const encoded = base64Url.encode(input);
		expect(encoded).not.toContain("+");
		expect(encoded).not.toContain("/");
		expect(encoded).not.toContain("=");
	});

	test.prop([fc.string()])("property: encode -> decode roundtrip", (str) => {
		const encoded = base64Url.encode(str);
		const decoded = base64Url.decodeAsString(encoded);
		return decoded === str;
	});
});

describe("Base32 Encoding/Decoding", () => {
	test("should correctly encode and decode", () => {
		// Test vectors
		const testCases = [
			{ input: "Hello", expected: "JBSWY3DP" },
			{ input: "Test", expected: "KRSXG5A=" },
			{ input: "12345", expected: "GEZDGNBV" },
			{ input: "", expected: "" },
		];

		for (const { input, expected } of testCases) {
			const encoder = new TextEncoder();
			const buffer = encoder.encode(input);
			const output = base32.fromBuffer(buffer);
			expect(output).toBe(expected);

			const decoded = base32.toBuffer(output);
			const decoder = new TextDecoder();
			const result = decoder.decode(decoded);
			expect(result).toBe(input);
		}
	});

	test("should throw on invalid base32 characters", () => {
		expect(() => base32.toBuffer("INVALID!")).toThrow(
			"Invalid base32 character: !",
		);
	});

	test("property: encode -> decode roundtrip", () => {
		fc.assert(
			fc.property(fc.string(), (str) => {
				const encoder = new TextEncoder();
				const buffer = encoder.encode(str);
				const output = base32.fromBuffer(buffer);
				const decoded = base32.toBuffer(output);
				const decoder = new TextDecoder();
				const result = decoder.decode(decoded);
				return result === str;
			}),
		);
	});
});
