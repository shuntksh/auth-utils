import type { CBORValue } from "./types";
import { CBOR_FLOAT_ADDITIONAL_INFO, CBOR_MAJOR_TYPES } from "./types";

/**
 * Encodes a CBOR value into a list of Uint8Arrays.
 */
export function encodeValue(value: CBORValue, buffers: Uint8Array[]): void {
	if (typeof value === "number") {
		if (!Number.isSafeInteger(value) || Object.is(value, -0)) {
			encodeFloat(value, buffers);
		} else {
			if (value < 0) {
				encodeNegativeInteger(value, buffers);
			} else {
				encodeUnsignedInteger(value, buffers);
			}
		}
	} else if (value instanceof ArrayBuffer) {
		encodeByteString(value, buffers);
	} else if (typeof value === "string") {
		encodeTextString(value, buffers);
	} else if (Array.isArray(value)) {
		encodeArray(value, buffers);
	} else if (typeof value === "object" && value !== null) {
		if ("tag" in value && "value" in value && typeof value.tag === "number") {
			encodeTag(value.tag, value.value, buffers);
		} else {
			encodeMap(value, buffers);
		}
	} else if (typeof value === "boolean") {
		encodeBoolean(value, buffers);
	} else if (value === null) {
		encodeNull(buffers);
	} else if (value === undefined) {
		encodeUndefined(buffers);
	} else {
		throw new Error(
			`Unsupported value type for CBOR encoding: ${typeof value}`,
		);
	}
}

/**
 * Major type 0: Unsigned integers
 */
function encodeUnsignedInteger(value: number, buffers: Uint8Array[]): void {
	if (value < 0 || !Number.isInteger(value)) {
		throw new Error("Only unsigned integers are supported");
	}
	const header = encodeLength(CBOR_MAJOR_TYPES.UNSIGNED_INTEGER, value);
	buffers.push(header);
}

/**
 * Major type 1: Negative integers
 */
function encodeNegativeInteger(value: number, buffers: Uint8Array[]): void {
	if (!Number.isInteger(value) || value >= 0) {
		throw new Error("Only negative integers are supported");
	}
	const absValue = Math.abs(value) - 1;
	const header = encodeLength(CBOR_MAJOR_TYPES.NEGATIVE_INTEGER, absValue);
	buffers.push(header);
}

/**
 * Major type 2: Byte strings
 */
function encodeByteString(value: ArrayBuffer, buffers: Uint8Array[]): void {
	const length = value.byteLength;
	const header = encodeLength(CBOR_MAJOR_TYPES.BYTE_STRING, length);
	buffers.push(header);
	buffers.push(new Uint8Array(value));
}

/**
 * Major type 3: Text strings
 */
function encodeTextString(value: string, buffers: Uint8Array[]): void {
	const bytes = new TextEncoder().encode(value);
	const header = encodeLength(CBOR_MAJOR_TYPES.TEXT_STRING, bytes.length);
	buffers.push(header);
	buffers.push(bytes);
}

/**
 * Major type 4: Arrays
 */
function encodeArray(value: CBORValue[], buffers: Uint8Array[]): void {
	if (value.length > 10000)
		throw new Error("Array length exceeds reasonable limit");
	const header = encodeLength(CBOR_MAJOR_TYPES.ARRAY, value.length);
	buffers.push(header);
	for (const item of value) {
		encodeValue(item, buffers);
	}
}

/**
 * Major type 5: Maps
 */
function encodeMap(
	value: { [key: string | number]: CBORValue },
	buffers: Uint8Array[],
): void {
	const entries = Object.entries(value);

	// Check for duplicate keys
	const seenKeys = new Set<string>();
	for (const [key] of entries) {
		if (seenKeys.has(key)) {
			throw new Error("Duplicate keys are not allowed in CBOR maps");
		}
		seenKeys.add(key);
	}

	const header = encodeLength(CBOR_MAJOR_TYPES.MAP, entries.length);
	buffers.push(header);
	for (const [key, val] of entries) {
		const numKey = Number(key);
		if (!Number.isNaN(numKey)) {
			encodeValue(numKey, buffers);
		} else {
			encodeTextString(key, buffers);
		}
		encodeValue(val, buffers);
	}
}

/**
 * Major type 6: Tags
 */
function encodeTag(tag: number, value: CBORValue, buffers: Uint8Array[]): void {
	if (!Number.isInteger(tag) || tag < 0) {
		throw new Error("Tag must be a non-negative integer");
	}
	const header = encodeLength(CBOR_MAJOR_TYPES.TAG, tag);
	buffers.push(header);
	encodeValue(value, buffers);
}

/**
 * Major type 7: Floating-point numbers
 */
function encodeFloat(value: number, buffers: Uint8Array[]): void {
	if (!Number.isFinite(value)) {
		const buffer = new Uint8Array(9);
		buffer[0] = getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.DOUBLE_PRECISION);
		new DataView(buffer.buffer).setFloat64(1, value, false);
		buffers.push(buffer);
		return;
	}

	// Special case for 0 and -0
	if (value === 0) {
		const buffer = new Uint8Array(3);
		buffer[0] = getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.HALF_PRECISION);
		buffer[1] = Object.is(value, -0) ? 0x80 : 0x00; // -0.0: sign bit 1, exp 0, mantissa 0
		buffer[2] = 0x00; // mantissa 0
		buffers.push(buffer);
		return;
	}

	// Try half-precision (16-bit)
	const halfBuffer = new Uint8Array(3);
	halfBuffer[0] = getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.HALF_PRECISION);

	// Convert to half-precision
	const float32 = new Float32Array([value]);
	const float32Bits = new Uint32Array(float32.buffer)[0];

	// Extract sign bit
	const sign = (float32Bits >> 31) & 1;

	// Extract exponent
	const exp = ((float32Bits >> 23) & 0xff) - 127;

	// Extract mantissa
	const mantissa = float32Bits & 0x7fffff;

	// Convert to half-precision format
	let halfBits = 0;
	halfBits |= sign << 15;

	if (exp > 15) {
		// Overflow to infinity
		halfBits |= 0x7c00;
	} else if (exp < -14) {
		// Underflow to zero
		halfBits |= 0;
	} else {
		// Normal number
		halfBits |= ((exp + 15) & 0x1f) << 10;
		halfBits |= (mantissa >> 13) & 0x3ff;
	}

	halfBuffer[1] = (halfBits >> 8) & 0xff;
	halfBuffer[2] = halfBits & 0xff;

	const halfDecoded = decodeHalfPrecision(halfBuffer.slice(1));
	if (halfDecoded === value) {
		buffers.push(halfBuffer);
		return;
	}

	// Try single-precision (32-bit)
	const singleBuffer = new Uint8Array(5);
	singleBuffer[0] = getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.SINGLE_PRECISION);
	new DataView(singleBuffer.buffer).setFloat32(1, value, false);
	const singleDecoded = new DataView(singleBuffer.buffer).getFloat32(1, false);
	if (singleDecoded === value) {
		buffers.push(singleBuffer);
		return;
	}

	// Default to double-precision (64-bit)
	const doubleBuffer = new Uint8Array(9);
	doubleBuffer[0] = getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.DOUBLE_PRECISION);
	new DataView(doubleBuffer.buffer).setFloat64(1, value, false);
	buffers.push(doubleBuffer);
}

/**
 * Helper function for half-precision decoding (for encoding validation)
 */
function decodeHalfPrecision(bytes: Uint8Array): number {
	const half = (bytes[0] << 8) + bytes[1];
	const sign = half & 0x8000 ? -1 : 1;
	const exp = (half & 0x7c00) >> 10;
	const mantissa = half & 0x03ff;
	if (exp === 0) return sign * 2 ** -14 * (mantissa / 1024);
	if (exp === 31)
		return mantissa === 0 ? sign * Number.POSITIVE_INFINITY : Number.NaN;
	return sign * 2 ** (exp - 15) * (1 + mantissa / 1024);
}

/**
 * Major type 7: Boolean values
 */
function encodeBoolean(value: boolean, buffers: Uint8Array[]): void {
	buffers.push(
		new Uint8Array([
			getSpecialType(
				value
					? CBOR_FLOAT_ADDITIONAL_INFO.TRUE
					: CBOR_FLOAT_ADDITIONAL_INFO.FALSE,
			),
		]),
	);
}

/**
 * Major type 7: Null value
 */
function encodeNull(buffers: Uint8Array[]): void {
	buffers.push(
		new Uint8Array([getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.NULL)]),
	);
}

/**
 * Major type 7: Undefined value
 */
function encodeUndefined(buffers: Uint8Array[]): void {
	buffers.push(
		new Uint8Array([getSpecialType(CBOR_FLOAT_ADDITIONAL_INFO.UNDEFINED)]),
	);
}

function getSpecialType(additionalInfo: number): number {
	return (CBOR_MAJOR_TYPES.FLOAT << 5) | additionalInfo;
}

/**
 * Encodes the length of a CBOR value.
 */
function encodeLength(majorType: number, length: number): Uint8Array {
	const mt = majorType << 5;
	if (length <= 23) return new Uint8Array([mt | length]);
	if (length <= 0xff) return new Uint8Array([mt | 24, length]);
	if (length <= 0xffff) {
		const buffer = new Uint8Array(3);
		buffer[0] = mt | 25;
		new DataView(buffer.buffer).setUint16(1, length, false);
		return buffer;
	}
	if (length <= 0xffffffff) {
		const buffer = new Uint8Array(5);
		buffer[0] = mt | 26;
		new DataView(buffer.buffer).setUint32(1, length, false);
		return buffer;
	}
	if (length <= Number.MAX_SAFE_INTEGER) {
		if (!Number.isSafeInteger(length)) {
			throw new Error("Length is not a safe integer");
		}
		const buffer = new Uint8Array(9);
		buffer[0] = mt | 27;
		const bigLength = BigInt(length);
		for (let i = 0; i < 8; i++) {
			buffer[1 + i] = Number(
				(bigLength >> (BigInt(7 - i) * 8n)) & BigInt(0xff),
			);
		}
		return buffer;
	}
	throw new Error("Length exceeds JavaScript's safe integer range; use BigInt");
}
