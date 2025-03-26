import type { CBORValue } from "./types";
import { CBOR_FLOAT_ADDITIONAL_INFO, CBOR_MAJOR_TYPES } from "./types";

/**
 * Decodes the first item in the buffer
 */
export function decodeValue(
	buffer: ArrayBuffer,
	startOffset: number,
): [CBORValue, number] {
	const dataView = new DataView(buffer);
	if (startOffset >= buffer.byteLength) {
		throw new Error("Buffer too short for CBOR decoding");
	}
	const firstByte = dataView.getUint8(startOffset);
	const majorType = firstByte >> 5;
	const additionalInfo = firstByte & 0x1f;
	const offset = startOffset + 1;

	switch (majorType) {
		case CBOR_MAJOR_TYPES.UNSIGNED_INTEGER:
			return decodeUnsignedInteger(dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.NEGATIVE_INTEGER:
			return decodeNegativeInteger(dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.BYTE_STRING:
			return decodeByteString(buffer, dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.TEXT_STRING:
			return decodeTextString(buffer, dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.ARRAY:
			return decodeArray(buffer, dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.MAP:
			return decodeMap(buffer, dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.TAG:
			return decodeTag(buffer, dataView, offset, additionalInfo);
		case CBOR_MAJOR_TYPES.FLOAT:
			return decodeSpecial(dataView, offset, additionalInfo);
		default:
			throw new Error(`Unsupported CBOR major type: ${majorType}`);
	}
}

/**
 * Major type 0: Unsigned integers
 */
function decodeUnsignedInteger(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) {
		return [additionalInfo, offset];
	}
	if (additionalInfo === 24) {
		ensureBytes(dataView, offset, 1);
		return [dataView.getUint8(offset), offset + 1];
	}
	if (additionalInfo === 25) {
		ensureBytes(dataView, offset, 2);
		return [dataView.getUint16(offset, false), offset + 2];
	}
	if (additionalInfo === 26) {
		ensureBytes(dataView, offset, 4);
		return [dataView.getUint32(offset, false), offset + 4];
	}
	if (additionalInfo === 27) {
		ensureBytes(dataView, offset, 8);
		return [Number(dataView.getBigUint64(offset, false)), offset + 8];
	}
	throw new Error("Invalid additional info for unsigned integer");
}

/**
 * Major type 1: Negative integers
 */
function decodeNegativeInteger(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) {
		return [-1 - additionalInfo, offset];
	}
	if (additionalInfo === 24) {
		ensureBytes(dataView, offset, 1);
		return [-1 - dataView.getUint8(offset), offset + 1];
	}
	if (additionalInfo === 25) {
		ensureBytes(dataView, offset, 2);
		return [-1 - dataView.getUint16(offset, false), offset + 2];
	}
	if (additionalInfo === 26) {
		ensureBytes(dataView, offset, 4);
		return [-1 - dataView.getUint32(offset, false), offset + 4];
	}
	if (additionalInfo === 27) {
		ensureBytes(dataView, offset, 8);
		return [-1 - Number(dataView.getBigUint64(offset, false)), offset + 8];
	}
	throw new Error("Invalid additional info for negative integer");
}

/**
 * Major type 2: Byte strings
 */
function decodeByteString(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [ArrayBuffer, number] {
	const [length, newOffset] = getLength(dataView, offset, additionalInfo);
	ensureBytes(dataView, newOffset, length);
	return [buffer.slice(newOffset, newOffset + length), newOffset + length];
}

/**
 * Major type 3: Text strings
 */
function decodeTextString(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [string, number] {
	const [length, newOffset] = getLength(dataView, offset, additionalInfo);
	ensureBytes(dataView, newOffset, length);
	const bytes = new Uint8Array(buffer.slice(newOffset, newOffset + length));
	try {
		return [
			new TextDecoder("utf-8", { fatal: true }).decode(bytes),
			newOffset + length,
		];
	} catch (e) {
		throw new Error("Invalid UTF-8 sequence in text string");
	}
}

/**
 * Major type 4: Arrays
 */
function decodeArray(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [CBORValue[], number] {
	const [length, newOffset] = getLength(dataView, offset, additionalInfo);
	if (length > 10000) {
		throw new Error("Array length exceeds reasonable limit");
	}

	const array: CBORValue[] = [];

	let currentOffset = newOffset;
	for (let i = 0; i < length; i++) {
		const [item, nextOffset] = decodeValue(buffer, currentOffset);
		array.push(item);
		currentOffset = nextOffset;
	}

	return [array, currentOffset];
}

/**
 * Major type 5: Maps
 */
function decodeMap(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [{ [key: string | number]: CBORValue }, number] {
	const [numPairs, newOffset] = getLength(dataView, offset, additionalInfo);
	if (numPairs > 10000) {
		throw new Error("Map size exceeds reasonable limit");
	}

	const map: { [key: string | number]: CBORValue } = {};

	let currentOffset = newOffset;
	for (let i = 0; i < numPairs; i++) {
		const [key, keyOffset] = decodeValue(buffer, currentOffset);
		if (typeof key !== "string" && typeof key !== "number") {
			throw new Error("CBOR map keys must be strings or numbers");
		}
		const [value, valueOffset] = decodeValue(buffer, keyOffset);
		map[key] = value;
		currentOffset = valueOffset;
	}

	return [map, currentOffset];
}

/**
 * Major type 6: Tags
 */
function decodeTag(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [{ tag: number; value: CBORValue }, number] {
	const [tag, newOffset] = getLength(dataView, offset, additionalInfo);
	const [value, finalOffset] = decodeValue(buffer, newOffset);
	return [{ tag, value }, finalOffset];
}

/**
 * Major type 7: Floating-point numbers and simple values
 */
function decodeSpecial(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [CBORValue, number] {
	switch (additionalInfo) {
		case CBOR_FLOAT_ADDITIONAL_INFO.FALSE:
			return [false, offset];
		case CBOR_FLOAT_ADDITIONAL_INFO.TRUE:
			return [true, offset];
		case CBOR_FLOAT_ADDITIONAL_INFO.NULL:
			return [null, offset];
		case CBOR_FLOAT_ADDITIONAL_INFO.UNDEFINED:
			return [undefined, offset];
		case CBOR_FLOAT_ADDITIONAL_INFO.HALF_PRECISION: {
			ensureBytes(dataView, offset, 2);
			const halfBits = dataView.getUint16(offset, false);
			return [
				decodeHalfPrecision(new Uint8Array([halfBits >> 8, halfBits & 0xff])),
				offset + 2,
			];
		}
		case CBOR_FLOAT_ADDITIONAL_INFO.SINGLE_PRECISION:
			ensureBytes(dataView, offset, 4);
			return [dataView.getFloat32(offset, false), offset + 4];
		case CBOR_FLOAT_ADDITIONAL_INFO.DOUBLE_PRECISION:
			ensureBytes(dataView, offset, 8);
			return [dataView.getFloat64(offset, false), offset + 8];
		default:
			throw new Error(`Unsupported special value: ${additionalInfo}`);
	}
}

/**
 * Helper function for half-precision decoding
 */
function decodeHalfPrecision(bytes: Uint8Array): number {
	const half = (bytes[0] << 8) + bytes[1];
	const sign = half & 0x8000 ? -1 : 1;
	const exp = (half & 0x7c00) >> 10;
	const mant = half & 0x03ff;
	if (exp === 0) return sign * 2 ** -14 * (mant / 1024);
	if (exp === 31)
		return mant === 0 ? sign * Number.POSITIVE_INFINITY : Number.NaN;
	return sign * 2 ** (exp - 15) * (1 + mant / 1024);
}

/**
 * Reads the length of the CBOR value
 */
function getLength(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) {
		return [additionalInfo, offset];
	}
	if (additionalInfo === CBOR_FLOAT_ADDITIONAL_INFO.SIMPLE_VALUE) {
		ensureBytes(dataView, offset, 1);
		return [dataView.getUint8(offset), offset + 1];
	}
	if (additionalInfo === CBOR_FLOAT_ADDITIONAL_INFO.HALF_PRECISION) {
		ensureBytes(dataView, offset, 2);
		return [dataView.getUint16(offset, false), offset + 2];
	}
	if (additionalInfo === CBOR_FLOAT_ADDITIONAL_INFO.SINGLE_PRECISION) {
		ensureBytes(dataView, offset, 4);
		return [dataView.getUint32(offset, false), offset + 4];
	}
	if (additionalInfo === CBOR_FLOAT_ADDITIONAL_INFO.DOUBLE_PRECISION) {
		ensureBytes(dataView, offset, 8);
		return [Number(dataView.getBigUint64(offset, false)), offset + 8];
	}
	throw new Error("Unsupported CBOR length encoding");
}

/**
 * Ensures that the buffer has enough bytes
 */
function ensureBytes(dataView: DataView, offset: number, length: number): void {
	if (offset + length > dataView.byteLength) {
		throw new Error("Buffer too short for CBOR data");
	}
}
