export type CBORValue =
	| number
	| ArrayBuffer
	| string
	| CBORValue[]
	| { [key: string | number]: CBORValue }
	| { tag: number; value: CBORValue }
	| boolean
	| null
	| undefined;

/**
 * Concatenates an array of ArrayBuffers into a single ArrayBuffer
 * @param buffers - Array of ArrayBuffers to concatenate
 * @returns Concatenated ArrayBuffer
 */
function concatenateBuffers(
	buffers: ArrayBuffer[] | Uint8Array[],
): ArrayBuffer {
	const totalLength = buffers.reduce(
		(sum, buffer) => sum + buffer.byteLength,
		0,
	);
	const result = new Uint8Array(totalLength);
	let offset = 0;
	for (const buffer of buffers) {
		result.set(new Uint8Array(buffer), offset);
		offset += buffer.byteLength;
	}
	return result.buffer;
}

/**
 * RFC 8949: Concise Binary Object Representation (CBOR)
 */
export const CBOR = {
	encode,
	decode,
	decodeWithOffset,
	decodeMapToMap,
} as const;

const MAX_BUFFER_SIZE = 16 * 1024 * 1024;

function decode(buffer: ArrayBuffer): CBORValue {
	if (buffer.byteLength > MAX_BUFFER_SIZE) {
		throw new Error(`Buffer exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`);
	}
	const [value] = decodeFirstItem(buffer, 0);
	return value;
}

function encode(value: CBORValue): ArrayBuffer {
	const buffers: Uint8Array[] = [];
	encodeValue(value, buffers);
	const totalLength = buffers.reduce((sum, buf) => sum + buf.byteLength, 0);
	if (totalLength > MAX_BUFFER_SIZE) {
		throw new Error(
			`Encoded data exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`,
		);
	}
	return concatenateBuffers(buffers);
}

/**
 * Decodes a CBOR buffer and returns the value along with the number of bytes consumed.
 * Useful for parsing concatenated CBOR data (e.g., COSE key followed by extensions in WebAuthn).
 *
 * @param buffer - The buffer to decode.
 * @param startOffset - The offset to start decoding from.
 * @returns The decoded value and the number of bytes consumed.
 */
function decodeWithOffset(
	buffer: ArrayBuffer,
	startOffset = 0,
): [CBORValue, number] {
	if (buffer.byteLength > MAX_BUFFER_SIZE) {
		throw new Error(`Buffer exceeds maximum size of ${MAX_BUFFER_SIZE} bytes`);
	}
	const [value, newOffset] = decodeFirstItem(buffer, startOffset);
	return [value, newOffset - startOffset];
}

/**
 * Decodes a CBOR map directly into a JavaScript Map with specified key/value types.
 * Tailored for WebAuthn COSE keys (numeric keys, number/ArrayBuffer values).
 *
 * @param buffer - The buffer to decode.
 * @param startOffset - The offset to start decoding from.
 * @param keyValidator - The validator for the keys.
 * @param valueValidator - The validator for the values.
 * @returns The decoded map.
 */
function decodeMapToMap<K extends string | number, V extends CBORValue>(
	buffer: ArrayBuffer,
	startOffset = 0,
	keyValidator: (key: string | number) => key is K = (key): key is K => true,
	valueValidator: (value: CBORValue) => value is V = (value): value is V =>
		true,
): [Map<K, V>, number] {
	const [obj, newOffset] = decodeFirstItem(buffer, startOffset);
	if (
		typeof obj !== "object" ||
		obj === null ||
		"tag" in obj ||
		Array.isArray(obj)
	) {
		throw new Error("Expected CBOR map");
	}
	const map = new Map<K, V>();
	for (const [key, value] of Object.entries(obj)) {
		const parsedKey =
			Number(key) === Number.parseInt(key, 10) ? Number(key) : key;
		if (!keyValidator(parsedKey)) {
			throw new Error(`Invalid map key: ${parsedKey}`);
		}
		if (!valueValidator(value)) {
			throw new Error(`Invalid map value for key ${parsedKey}: ${value}`);
		}
		map.set(parsedKey as K, value as V);
	}
	return [map, newOffset - startOffset];
}

// --- Decoding Helpers ---

function decodeFirstItem(
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
		case 0:
			return decodeUnsignedInteger(dataView, offset, additionalInfo);
		case 1:
			return decodeNegativeInteger(dataView, offset, additionalInfo);
		case 2:
			return decodeByteString(buffer, dataView, offset, additionalInfo);
		case 3:
			return decodeTextString(buffer, dataView, offset, additionalInfo);
		case 4:
			return decodeArray(buffer, dataView, offset, additionalInfo);
		case 5:
			return decodeMap(buffer, dataView, offset, additionalInfo);
		case 6:
			return decodeTag(buffer, dataView, offset, additionalInfo);
		case 7:
			return decodeSpecial(dataView, offset, additionalInfo);
		default:
			throw new Error(`Unsupported CBOR major type: ${majorType}`);
	}
}

function decodeUnsignedInteger(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) return [additionalInfo, offset];
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

function decodeNegativeInteger(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) return [-1 - additionalInfo, offset];
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

function decodeByteString(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [ArrayBuffer, number] {
	const [length, newOffset] = readLength(dataView, offset, additionalInfo);
	ensureBytes(dataView, newOffset, length);
	return [buffer.slice(newOffset, newOffset + length), newOffset + length];
}

function decodeTextString(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [string, number] {
	const [length, newOffset] = readLength(dataView, offset, additionalInfo);
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

function decodeArray(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [CBORValue[], number] {
	const [length, newOffset] = readLength(dataView, offset, additionalInfo);
	if (length > 10000) throw new Error("Array length exceeds reasonable limit");
	const array: CBORValue[] = [];
	let currentOffset = newOffset;
	for (let i = 0; i < length; i++) {
		const [item, nextOffset] = decodeFirstItem(buffer, currentOffset);
		array.push(item);
		currentOffset = nextOffset;
	}
	return [array, currentOffset];
}

function decodeMap(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [{ [key: string | number]: CBORValue }, number] {
	const [numPairs, newOffset] = readLength(dataView, offset, additionalInfo);
	if (numPairs > 10000) throw new Error("Map size exceeds reasonable limit");
	const map: { [key: string | number]: CBORValue } = {};
	let currentOffset = newOffset;
	for (let i = 0; i < numPairs; i++) {
		const [key, keyOffset] = decodeFirstItem(buffer, currentOffset);
		if (typeof key !== "string" && typeof key !== "number") {
			throw new Error("CBOR map keys must be strings or numbers");
		}
		const [value, valueOffset] = decodeFirstItem(buffer, keyOffset);
		map[key] = value;
		currentOffset = valueOffset;
	}
	return [map, currentOffset];
}

function decodeTag(
	buffer: ArrayBuffer,
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [{ tag: number; value: CBORValue }, number] {
	const [tag, newOffset] = readLength(dataView, offset, additionalInfo);
	const [value, finalOffset] = decodeFirstItem(buffer, newOffset);
	return [{ tag, value }, finalOffset];
}

function decodeSpecial(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [CBORValue, number] {
	switch (additionalInfo) {
		case 20:
			return [false, offset];
		case 21:
			return [true, offset];
		case 22:
			return [null, offset];
		case 23:
			return [undefined, offset];
		case 25:
			ensureBytes(dataView, offset, 2);
			return [dataView.getFloat32(offset, false), offset + 2];
		case 26:
			ensureBytes(dataView, offset, 4);
			return [dataView.getFloat32(offset, false), offset + 4];
		case 27:
			ensureBytes(dataView, offset, 8);
			return [dataView.getFloat64(offset, false), offset + 8];
		default:
			throw new Error(`Unsupported special value: ${additionalInfo}`);
	}
}

function readLength(
	dataView: DataView,
	offset: number,
	additionalInfo: number,
): [number, number] {
	if (additionalInfo <= 23) return [additionalInfo, offset];
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
	throw new Error("Unsupported CBOR length encoding");
}

function ensureBytes(dataView: DataView, offset: number, length: number): void {
	if (offset + length > dataView.byteLength) {
		throw new Error("Buffer too short for CBOR data");
	}
}

// --- Encoding Helpers ---

function encodeValue(value: CBORValue, buffers: Uint8Array[]): void {
	if (typeof value === "number") {
		if (Number.isInteger(value)) {
			if (value >= 0) encodeUnsignedInteger(value, buffers);
			else encodeNegativeInteger(value, buffers);
		} else {
			encodeFloat(value, buffers);
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

function encodeUnsignedInteger(value: number, buffers: Uint8Array[]): void {
	if (value < 0 || !Number.isInteger(value)) {
		throw new Error("Only unsigned integers are supported");
	}
	if (value <= 23) {
		buffers.push(new Uint8Array([value]));
	} else if (value <= 0xff) {
		buffers.push(new Uint8Array([0x18, value]));
	} else if (value <= 0xffff) {
		const buffer = new Uint8Array(3);
		buffer[0] = 0x19;
		new DataView(buffer.buffer).setUint16(1, value, false);
		buffers.push(buffer);
	} else if (value <= 0xffffffff) {
		const buffer = new Uint8Array(5);
		buffer[0] = 0x1a;
		new DataView(buffer.buffer).setUint32(1, value, false);
		buffers.push(buffer);
	} else if (value <= Number.MAX_SAFE_INTEGER) {
		const buffer = new Uint8Array(9);
		buffer[0] = 0x1b;
		new DataView(buffer.buffer).setBigUint64(1, BigInt(value), false);
		buffers.push(buffer);
	} else {
		throw new Error("Integer value too large for CBOR encoding");
	}
}

function encodeNegativeInteger(value: number, buffers: Uint8Array[]): void {
	if (!Number.isInteger(value) || value >= 0) {
		throw new Error("Only negative integers are supported");
	}
	const absValue = Math.abs(value) - 1;
	if (absValue <= 23) {
		buffers.push(new Uint8Array([0x20 | absValue]));
	} else if (absValue <= 0xff) {
		buffers.push(new Uint8Array([0x38, absValue]));
	} else if (absValue <= 0xffff) {
		const buffer = new Uint8Array(3);
		buffer[0] = 0x39;
		new DataView(buffer.buffer).setUint16(1, absValue, false);
		buffers.push(buffer);
	} else if (absValue <= 0xffffffff) {
		const buffer = new Uint8Array(5);
		buffer[0] = 0x3a;
		new DataView(buffer.buffer).setUint32(1, absValue, false);
		buffers.push(buffer);
	} else if (absValue <= Number.MAX_SAFE_INTEGER) {
		const buffer = new Uint8Array(9);
		buffer[0] = 0x3b;
		new DataView(buffer.buffer).setBigUint64(1, BigInt(absValue), false);
		buffers.push(buffer);
	} else {
		throw new Error("Integer value too large for CBOR encoding");
	}
}

function encodeByteString(value: ArrayBuffer, buffers: Uint8Array[]): void {
	const length = value.byteLength;
	const header = encodeLength(2, length);
	buffers.push(header);
	buffers.push(new Uint8Array(value));
}

function encodeTextString(value: string, buffers: Uint8Array[]): void {
	const bytes = new TextEncoder().encode(value);
	const header = encodeLength(3, bytes.length);
	buffers.push(header);
	buffers.push(bytes);
}

function encodeArray(value: CBORValue[], buffers: Uint8Array[]): void {
	if (value.length > 10000)
		throw new Error("Array length exceeds reasonable limit");
	const header = encodeLength(4, value.length);
	buffers.push(header);
	for (const item of value) {
		encodeValue(item, buffers);
	}
}

function encodeMap(
	value: { [key: string | number]: CBORValue },
	buffers: Uint8Array[],
): void {
	const entries = Object.entries(value);
	if (entries.length > 10000)
		throw new Error("Map size exceeds reasonable limit");
	entries.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
	const header = encodeLength(5, entries.length);
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

function encodeTag(tag: number, value: CBORValue, buffers: Uint8Array[]): void {
	if (!Number.isInteger(tag) || tag < 0) {
		throw new Error("Tag must be a non-negative integer");
	}
	const header = encodeLength(6, tag);
	buffers.push(header);
	encodeValue(value, buffers);
}

function encodeFloat(value: number, buffers: Uint8Array[]): void {
	const buffer = new Uint8Array(9);
	buffer[0] = 0xfb;
	new DataView(buffer.buffer).setFloat64(1, value, false);
	buffers.push(buffer.slice(0, 9));
}

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
	throw new Error("Length too large for CBOR encoding");
}

function encodeBoolean(value: boolean, buffers: Uint8Array[]): void {
	buffers.push(new Uint8Array([value ? 0xf5 : 0xf4]));
}

function encodeNull(buffers: Uint8Array[]): void {
	buffers.push(new Uint8Array([0xf6]));
}

function encodeUndefined(buffers: Uint8Array[]): void {
	buffers.push(new Uint8Array([0xf7]));
}
