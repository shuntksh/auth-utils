import type { CBORValue } from "./types";

export function encodeValue(value: CBORValue, buffers: Uint8Array[]): void {
	if (typeof value === "number") {
		if (Number.isInteger(value)) {
			if (value >= 0) {
				encodeUnsignedInteger(value, buffers);
			} else {
				encodeNegativeInteger(value, buffers);
			}
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
