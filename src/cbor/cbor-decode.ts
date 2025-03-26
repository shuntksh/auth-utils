import type { CBORValue } from "./types";

export function decodeFirstItem(
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
