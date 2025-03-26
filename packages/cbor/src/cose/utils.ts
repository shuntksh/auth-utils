import type { CBORValue, HeaderMap } from "../types";
import { COSEAlgorithm, COSEHeader } from "../types";

export function validateProtectedHeader(header: HeaderMap): void {
	if (!(COSEHeader.alg in header)) {
		throw new Error("Protected header must contain 'alg' parameter");
	}
	const alg = header[COSEHeader.alg];
	if (typeof alg !== "number" || !(alg in COSEAlgorithm)) {
		throw new Error("Invalid or unsupported algorithm in protected header");
	}
}

export function ensureArrayBuffer(value: CBORValue): ArrayBuffer {
	if (!(value instanceof ArrayBuffer)) {
		throw new Error("Expected ArrayBuffer");
	}
	return value;
}
