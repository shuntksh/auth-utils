/**
 * Constant-time comparison of two Uint8Arrays or strings
 */
export function constantTimeEqual(a: ArrayBuffer, b: ArrayBuffer): boolean;
export function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean;
export function constantTimeEqual(a: string, b: string): boolean;
export function constantTimeEqual(
	a: ArrayBuffer | string | Uint8Array,
	b: ArrayBuffer | string | Uint8Array,
): boolean {
	let result = 0;
	if (
		(a instanceof ArrayBuffer && b instanceof ArrayBuffer) ||
		(a instanceof Uint8Array && b instanceof Uint8Array)
	) {
		const bytes1 = new Uint8Array(a);
		const bytes2 = new Uint8Array(b);
		if (bytes1.byteLength !== bytes2.byteLength) return false;
		for (let i = 0; i < bytes1.byteLength; i++) {
			result |= bytes1[i] ^ bytes2[i];
		}
		return result === 0;
	}

	if (typeof a === "string" && typeof b === "string") {
		if (a.length !== b.length) return false;
		for (let i = 0; i < a.length; i++) {
			result |= a.charCodeAt(i) ^ b.charCodeAt(i);
		}
		return result === 0;
	}

	throw new Error("Invalid input");
}
