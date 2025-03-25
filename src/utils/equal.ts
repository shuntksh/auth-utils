/**
 * Constant-time comparison of two Uint8Arrays or strings
 */
export function constantTimeEqual(a: string, b: string): boolean {
	if (typeof a === "string" && typeof b === "string") {
		if (a.length !== b.length) return false;
		let result = 0;
		for (let i = 0; i < a.length; i++) {
			result |= a.charCodeAt(i) ^ b.charCodeAt(i);
		}
		return result === 0;
	}
	throw new Error("Invalid input");
}
