/**
 * Verifies that the origin of a request is in the list of allowed domains to
 * ensure that the request is coming from a trusted source for CSRF protection.
 */
export function verifyRequestOrigin(
	origin: string,
	allowedDomains: string[],
): boolean {
	// If the origin is missing or the list of allowed domains is empty, deny the request
	if (!origin || allowedDomains.length === 0) return false;
	const originHost = parseURL(origin)?.host ?? null;

	// If the origin host is missing or not a valid URL, deny the request
	if (!originHost) return false;

	// Check if the origin host is in the list of allowed domains
	for (const domain of allowedDomains) {
		let host: string | null;
		if (domain.startsWith("http://") || domain.startsWith("https://")) {
			host = parseURL(domain)?.host ?? null;
		} else {
			host = parseURL(`https://${domain}`)?.host ?? null;
		}
		if (originHost === host) return true;
	}
	return false;
}

function parseURL(url: URL | string): URL | null {
	try {
		return new URL(url);
	} catch {
		return null;
	}
}
