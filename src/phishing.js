/*
メモ
フィッシング疑いURLの簡易判定

目的
- ブロックではなく「事前警告」を出すためのヒューリスティック判定。
- デモ/教育用途なので、設定で疑わしいドメインやキーワードを追加できる形にする。
*/

const DEFAULT_KEYWORDS = [
	'login',
	'verify',
	'verification',
	'account',
	'secure',
	'security',
	'password',
	'update',
	'confirm',
	'wallet',
	'payment',
	'bank',
];

const DEFAULT_SUSPICIOUS_TLDS = ['zip', 'mov', 'click', 'work', 'top', 'xyz', 'loan', 'tk'];

function normalizeHostname(hostname) {
	return String(hostname || '').toLowerCase().trim().replace(/\.$/, '');
}

function hostnameMatches(hostname, rule) {
	const host = normalizeHostname(hostname);
	const r = normalizeHostname(rule);
	if (!host || !r) return false;
	return host === r || host.endsWith(`.${r}`);
}

function isLocalHostname(hostname) {
	const h = normalizeHostname(hostname);
	if (!h) return true;
	if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true;
	if (/^10\./.test(h)) return true;
	if (/^192\.168\./.test(h)) return true;
	if (/^172\.(1[6-9]|2\d|3[0-1])\./.test(h)) return true;
	return false;
}

function hasManySubdomains(hostname) {
	const parts = normalizeHostname(hostname).split('.').filter(Boolean);
	return parts.length >= 5;
}

function hasSuspiciousTld(hostname, tlds) {
	const parts = normalizeHostname(hostname).split('.').filter(Boolean);
	const tld = parts.length > 0 ? parts[parts.length - 1] : '';
	return tld && tlds.includes(tld);
}

function hasCredentialKeyword(urlText, keywords) {
	const s = String(urlText || '').toLowerCase();
	return keywords.some((kw) => kw && s.includes(String(kw).toLowerCase()));
}

function hasAtSignHostTrick(rawUrl) {
	try {
		const s = String(rawUrl || '');
		const schemeIdx = s.indexOf('://');
		if (schemeIdx < 0) return false;
		const authority = s.slice(schemeIdx + 3).split(/[/?#]/)[0];
		return authority.includes('@');
	} catch {
		return false;
	}
}

function buildPhishingAssessment(rawUrl, config) {
	const phishing = config && config.phishing ? config.phishing : {};
	if (phishing.enabled === false) return { suspicious: false, reasons: [] };

	let parsed;
	try {
		parsed = new URL(String(rawUrl || ''));
	} catch {
		return { suspicious: false, reasons: [] };
	}

	const hostname = normalizeHostname(parsed.hostname);
	if (isLocalHostname(hostname)) return { suspicious: false, reasons: [] };

	const reasons = [];
	const suspiciousDomains = Array.isArray(phishing.suspiciousDomains) ? phishing.suspiciousDomains : [];
	const trustedDomains = Array.isArray(phishing.trustedDomains) ? phishing.trustedDomains : [];
	const keywords = Array.isArray(phishing.keywords) ? phishing.keywords : DEFAULT_KEYWORDS;
	const suspiciousTlds = Array.isArray(phishing.suspiciousTlds) ? phishing.suspiciousTlds : DEFAULT_SUSPICIOUS_TLDS;

	for (const rule of trustedDomains) {
		if (hostnameMatches(hostname, rule)) return { suspicious: false, reasons: [] };
	}

	for (const rule of suspiciousDomains) {
		if (hostnameMatches(hostname, rule)) reasons.push(`suspicious domain: ${rule}`);
	}
	if (hasCredentialKeyword(parsed.pathname + parsed.search, keywords)) {
		reasons.push('credential/payment related keyword in URL');
	}
	if (hasAtSignHostTrick(String(rawUrl))) {
		reasons.push('URL contains @ in authority');
	}
	if (hostname.startsWith('xn--')) {
		reasons.push('punycode hostname');
	}
	if (hasManySubdomains(hostname)) {
		reasons.push('many subdomains');
	}
	if (hasSuspiciousTld(hostname, suspiciousTlds)) {
		reasons.push('suspicious top-level domain');
	}

	const requireKeywordWithHeuristics = phishing.requireKeywordWithHeuristics !== false;
	const matchedConfiguredDomain = reasons.some((r) => r.startsWith('suspicious domain:'));
	if (requireKeywordWithHeuristics && !matchedConfiguredDomain) {
		const hasKeyword = reasons.includes('credential/payment related keyword in URL');
		const hasOtherHeuristic = reasons.some((r) => r !== 'credential/payment related keyword in URL');
		if (!hasKeyword || !hasOtherHeuristic) return { suspicious: false, reasons: [] };
	}

	return {
		suspicious: reasons.length > 0,
		reasons,
	};
}

module.exports = {
	buildPhishingAssessment,
};
