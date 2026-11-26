export interface DiscoveryDoc {
	service: string;
	edition: string;
	version: string;
	issuer: string;
	tenant_id: string;
	ui_mode: string;
	cookies: {
		session: string;
		csrf: string;
	};
	endpoints: Record<string, string>;
}

export interface SessionInfo {
	id: string;
	user_id: string;
	tenant_id: string;
	expires_at: string;
	created_at?: string;
}

export interface ApiKeyInfo {
	id: string;
	name?: string;
	prefix?: string;
	scopes?: string[];
	created_at?: string;
	expires_at?: string | null;
}

export interface OidcClientSummary {
	client_id: string;
	name: string;
	confidential: boolean;
	redirect_uris: string[];
	allowed_scopes: string[];
	require_pkce: boolean;
}

export interface ScimUser {
	id: string;
	userName: string;
	active: boolean;
	emails?: Array<{ value: string; primary?: boolean }>;
}

export interface MetricsSummary {
	http2xx: number;
	http4xx: number;
	http5xx: number;
	forwardAuthAllow: number;
	forwardAuthDeny: number;
	raw: string;
}

let cachedCsrfCookieName = 'neotales.csrf';

export function readCookie(name: string): string | null {
	if (typeof document === 'undefined') return null;
	const parts = document.cookie.split(';');
	for (const part of parts) {
		const idx = part.indexOf('=');
		if (idx === -1) continue;
		const k = part.slice(0, idx).trim();
		if (k === name) {
			return decodeURIComponent(part.slice(idx + 1).trim());
		}
	}
	return null;
}

async function ensureCsrfToken(): Promise<string | null> {
	let token = readCookie(cachedCsrfCookieName);
	if (token) return token;
	// GET /session sets the CSRF cookie if absent even when unauthenticated.
	await fetch('/session', { credentials: 'same-origin' }).catch(() => {});
	token = readCookie(cachedCsrfCookieName);
	return token;
}

async function requestJson<T>(
	path: string,
	init: RequestInit = {},
	requireCsrf = false
): Promise<T> {
	const headers = new Headers(init.headers ?? {});
	if (init.body && !headers.has('content-type')) {
		headers.set('content-type', 'application/json');
	}
	if (requireCsrf) {
		const csrf = await ensureCsrfToken();
		if (csrf) {
			headers.set('x-csrf-token', csrf);
		}
	}
	const res = await fetch(path, {
		...init,
		headers,
		credentials: 'same-origin'
	});
	const text = await res.text();
	let data: unknown = null;
	if (text) {
		try {
			data = JSON.parse(text);
		} catch {
			data = text;
		}
	}
	if (!res.ok) {
		const errMsg =
			typeof data === 'object' && data !== null && 'error' in data
				? String((data as { error: unknown }).error)
				: typeof data === 'object' && data !== null && 'detail' in data
					? String((data as { detail: unknown }).detail)
					: `HTTP ${res.status}`;
		throw new Error(errMsg);
	}
	return data as T;
}

export async function getDiscovery(): Promise<DiscoveryDoc> {
	const doc = await requestJson<DiscoveryDoc>('/.well-known/vaelspire');
	if (doc.cookies?.csrf) {
		cachedCsrfCookieName = doc.cookies.csrf;
	}
	return doc;
}

export async function getHealth(): Promise<{ status: string; version: string; edition: string }> {
	return requestJson('/health');
}

export async function getReady(): Promise<{ status: string; store: string; tenant_id?: string }> {
	return requestJson('/ready');
}

export async function getMetrics(): Promise<MetricsSummary> {
	const res = await fetch('/metrics', { credentials: 'same-origin' });
	const raw = await res.text();
	const parseCounter = (pattern: RegExp): number => {
		let sum = 0;
		for (const line of raw.split('\n')) {
			if (line.startsWith('#')) continue;
			const m = line.match(pattern);
			if (m) {
				sum += Number(m[1]) || 0;
			}
		}
		return sum;
	};
	return {
		http2xx: parseCounter(/^vaelspire_http_responses_total\{class="2xx"\}\s+(\d+)/),
		http4xx: parseCounter(/^vaelspire_http_responses_total\{class="4xx"\}\s+(\d+)/),
		http5xx: parseCounter(/^vaelspire_http_responses_total\{class="5xx"\}\s+(\d+)/),
		forwardAuthAllow: parseCounter(
			/^vaelspire_forward_auth_total\{outcome="allow"[^}]*\}\s+(\d+)/
		),
		forwardAuthDeny: parseCounter(
			/^vaelspire_forward_auth_total\{outcome="deny"[^}]*\}\s+(\d+)/
		),
		raw
	};
}

export async function getCurrentSession(): Promise<SessionInfo | null> {
	const res = await fetch('/session', { credentials: 'same-origin' });
	if (res.status === 401 || res.status === 404) return null;
	if (!res.ok) return null;
	return (await res.json()) as SessionInfo;
}

export async function signUp(email: string, password: string): Promise<unknown> {
	return requestJson(
		'/sign-up',
		{
			method: 'POST',
			body: JSON.stringify({ email, password })
		},
		true
	);
}

export async function signIn(email: string, password: string): Promise<unknown> {
	return requestJson(
		'/sign-in',
		{
			method: 'POST',
			body: JSON.stringify({ email, password })
		},
		true
	);
}

export async function signOut(): Promise<void> {
	await requestJson('/sign-out', { method: 'POST' }, true);
}

export async function listSessions(): Promise<SessionInfo[]> {
	const res = await requestJson<SessionInfo[] | { sessions: SessionInfo[] }>('/sessions');
	return Array.isArray(res) ? res : (res.sessions ?? []);
}

export async function revokeSession(id: string): Promise<void> {
	await requestJson(`/sessions/${encodeURIComponent(id)}`, { method: 'DELETE' }, true);
}

export async function listApiKeys(): Promise<ApiKeyInfo[]> {
	const res = await requestJson<ApiKeyInfo[] | { api_keys: ApiKeyInfo[]; keys?: ApiKeyInfo[] }>(
		'/api-keys'
	);
	if (Array.isArray(res)) return res;
	return res.api_keys ?? res.keys ?? [];
}

export async function createApiKey(
	name: string,
	scopes: string[]
): Promise<{ id?: string; token?: string; key?: string; secret?: string }> {
	return requestJson(
		'/api-keys',
		{
			method: 'POST',
			body: JSON.stringify({ name, scopes })
		},
		true
	);
}

export async function revokeApiKey(id: string): Promise<void> {
	await requestJson(`/api-keys/${encodeURIComponent(id)}`, { method: 'DELETE' }, true);
}

export async function listOidcClients(): Promise<OidcClientSummary[]> {
	const res = await requestJson<{ clients: OidcClientSummary[] }>('/admin/oidc/clients');
	return res.clients ?? [];
}

export async function createOidcClient(payload: {
	client_id: string;
	name: string;
	confidential: boolean;
	redirect_uris: string[];
	allowed_scopes: string[];
}): Promise<{
	client_id: string;
	name: string;
	confidential: boolean;
	redirect_uris: string[];
	allowed_scopes: string[];
	client_secret?: string | null;
}> {
	return requestJson(
		'/admin/oidc/clients',
		{
			method: 'POST',
			body: JSON.stringify(payload)
		},
		true
	);
}

export async function listScimUsers(): Promise<ScimUser[]> {
	const res = await requestJson<{ Resources: ScimUser[] }>('/scim/v2/Users');
	return res.Resources ?? [];
}

export async function createScimUser(email: string, password: string): Promise<ScimUser> {
	return requestJson(
		'/scim/v2/Users',
		{
			method: 'POST',
			body: JSON.stringify({
				userName: email,
				password,
				active: true
			})
		},
		true
	);
}

export async function deleteScimUser(id: string): Promise<void> {
	await requestJson(`/scim/v2/Users/${encodeURIComponent(id)}`, { method: 'DELETE' }, true);
}
