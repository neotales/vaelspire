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

// --- Passkey (WebAuthn) APIs ---

export async function passkeyRegisterBegin(rpId: string, origin: string): Promise<Record<string, unknown>> {
	return requestJson('/passkey/register/begin', {
		method: 'POST',
		body: JSON.stringify({ rp_id: rpId, origin })
	}, true);
}

export async function passkeyRegisterFinish(
	rpId: string,
	origin: string,
	credential: Record<string, unknown>
): Promise<void> {
	await requestJson('/passkey/register/finish', {
		method: 'POST',
		body: JSON.stringify({ rp_id: rpId, origin, credential })
	}, true);
}

export async function passkeyLoginBegin(
	email: string,
	rpId: string,
	origin: string
): Promise<Record<string, unknown>> {
	return requestJson('/passkey/login/begin', {
		method: 'POST',
		body: JSON.stringify({ email, rp_id: rpId, origin })
	}, true);
}

export async function passkeyLoginFinish(
	rpId: string,
	origin: string,
	credential: Record<string, unknown>
): Promise<unknown> {
	return requestJson('/passkey/login/finish', {
		method: 'POST',
		body: JSON.stringify({ rp_id: rpId, origin, credential })
	}, true);
}

// --- GDPR Export & Erasure ---

export async function exportOwnGdprData(): Promise<Record<string, unknown>> {
	return requestJson('/account/export');
}

export async function eraseOwnAccount(): Promise<void> {
	await requestJson('/account/erase', { method: 'DELETE' }, true);
}

// --- Self-Service Org Policy, Domains, IdP, SCIM Tokens & Home Realm Discovery ---

export interface OrgPolicy {
	email_policy: 'allow_public' | 'business_domains_only' | 'verified_domains_only';
	session_sliding: boolean;
	session_idle_secs: number;
	session_absolute_secs: number;
	break_glass_enabled: boolean;
}

export interface OrgDomain {
	id: string;
	domain: string;
	txt_record_name: string;
	verification_token: string;
	verified: boolean;
	verified_at?: string | null;
}

export interface OrgIdp {
	id: string;
	name: string;
	protocol: string;
	issuer_url: string;
	client_id: string;
	has_client_secret: boolean;
	has_metadata_xml: boolean;
	jit_provisioning: boolean;
	default_role: string;
	group_claim: string;
	enabled: boolean;
}

export async function discoverHomeRealm(email: string): Promise<{
	mode: 'sso' | 'local';
	domain_verified: boolean;
	email_policy: string;
	allowed: boolean;
	reason?: string;
	break_glass_enabled: boolean;
	idp?: { id: string; name: string; protocol: string; issuer_url: string };
}> {
	return requestJson('/auth/discover', {
		method: 'POST',
		body: JSON.stringify({ email })
	});
}

export async function getOrgPolicy(): Promise<OrgPolicy> {
	return requestJson('/org/portal/policy');
}

export async function updateOrgPolicy(policy: OrgPolicy): Promise<OrgPolicy> {
	return requestJson('/org/portal/policy', {
		method: 'PUT',
		body: JSON.stringify(policy)
	}, true);
}

export async function listOrgDomains(): Promise<OrgDomain[]> {
	const res = await requestJson<{ domains: OrgDomain[] }>('/org/portal/domains');
	return res.domains ?? [];
}

export async function addOrgDomain(domain: string): Promise<OrgDomain> {
	return requestJson('/org/portal/domains', {
		method: 'POST',
		body: JSON.stringify({ domain })
	}, true);
}

export async function verifyOrgDomain(id: string, txtValue?: string): Promise<OrgDomain> {
	return requestJson(`/org/portal/domains/${encodeURIComponent(id)}/verify`, {
		method: 'POST',
		body: JSON.stringify(txtValue ? { txt_value: txtValue } : {})
	}, true);
}

export async function listOrgIdps(): Promise<OrgIdp[]> {
	const res = await requestJson<{ idps: OrgIdp[] }>('/org/portal/idps');
	return res.idps ?? [];
}

export async function createOrgIdp(payload: {
	name: string;
	protocol: 'oidc' | 'saml';
	issuer_url: string;
	client_id: string;
	client_secret: string;
	metadata_xml: string;
	jit_provisioning: boolean;
	default_role: string;
	group_claim: string;
	enabled: boolean;
}): Promise<OrgIdp> {
	return requestJson('/org/portal/idps', {
		method: 'POST',
		body: JSON.stringify(payload)
	}, true);
}

export async function testOrgIdp(id: string): Promise<{ ok: boolean; checks: Array<{ check: string; ok: boolean }> }> {
	return requestJson(`/org/portal/idps/${encodeURIComponent(id)}/test`, { method: 'POST' }, true);
}

export async function deleteOrgIdp(id: string): Promise<void> {
	await requestJson(`/org/portal/idps/${encodeURIComponent(id)}`, { method: 'DELETE' }, true);
}

export async function createScimToken(name: string): Promise<{ id: string; name: string; token: string }> {
	return requestJson('/org/portal/scim-tokens', {
		method: 'POST',
		body: JSON.stringify({ name })
	}, true);
}

// --- Org-Wide & Per-App RBAC ---

export interface AppRole {
	id: string;
	app_id?: string | null;
	name: string;
	description: string;
}

export interface AppPermission {
	id: string;
	app_id?: string | null;
	name: string;
	description: string;
}

export interface RbacGroup {
	id: string;
	name: string;
	external_id?: string | null;
}

export async function listRbacRoles(): Promise<AppRole[]> {
	const res = await requestJson<{ roles: AppRole[] }>('/admin/rbac/roles');
	return res.roles ?? [];
}

export async function createRbacRole(name: string, appId?: string, description = ''): Promise<AppRole> {
	return requestJson('/admin/rbac/roles', {
		method: 'POST',
		body: JSON.stringify({ name, app_id: appId || null, description })
	}, true);
}

export async function listRbacPermissions(): Promise<AppPermission[]> {
	const res = await requestJson<{ permissions: AppPermission[] }>('/admin/rbac/permissions');
	return res.permissions ?? [];
}

export async function createRbacPermission(name: string, appId?: string, description = ''): Promise<AppPermission> {
	return requestJson('/admin/rbac/permissions', {
		method: 'POST',
		body: JSON.stringify({ name, app_id: appId || null, description })
	}, true);
}

export async function grantPermissionToRole(roleId: string, permId: string): Promise<void> {
	await requestJson(`/admin/rbac/roles/${encodeURIComponent(roleId)}/permissions/${encodeURIComponent(permId)}`, {
		method: 'POST'
	}, true);
}

export async function listRbacGroups(): Promise<RbacGroup[]> {
	const res = await requestJson<{ groups: RbacGroup[] }>('/admin/rbac/groups');
	return res.groups ?? [];
}

export async function createRbacGroup(name: string, externalId?: string): Promise<RbacGroup> {
	return requestJson('/admin/rbac/groups', {
		method: 'POST',
		body: JSON.stringify({ name, external_id: externalId || null })
	}, true);
}

export async function assignRoleToGroup(groupId: string, roleId: string): Promise<void> {
	await requestJson(`/admin/rbac/groups/${encodeURIComponent(groupId)}/roles/${encodeURIComponent(roleId)}`, {
		method: 'POST'
	}, true);
}

export async function getEffectiveAccess(userId: string, appId?: string): Promise<{
	groups: string[];
	roles: string[];
	permissions: string[];
}> {
	const qs = appId ? `?app_id=${encodeURIComponent(appId)}` : '';
	return requestJson(`/admin/rbac/users/${encodeURIComponent(userId)}/effective${qs}`);
}
