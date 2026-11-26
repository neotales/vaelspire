<script lang="ts">
	import { base } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		createOidcClient,
		createScimUser,
		deleteScimUser,
		getCurrentSession,
		getMetrics,
		listOidcClients,
		listScimUsers,
		type MetricsSummary,
		type OidcClientSummary,
		type ScimUser,
		type SessionInfo
	} from '$lib/api';

	let session = $state<SessionInfo | null>(null);
	let metrics = $state<MetricsSummary | null>(null);
	let clients = $state<OidcClientSummary[]>([]);
	let users = $state<ScimUser[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	// New OIDC client form
	let clientId = $state('vaelsgard');
	let clientName = $state('Vaelsgard App');
	let clientKind = $state<'confidential' | 'public'>('confidential');
	let redirectUri = $state('https://vaelsgard.local/auth/callback');
	let scopesText = $state('openid email profile offline_access');
	let requirePkce = $state(true);
	let issuedSecret = $state<{ clientId: string; secret: string } | null>(null);
	let creatingClient = $state(false);

	// New SCIM user form
	let scimEmail = $state('');
	let scimPassword = $state('');
	let creatingUser = $state(false);

	async function loadAdmin() {
		loading = true;
		error = null;
		try {
			const [s, m] = await Promise.all([getCurrentSession(), getMetrics()]);
			session = s;
			metrics = m;
			if (s) {
				const [c, u] = await Promise.all([listOidcClients(), listScimUsers()]);
				clients = c;
				users = u;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load admin console';
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadAdmin();
	});

	async function handleCreateClient(event: SubmitEvent) {
		event.preventDefault();
		creatingClient = true;
		error = null;
		issuedSecret = null;
		try {
			const res = await createOidcClient({
				client_id: clientId.trim(),
				name: clientName.trim(),
				confidential: clientKind === 'confidential',
				redirect_uris: redirectUri
					.split(',')
					.map((u) => u.trim())
					.filter(Boolean),
				allowed_scopes: scopesText
					.split(/\s+/)
					.map((s) => s.trim())
					.filter(Boolean)
			});
			if (res.client_secret) {
				issuedSecret = { clientId: res.client_id, secret: res.client_secret };
			}
			await loadAdmin();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to register OIDC client';
		} finally {
			creatingClient = false;
		}
	}

	async function handleCreateScimUser(event: SubmitEvent) {
		event.preventDefault();
		creatingUser = true;
		error = null;
		try {
			await createScimUser(scimEmail.trim(), scimPassword);
			scimEmail = '';
			scimPassword = '';
			await loadAdmin();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to provision SCIM user';
		} finally {
			creatingUser = false;
		}
	}

	async function handleDeleteUser(id: string) {
		try {
			await deleteScimUser(id);
			await loadAdmin();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to deactivate user';
		}
	}
</script>

<div class="space-y-8">
	<div class="flex flex-wrap items-center justify-between gap-4">
		<div>
			<h1 class="text-2xl font-bold text-[#fafaf9]">Core Admin Console</h1>
			<p class="text-sm text-[#a8a29e]">
				Live Prometheus telemetry, OIDC 1.0 client registry, and SCIM 2.0 user provisioning.
			</p>
		</div>
		<button type="button" onclick={loadAdmin} class="vs-btn-secondary text-xs">Refresh Data</button>
	</div>

	{#if error}
		<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/12 px-4 py-3 text-sm text-[#fca5a5]">
			{error}
		</div>
	{/if}

	{#if metrics}
		<section class="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
			<div class="vs-card p-4">
				<div class="text-[11px] uppercase tracking-wider text-[#a8a29e]">HTTP 2xx</div>
				<div class="mt-1 text-2xl font-bold text-[#6ee7b7]">{metrics.http2xx}</div>
			</div>
			<div class="vs-card p-4">
				<div class="text-[11px] uppercase tracking-wider text-[#a8a29e]">HTTP 4xx</div>
				<div class="mt-1 text-2xl font-bold text-[#fbbf24]">{metrics.http4xx}</div>
			</div>
			<div class="vs-card p-4">
				<div class="text-[11px] uppercase tracking-wider text-[#a8a29e]">HTTP 5xx</div>
				<div class="mt-1 text-2xl font-bold text-[#fca5a5]">{metrics.http5xx}</div>
			</div>
			<div class="vs-card p-4">
				<div class="text-[11px] uppercase tracking-wider text-[#a8a29e]">Forward-Auth Allow</div>
				<div class="mt-1 text-2xl font-bold text-[#6ee7b7]">{metrics.forwardAuthAllow}</div>
			</div>
			<div class="vs-card p-4">
				<div class="text-[11px] uppercase tracking-wider text-[#a8a29e]">Forward-Auth Deny</div>
				<div class="mt-1 text-2xl font-bold text-[#fca5a5]">{metrics.forwardAuthDeny}</div>
			</div>
		</section>
	{/if}

	{#if loading}
		<div class="vs-card p-6 text-sm text-[#a8a29e]">Loading admin data...</div>
	{:else if !session}
		<div class="vs-card p-6 space-y-3">
			<p class="text-sm text-[#d6d3d1]">
				Sign in with an administrator account (or API key) to manage OIDC clients and SCIM 2.0 users.
			</p>
			<a href="{base}/login?next={encodeURIComponent(`${base}/admin`)}" class="vs-btn-primary text-sm">
				Sign In
			</a>
		</div>
	{:else}
		<section class="vs-card p-6 space-y-5">
			<div>
				<h2 class="text-lg font-semibold text-[#fde68a]">OIDC 1.0 Applications ({clients.length})</h2>
				<p class="text-xs text-[#a8a29e]">
					Register first-party apps (e.g., Vaelsgard), dashboards, or AI agent workloads (NHI <code class="text-[#e7e5e4]">client_credentials</code>).
				</p>
			</div>

			{#if issuedSecret}
				<div class="rounded-lg border border-[#10b981]/45 bg-[#10b981]/10 p-4 space-y-1.5">
					<div class="text-xs font-semibold uppercase text-[#6ee7b7]">
						Client Secret for {issuedSecret.clientId} (Copy Now — Shown Once)
					</div>
					<code class="block break-all rounded bg-[#0c0a09] p-2.5 font-mono text-xs text-[#fde68a]">
						{issuedSecret.secret}
					</code>
				</div>
			{/if}

			<form onsubmit={handleCreateClient} class="grid gap-3 md:grid-cols-2">
				<input type="text" bind:value={clientId} placeholder="client_id (e.g. vaelsgard)" class="vs-input" required />
				<input type="text" bind:value={clientName} placeholder="Display name" class="vs-input" required />
				<input type="text" bind:value={redirectUri} placeholder="Redirect URI(s), comma separated" class="vs-input" required />
				<input type="text" bind:value={scopesText} placeholder="Allowed scopes (space separated)" class="vs-input" required />
				<div class="flex items-center gap-4">
					<select bind:value={clientKind} class="vs-input">
						<option value="confidential">Confidential (client_secret)</option>
						<option value="public">Public (SPA / Mobile / PKCE)</option>
					</select>
					<label class="flex items-center gap-2 text-xs text-[#d6d3d1] whitespace-nowrap">
						<input type="checkbox" bind:checked={requirePkce} class="accent-[#dc2626]" />
						Require PKCE S256
					</label>
				</div>
				<button type="submit" disabled={creatingClient} class="vs-btn-primary">
					{creatingClient ? 'Registering...' : 'Register OIDC Client'}
				</button>
			</form>

			{#if clients.length > 0}
				<div class="overflow-x-auto">
					<table class="w-full text-left text-sm">
						<thead class="border-b border-[#292524] text-xs uppercase text-[#a8a29e]">
							<tr>
								<th class="py-2 pr-4">Client ID</th>
								<th class="py-2 pr-4">Kind</th>
								<th class="py-2 pr-4">Redirect URIs</th>
								<th class="py-2">Scopes</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[#292524]/70">
							{#each clients as c}
								<tr>
									<td class="py-2.5 pr-4 font-mono text-xs font-semibold text-[#fde68a]">{c.client_id}</td>
									<td class="py-2.5 pr-4 text-xs text-[#d6d3d1]">{c.confidential ? 'confidential' : 'public'}</td>
									<td class="py-2.5 pr-4 font-mono text-xs text-[#a8a29e]">{c.redirect_uris.join(', ')}</td>
									<td class="py-2.5 font-mono text-xs text-[#a8a29e]">{c.allowed_scopes.join(' ')}</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>

		<section class="vs-card p-6 space-y-5">
			<div>
				<h2 class="text-lg font-semibold text-[#fde68a]">SCIM 2.0 User Directory ({users.length})</h2>
				<p class="text-xs text-[#a8a29e]">
					Backed live by <code class="text-[#e7e5e4]">/scim/v2/Users</code> (RFC 7644). Provision or deactivate identities instantly.
				</p>
			</div>

			<form onsubmit={handleCreateScimUser} class="grid gap-3 sm:grid-cols-3">
				<input type="email" bind:value={scimEmail} placeholder="new.user@example.com" class="vs-input" required />
				<input type="password" bind:value={scimPassword} placeholder="Initial password (12+ chars)" minlength="12" class="vs-input" required />
				<button type="submit" disabled={creatingUser} class="vs-btn-primary">
					{creatingUser ? 'Provisioning...' : 'Provision User (SCIM)'}
				</button>
			</form>

			<div class="overflow-x-auto">
				<table class="w-full text-left text-sm">
					<thead class="border-b border-[#292524] text-xs uppercase text-[#a8a29e]">
						<tr>
							<th class="py-2 pr-4">Username / Email</th>
							<th class="py-2 pr-4">User ID</th>
							<th class="py-2 pr-4">Status</th>
							<th class="py-2 text-right">Action</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[#292524]/70">
						{#each users as u}
							<tr>
								<td class="py-2.5 pr-4 text-sm font-medium text-[#fafaf9]">{u.userName}</td>
								<td class="py-2.5 pr-4 font-mono text-xs text-[#a8a29e]">{u.id}</td>
								<td class="py-2.5 pr-4 text-xs">
									<span class="rounded-full px-2 py-0.5 font-medium {u.active ? 'bg-[#10b981]/15 text-[#6ee7b7]' : 'bg-[#dc2626]/15 text-[#fca5a5]'}">
										{u.active ? 'active' : 'inactive'}
									</span>
								</td>
								<td class="py-2.5 text-right">
									<button type="button" onclick={() => handleDeleteUser(u.id)} class="vs-btn-danger text-xs">
										Deactivate
									</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>
	{/if}
</div>
