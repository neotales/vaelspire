<script lang="ts">
	import { base } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		createApiKey,
		getCurrentSession,
		listApiKeys,
		listSessions,
		revokeApiKey,
		revokeSession,
		type ApiKeyInfo,
		type SessionInfo
	} from '$lib/api';

	let currentSession = $state<SessionInfo | null>(null);
	let sessions = $state<SessionInfo[]>([]);
	let apiKeys = $state<ApiKeyInfo[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);

	let keyName = $state('');
	let keyScopes = $state('read write');
	let newlyIssuedToken = $state<string | null>(null);
	let busy = $state(false);

	async function loadAll() {
		loading = true;
		error = null;
		try {
			currentSession = await getCurrentSession();
			if (currentSession) {
				const [s, k] = await Promise.all([listSessions(), listApiKeys()]);
				sessions = s;
				apiKeys = k;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load account security data';
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadAll();
	});

	async function handleRevokeSession(id: string) {
		try {
			await revokeSession(id);
			await loadAll();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Could not revoke session';
		}
	}

	async function handleCreateKey(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		newlyIssuedToken = null;
		try {
			const scopes = keyScopes
				.split(/[\s,]+/)
				.map((s) => s.trim())
				.filter(Boolean);
			const res = await createApiKey(keyName.trim() || 'cli-key', scopes);
			newlyIssuedToken = res.token ?? res.key ?? res.secret ?? null;
			keyName = '';
			await loadAll();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Could not create API key';
		} finally {
			busy = false;
		}
	}

	async function handleRevokeKey(id: string) {
		try {
			await revokeApiKey(id);
			await loadAll();
		} catch (e) {
			error = e instanceof Error ? e.message : 'Could not revoke API key';
		}
	}
</script>

<div class="space-y-8">
	<div class="flex flex-wrap items-center justify-between gap-4">
		<div>
			<h1 class="text-2xl font-bold text-[#fafaf9]">Account Security &amp; API Keys</h1>
			<p class="text-sm text-[#a8a29e]">
				Manage active browser sessions and prefix-validated <code class="text-[#fde68a]">vs_</code> API keys.
			</p>
		</div>
		<button type="button" onclick={loadAll} class="vs-btn-secondary text-xs">Refresh</button>
	</div>

	{#if error}
		<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/12 px-4 py-3 text-sm text-[#fca5a5]">
			{error}
		</div>
	{/if}

	{#if loading}
		<div class="vs-card p-6 text-sm text-[#a8a29e]">Loading account security state...</div>
	{:else if !currentSession}
		<div class="vs-card p-6 space-y-3">
			<p class="text-sm text-[#d6d3d1]">Sign in to view your sessions and issue API keys.</p>
			<a href="{base}/login?next={encodeURIComponent(`${base}/account`)}" class="vs-btn-primary text-sm">
				Sign In
			</a>
		</div>
	{:else}
		<section class="vs-card p-6 space-y-4">
			<div class="flex items-center justify-between">
				<h2 class="text-lg font-semibold text-[#fde68a]">Active Sessions ({sessions.length})</h2>
				<span class="font-mono text-xs text-[#a8a29e]">User: {currentSession.user_id}</span>
			</div>

			<div class="overflow-x-auto">
				<table class="w-full text-left text-sm">
					<thead class="border-b border-[#292524] text-xs uppercase text-[#a8a29e]">
						<tr>
							<th class="py-2 pr-4">Session ID</th>
							<th class="py-2 pr-4">Expires</th>
							<th class="py-2 text-right">Action</th>
						</tr>
					</thead>
					<tbody class="divide-y divide-[#292524]/70">
						{#each sessions as s}
							<tr>
								<td class="py-3 pr-4 font-mono text-xs text-[#e7e5e4]">
									{s.id}
									{#if s.id === currentSession.id}
										<span class="ml-2 rounded bg-[#10b981]/15 px-1.5 py-0.5 text-[10px] font-sans font-semibold text-[#6ee7b7]">
											Current
										</span>
									{/if}
								</td>
								<td class="py-3 pr-4 text-xs text-[#a8a29e]">{s.expires_at}</td>
								<td class="py-3 text-right">
									<button
										type="button"
										onclick={() => handleRevokeSession(s.id)}
										class="vs-btn-danger text-xs"
									>
										Revoke
									</button>
								</td>
							</tr>
						{/each}
					</tbody>
				</table>
			</div>
		</section>

		<section class="vs-card p-6 space-y-5">
			<div>
				<h2 class="text-lg font-semibold text-[#fde68a]">Personal &amp; Service API Keys</h2>
				<p class="text-xs text-[#a8a29e]">
					Keys are hashed with keyed BLAKE3 at rest. The plaintext token is revealed once upon creation.
				</p>
			</div>

			{#if newlyIssuedToken}
				<div class="rounded-lg border border-[#10b981]/45 bg-[#10b981]/10 p-4 space-y-2">
					<div class="text-xs font-semibold uppercase tracking-wider text-[#6ee7b7]">
						Copy Now — Shown Once
					</div>
					<code class="block break-all rounded bg-[#0c0a09] p-3 font-mono text-xs text-[#fde68a]">
						{newlyIssuedToken}
					</code>
				</div>
			{/if}

			<form onsubmit={handleCreateKey} class="grid gap-3 sm:grid-cols-3">
				<input
					type="text"
					bind:value={keyName}
					placeholder="Key label (e.g. vaelsgard-ci)"
					class="vs-input"
					required
				/>
				<input
					type="text"
					bind:value={keyScopes}
					placeholder="Scopes (space separated)"
					class="vs-input"
				/>
				<button type="submit" disabled={busy} class="vs-btn-primary">
					{busy ? 'Issuing...' : 'Issue API Key'}
				</button>
			</form>

			{#if apiKeys.length === 0}
				<p class="text-xs text-[#a8a29e]">No active API keys yet.</p>
			{:else}
				<div class="overflow-x-auto">
					<table class="w-full text-left text-sm">
						<thead class="border-b border-[#292524] text-xs uppercase text-[#a8a29e]">
							<tr>
								<th class="py-2 pr-4">ID</th>
								<th class="py-2 pr-4">Label</th>
								<th class="py-2 text-right">Action</th>
							</tr>
						</thead>
						<tbody class="divide-y divide-[#292524]/70">
							{#each apiKeys as key}
								<tr>
									<td class="py-2.5 pr-4 font-mono text-xs text-[#e7e5e4]">{key.id}</td>
									<td class="py-2.5 pr-4 text-xs text-[#d6d3d1]">{key.name ?? 'unnamed'}</td>
									<td class="py-2.5 text-right">
										<button
											type="button"
											onclick={() => handleRevokeKey(key.id)}
											class="vs-btn-danger text-xs"
										>
											Revoke
										</button>
									</td>
								</tr>
							{/each}
						</tbody>
					</table>
				</div>
			{/if}
		</section>
	{/if}
</div>
