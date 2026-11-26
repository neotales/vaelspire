<script lang="ts">
	import { base } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		getCurrentSession,
		getDiscovery,
		getHealth,
		getReady,
		type DiscoveryDoc,
		type SessionInfo
	} from '$lib/api';

	let discovery = $state<DiscoveryDoc | null>(null);
	let health = $state<{ status: string; version: string; edition: string } | null>(null);
	let ready = $state<{ status: string; store: string } | null>(null);
	let session = $state<SessionInfo | null>(null);
	let error = $state<string | null>(null);

	onMount(async () => {
		try {
			const [d, h, r, s] = await Promise.all([
				getDiscovery(),
				getHealth(),
				getReady(),
				getCurrentSession()
			]);
			discovery = d;
			health = h;
			ready = r;
			session = s;
		} catch (e) {
			error = e instanceof Error ? e.message : 'Unable to reach Vaelspire server';
		}
	});
</script>

<div class="space-y-8">
	<section class="vs-card p-6 sm:p-8 relative overflow-hidden">
		<div class="flex flex-col gap-4 md:flex-row md:items-center md:justify-between">
			<div class="space-y-2 max-w-2xl">
				<div class="inline-flex items-center gap-2 rounded-full border border-[#d97706]/40 bg-[#d97706]/10 px-3 py-1 text-xs font-semibold text-[#fde68a]">
					<span>Embedded Core UI</span>
					{#if discovery}
						<span class="text-[#a8a29e]">•</span>
						<span>v{discovery.version}</span>
					{/if}
				</div>
				<h1 class="text-3xl font-bold tracking-tight text-[#fafaf9] sm:text-4xl">
					Fast, Single-Binary Rust Identity
				</h1>
				<p class="text-sm sm:text-base text-[#d6d3d1] leading-relaxed">
					OIDC 1.0 IdP with Ed25519 JWKS, PKCE, Refresh Token Rotation, Non-Human Identity (AI Agents),
					SCIM 2.0 provisioning, and sub-millisecond <code class="text-[#fde68a]">/forward-auth</code> — all 100% free in Vaelspire Core.
				</p>
			</div>

			<div class="flex flex-wrap gap-3">
				{#if session}
					<a href="{base}/admin" class="vs-btn-primary">Open Admin Console</a>
					<a href="{base}/account" class="vs-btn-secondary">Manage Sessions &amp; Keys</a>
				{:else}
					<a href="{base}/login" class="vs-btn-primary">Sign In</a>
					<a href="{base}/register" class="vs-btn-secondary">Create Account</a>
				{/if}
			</div>
		</div>
	</section>

	{#if error}
		<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/10 px-4 py-3 text-sm text-[#fca5a5]">
			{error}
		</div>
	{/if}

	<section class="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
		<div class="vs-card p-5">
			<div class="text-xs font-medium uppercase tracking-wider text-[#a8a29e]">Server Health</div>
			<div class="mt-2 flex items-center gap-2 text-xl font-bold text-[#fafaf9]">
				<span class="h-2.5 w-2.5 rounded-full {health?.status === 'ok' ? 'bg-[#10b981]' : 'bg-[#f59e0b]'}"></span>
				{health ? health.status.toUpperCase() : 'Checking...'}
			</div>
			<div class="mt-1 text-xs text-[#a8a29e]">Edition: {health?.edition ?? 'core'}</div>
		</div>

		<div class="vs-card p-5">
			<div class="text-xs font-medium uppercase tracking-wider text-[#a8a29e]">Storage Backend</div>
			<div class="mt-2 text-xl font-bold text-[#fde68a]">
				{ready ? ready.store.toUpperCase() : 'Checking...'}
			</div>
			<div class="mt-1 text-xs text-[#a8a29e]">
				Status: {ready?.status ?? 'probing'}
			</div>
		</div>

		<div class="vs-card p-5">
			<div class="text-xs font-medium uppercase tracking-wider text-[#a8a29e]">OIDC Issuer</div>
			<div class="mt-2 truncate text-sm font-mono font-semibold text-[#fafaf9]" title={discovery?.issuer}>
				{discovery?.issuer ?? 'Loading...'}
			</div>
			<div class="mt-2 text-xs text-[#a8a29e]">EdDSA (Ed25519) JWKS</div>
		</div>

		<div class="vs-card p-5">
			<div class="text-xs font-medium uppercase tracking-wider text-[#a8a29e]">Active Session</div>
			<div class="mt-2 text-xl font-bold {session ? 'text-[#6ee7b7]' : 'text-[#d6d3d1]'}">
				{session ? 'Authenticated' : 'Guest'}
			</div>
			<div class="mt-1 truncate text-xs font-mono text-[#a8a29e]">
				{session ? session.user_id : 'Sign in to access admin APIs'}
			</div>
		</div>
	</section>

	<section class="grid gap-4 md:grid-cols-3">
		<a href="{base}/account" class="vs-card p-5 hover:border-[#d97706]/70 transition-colors block">
			<div class="text-sm font-semibold text-[#fde68a]">Account &amp; API Keys</div>
			<p class="mt-1.5 text-xs text-[#a8a29e] leading-relaxed">
				Inspect active browser sessions, revoke compromised devices, and mint prefix-validated <code class="text-[#e7e5e4]">vs_</code> API keys for CLI and services.
			</p>
		</a>

		<a href="{base}/admin" class="vs-card p-5 hover:border-[#dc2626]/70 transition-colors block">
			<div class="text-sm font-semibold text-[#fca5a5]">Admin Console</div>
			<p class="mt-1.5 text-xs text-[#a8a29e] leading-relaxed">
				Register OIDC applications (Vaelsgard, Grafana, internal apps), inspect live Prometheus metrics, and manage SCIM 2.0 users.
			</p>
		</a>

		<a href="{base}/consent" class="vs-card p-5 hover:border-[#f59e0b]/70 transition-colors block">
			<div class="text-sm font-semibold text-[#fbbf24]">OIDC Authorization Flow</div>
			<p class="mt-1.5 text-xs text-[#a8a29e] leading-relaxed">
				Review requested OAuth 2.0 / OpenID Connect scopes and complete PKCE <code class="text-[#e7e5e4]">S256</code> authorization redirects cleanly.
			</p>
		</a>
	</section>
</div>
