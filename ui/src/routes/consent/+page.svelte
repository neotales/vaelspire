<script lang="ts">
	import { base } from '$app/paths';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { getCurrentSession, type SessionInfo } from '$lib/api';

	let session = $state<SessionInfo | null>(null);
	let loading = $state(true);

	const clientId = $derived(page.url.searchParams.get('client_id') ?? '');
	const redirectUri = $derived(page.url.searchParams.get('redirect_uri') ?? '');
	const scopeParam = $derived(page.url.searchParams.get('scope') ?? 'openid email profile');
	const scopes = $derived(scopeParam.split(/\s+/).filter(Boolean));
	const stateParam = $derived(page.url.searchParams.get('state') ?? '');
	const codeChallenge = $derived(page.url.searchParams.get('code_challenge') ?? '');
	const codeChallengeMethod = $derived(
		page.url.searchParams.get('code_challenge_method') ?? 'S256'
	);
	const nonce = $derived(page.url.searchParams.get('nonce') ?? '');

	onMount(async () => {
		session = await getCurrentSession().catch(() => null);
		loading = false;
	});

	function approveAuthorization() {
		const params = new URLSearchParams();
		params.set('response_type', 'code');
		params.set('client_id', clientId);
		params.set('redirect_uri', redirectUri);
		params.set('scope', scopes.join(' '));
		if (stateParam) params.set('state', stateParam);
		if (codeChallenge) {
			params.set('code_challenge', codeChallenge);
			params.set('code_challenge_method', codeChallengeMethod);
		}
		if (nonce) params.set('nonce', nonce);
		window.location.href = `/oauth2/authorize?${params.toString()}`;
	}

	function denyAuthorization() {
		if (!redirectUri) {
			window.location.href = `${base}/`;
			return;
		}
		const target = new URL(redirectUri);
		target.searchParams.set('error', 'access_denied');
		if (stateParam) target.searchParams.set('state', stateParam);
		window.location.href = target.toString();
	}
</script>

<div class="mx-auto max-w-lg pt-6">
	<div class="vs-card p-6 sm:p-8 space-y-6">
		<div class="space-y-1.5">
			<span class="inline-flex items-center rounded-full border border-[#d97706]/40 bg-[#d97706]/10 px-2.5 py-0.5 text-xs font-semibold text-[#fde68a]">
				OpenID Connect Authorization
			</span>
			<h1 class="text-2xl font-bold text-[#fafaf9]">Approve Application Access</h1>
			<p class="text-sm text-[#a8a29e]">
				Review the requested permissions before Vaelspire issues a single-use authorization code.
			</p>
		</div>

		{#if !clientId || !redirectUri}
			<div class="rounded-lg border border-[#d97706]/40 bg-[#d97706]/10 p-4 text-sm text-[#fde68a] space-y-2">
				<p class="font-semibold">No active OIDC request parameters detected.</p>
				<p class="text-xs text-[#d6d3d1]">
					Pass <code class="text-[#fde68a]">?client_id=...&amp;redirect_uri=...&amp;scope=openid+email&amp;code_challenge=...</code> to preview consent, or launch an OIDC login from a registered client like Vaelsgard.
				</p>
			</div>
		{:else if loading}
			<div class="text-sm text-[#a8a29e]">Checking active session...</div>
		{:else if !session}
			<div class="rounded-lg border border-[#dc2626]/40 bg-[#dc2626]/10 p-4 space-y-3">
				<p class="text-sm text-[#fca5a5]">Sign in first to authorize <strong>{clientId}</strong>.</p>
				<a
					href="{base}/login?next={encodeURIComponent(page.url.pathname + page.url.search)}"
					class="vs-btn-primary text-sm"
				>
					Sign In to Continue
				</a>
			</div>
		{:else}
			<div class="space-y-4">
				<div class="rounded-lg border border-[#292524] bg-[#0c0a09] p-4 space-y-2 text-sm">
					<div class="flex justify-between gap-4">
						<span class="text-[#a8a29e]">Application</span>
						<span class="font-mono font-semibold text-[#fde68a]">{clientId}</span>
					</div>
					<div class="flex justify-between gap-4">
						<span class="text-[#a8a29e]">Callback URI</span>
						<span class="font-mono text-xs text-[#e7e5e4] truncate">{redirectUri}</span>
					</div>
					<div class="flex justify-between gap-4">
						<span class="text-[#a8a29e]">PKCE Protection</span>
						<span class="text-xs font-medium {codeChallenge ? 'text-[#6ee7b7]' : 'text-[#f59e0b]'}">
							{codeChallenge ? `Enabled (${codeChallengeMethod})` : 'Not supplied'}
						</span>
					</div>
				</div>

				<div>
					<div class="text-xs font-semibold uppercase tracking-wider text-[#a8a29e] mb-2">
						Requested Scopes
					</div>
					<div class="flex flex-wrap gap-2">
						{#each scopes as scope}
							<span class="rounded-md border border-[#3f3834] bg-[#1c1917] px-2.5 py-1 font-mono text-xs text-[#fde68a]">
								{scope}
							</span>
						{/each}
					</div>
				</div>

				<div class="flex items-center gap-3 pt-2">
					<button type="button" onclick={approveAuthorization} class="vs-btn-primary flex-1">
						Approve &amp; Continue
					</button>
					<button type="button" onclick={denyAuthorization} class="vs-btn-secondary">
						Deny
					</button>
				</div>
			</div>
		{/if}
	</div>
</div>
