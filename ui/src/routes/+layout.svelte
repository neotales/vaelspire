<script lang="ts">
	import '../app.css';
	import { base } from '$app/paths';
	import { page } from '$app/state';
	import { onMount } from 'svelte';
	import { getCurrentSession, signOut, type SessionInfo } from '$lib/api';

	let { children } = $props();
	let session = $state<SessionInfo | null>(null);
	let loaded = $state(false);

	async function refreshSession() {
		session = await getCurrentSession().catch(() => null);
		loaded = true;
	}

	onMount(() => {
		refreshSession();
	});

	async function handleSignOut() {
		await signOut().catch(() => {});
		session = null;
		window.location.href = `${base}/login`;
	}

	const navItems = [
		{ href: `${base}/`, label: 'Overview' },
		{ href: `${base}/account`, label: 'Account & Keys' },
		{ href: `${base}/admin`, label: 'Admin Console' },
		{ href: `${base}/consent`, label: 'OIDC Consent' }
	];
</script>

<div class="min-h-screen flex flex-col">
	<header class="sticky top-0 z-30 border-b border-[#292524] bg-[#0c0a09]/90 backdrop-blur-md">
		<div class="mx-auto flex max-w-6xl items-center justify-between px-4 py-3 sm:px-6">
			<a href="{base}/" class="flex items-center gap-3 group">
				<svg
					class="h-8 w-8 shrink-0"
					viewBox="0 0 64 64"
					fill="none"
					xmlns="http://www.w3.org/2000/svg"
					aria-hidden="true"
				>
					<rect width="64" height="64" rx="14" fill="#1c1917" stroke="#44403c" stroke-width="2" />
					<path d="M32 7 L45 53 L32 45 L19 53 Z" fill="#dc2626" />
					<path d="M32 15 L39 45 L32 40 L25 45 Z" fill="#f59e0b" />
					<circle cx="32" cy="24" r="3" fill="#fde68a" />
				</svg>
				<div class="flex flex-col leading-tight">
					<span class="text-base font-bold tracking-tight text-[#fafaf9] group-hover:text-[#fde68a] transition-colors">
						Vaelspire
					</span>
					<span class="text-[11px] font-medium text-[#a8a29e]">
						Core Console · <span class="text-[#c084fc]">by Neotales</span>
					</span>
				</div>
			</a>

			<nav class="hidden md:flex items-center gap-1">
				{#each navItems as item}
					{@const active = page.url.pathname === item.href || (item.href !== `${base}/` && page.url.pathname.startsWith(item.href))}
					<a
						href={item.href}
						class="rounded-md px-3 py-1.5 text-sm font-medium transition-colors {active
							? 'bg-[#dc2626]/20 text-[#fde68a] border border-[#dc2626]/40'
							: 'text-[#d6d3d1] hover:text-[#fde68a] hover:bg-[#1c1917]'}"
					>
						{item.label}
					</a>
				{/each}
			</nav>

			<div class="flex items-center gap-2">
				{#if loaded && session}
					<span class="hidden sm:inline-flex items-center gap-1.5 rounded-full border border-[#10b981]/35 bg-[#10b981]/10 px-2.5 py-1 text-xs font-medium text-[#6ee7b7]">
						<span class="h-1.5 w-1.5 rounded-full bg-[#10b981]"></span>
						Signed In
					</span>
					<button type="button" onclick={handleSignOut} class="vs-btn-secondary text-xs py-1.5 px-3">
						Sign Out
					</button>
				{:else if loaded}
					<a href="{base}/login" class="vs-btn-secondary text-xs py-1.5 px-3">Sign In</a>
					<a href="{base}/register" class="vs-btn-primary text-xs py-1.5 px-3">Create Account</a>
				{/if}
			</div>
		</div>
	</header>

	<main class="mx-auto w-full max-w-6xl flex-1 px-4 py-8 sm:px-6">
		{@render children()}
	</main>

	<footer class="border-t border-[#292524] bg-[#0c0a09]/80 py-5 text-xs text-[#a8a29e]">
		<div class="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 sm:px-6">
			<div>
				<strong class="text-[#e7e5e4]">Vaelspire Core</strong> — MIT Open-Core Rust Identity &amp; Auth Platform (Zero SSO Tax).
			</div>
			<div class="flex flex-wrap items-center gap-4">
				<a href="/.well-known/openid-configuration" target="_blank" class="hover:text-[#fde68a]">OIDC Discovery</a>
				<a href="/.well-known/jwks.json" target="_blank" class="hover:text-[#fde68a]">JWKS</a>
				<a href="/saml/metadata" target="_blank" class="hover:text-[#fde68a]">SAML Metadata</a>
				<a href="/metrics" target="_blank" class="hover:text-[#fde68a]">Metrics</a>
			</div>
		</div>
	</footer>
</div>
