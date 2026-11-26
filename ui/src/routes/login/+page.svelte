<script lang="ts">
	import { base } from '$app/paths';
	import { page } from '$app/state';
	import { signIn } from '$lib/api';

	let email = $state('');
	let password = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		busy = true;
		error = null;
		try {
			await signIn(email.trim(), password);
			const next = page.url.searchParams.get('next');
			if (next && next.startsWith('/')) {
				window.location.href = next;
			} else {
				window.location.href = `${base}/admin`;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Sign-in failed';
		} finally {
			busy = false;
		}
	}
</script>

<div class="mx-auto max-w-md pt-6">
	<div class="vs-card p-6 sm:p-8 space-y-6">
		<div class="space-y-1.5">
			<h1 class="text-2xl font-bold text-[#fafaf9]">Sign in to Vaelspire</h1>
			<p class="text-sm text-[#a8a29e]">
				Authenticate with your Vaelspire Core account to manage sessions, API keys, and OIDC clients.
			</p>
		</div>

		{#if error}
			<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/12 px-3.5 py-2.5 text-sm text-[#fca5a5]">
				{error}
			</div>
		{/if}

		<form onsubmit={handleSubmit} class="space-y-4">
			<div>
				<label for="email" class="block text-xs font-medium uppercase tracking-wider text-[#d6d3d1] mb-1.5">
					Email Address
				</label>
				<input
					id="email"
					type="email"
					required
					autocomplete="email"
					bind:value={email}
					placeholder="admin@vaelspire.local"
					class="vs-input"
				/>
			</div>

			<div>
				<label for="password" class="block text-xs font-medium uppercase tracking-wider text-[#d6d3d1] mb-1.5">
					Password
				</label>
				<input
					id="password"
					type="password"
					required
					autocomplete="current-password"
					bind:value={password}
					placeholder="••••••••••••"
					class="vs-input"
				/>
			</div>

			<button type="submit" disabled={busy} class="vs-btn-primary w-full">
				{busy ? 'Signing in...' : 'Sign In'}
			</button>
		</form>

		<div class="border-t border-[#292524] pt-4 text-center text-xs text-[#a8a29e]">
			Need an account?
			<a href="{base}/register" class="font-medium text-[#fde68a] hover:underline">Create one now</a>
		</div>
	</div>
</div>
