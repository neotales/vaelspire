<script lang="ts">
	import { base } from '$app/paths';
	import { signUp } from '$lib/api';

	let email = $state('');
	let password = $state('');
	let confirmPassword = $state('');
	let busy = $state(false);
	let error = $state<string | null>(null);
	let success = $state<string | null>(null);

	async function handleSubmit(event: SubmitEvent) {
		event.preventDefault();
		error = null;
		success = null;
		if (password !== confirmPassword) {
			error = 'Passwords do not match.';
			return;
		}
		if (password.length < 12) {
			error = 'Password must be at least 12 characters.';
			return;
		}
		busy = true;
		try {
			await signUp(email.trim(), password);
			success = 'Account created! Redirecting to sign in...';
			setTimeout(() => {
				window.location.href = `${base}/login`;
			}, 700);
		} catch (e) {
			error = e instanceof Error ? e.message : 'Registration failed';
		} finally {
			busy = false;
		}
	}
</script>

<div class="mx-auto max-w-md pt-6">
	<div class="vs-card p-6 sm:p-8 space-y-6">
		<div class="space-y-1.5">
			<h1 class="text-2xl font-bold text-[#fafaf9]">Create Vaelspire Account</h1>
			<p class="text-sm text-[#a8a29e]">
				Passwords are hashed with Argon2id (OWASP parameters) and never stored in plaintext.
			</p>
		</div>

		{#if error}
			<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/12 px-3.5 py-2.5 text-sm text-[#fca5a5]">
				{error}
			</div>
		{/if}

		{#if success}
			<div class="rounded-lg border border-[#10b981]/50 bg-[#10b981]/12 px-3.5 py-2.5 text-sm text-[#6ee7b7]">
				{success}
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
					placeholder="you@example.com"
					class="vs-input"
				/>
			</div>

			<div>
				<label for="password" class="block text-xs font-medium uppercase tracking-wider text-[#d6d3d1] mb-1.5">
					Password (12+ chars)
				</label>
				<input
					id="password"
					type="password"
					required
					minlength="12"
					autocomplete="new-password"
					bind:value={password}
					placeholder="••••••••••••"
					class="vs-input"
				/>
			</div>

			<div>
				<label for="confirm" class="block text-xs font-medium uppercase tracking-wider text-[#d6d3d1] mb-1.5">
					Confirm Password
				</label>
				<input
					id="confirm"
					type="password"
					required
					minlength="12"
					autocomplete="new-password"
					bind:value={confirmPassword}
					placeholder="••••••••••••"
					class="vs-input"
				/>
			</div>

			<button type="submit" disabled={busy} class="vs-btn-primary w-full">
				{busy ? 'Creating Account...' : 'Create Account'}
			</button>
		</form>

		<div class="border-t border-[#292524] pt-4 text-center text-xs text-[#a8a29e]">
			Already have an account?
			<a href="{base}/login" class="font-medium text-[#fde68a] hover:underline">Sign in</a>
		</div>
	</div>
</div>
