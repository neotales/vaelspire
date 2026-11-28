<script lang="ts">
	import { base } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		addOrgDomain,
		createOrgIdp,
		createScimToken,
		deleteOrgIdp,
		getCurrentSession,
		getOrgPolicy,
		listOrgDomains,
		listOrgIdps,
		testOrgIdp,
		updateOrgPolicy,
		verifyOrgDomain,
		type OrgDomain,
		type OrgIdp,
		type OrgPolicy,
		type SessionInfo
	} from '$lib/api';

	let session = $state<SessionInfo | null>(null);
	let policy = $state<OrgPolicy>({
		email_policy: 'allow_public',
		session_sliding: true,
		session_idle_secs: 86400,
		session_absolute_secs: 604800,
		break_glass_enabled: true
	});
	let domains = $state<OrgDomain[]>([]);
	let idps = $state<OrgIdp[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);

	// Domain form
	let newDomain = $state('');

	// IdP form
	let idpName = $state('Company Okta');
	let idpProtocol = $state<'oidc' | 'saml'>('oidc');
	let idpIssuer = $state('https://company.okta.com');
	let idpClientId = $state('');
	let idpClientSecret = $state('');
	let idpMetadataXml = $state('');
	let idpEnabled = $state(true);

	// SCIM token form
	let scimTokenName = $state('Directory Sync');
	let issuedScimToken = $state<string | null>(null);

	async function loadAll() {
		loading = true;
		error = null;
		try {
			session = await getCurrentSession();
			if (session) {
				const [p, d, i] = await Promise.all([getOrgPolicy(), listOrgDomains(), listOrgIdps()]);
				policy = p;
				domains = d;
				idps = i;
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load organization portal';
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadAll();
	});

	async function savePolicy(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		notice = null;
		try {
			policy = await updateOrgPolicy(policy);
			notice = 'Organization email domain & session timeout policy saved.';
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to save policy';
		}
	}

	async function handleAddDomain(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		try {
			await addOrgDomain(newDomain.trim());
			newDomain = '';
			await loadAll();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to add domain';
		}
	}

	async function handleVerifyDomain(d: OrgDomain) {
		error = null;
		try {
			await verifyOrgDomain(d.id, d.verification_token);
			notice = `Verified ownership of ${d.domain}.`;
			await loadAll();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Verification failed';
		}
	}

	async function handleAddIdp(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		try {
			await createOrgIdp({
				name: idpName.trim(),
				protocol: idpProtocol,
				issuer_url: idpIssuer.trim(),
				client_id: idpClientId.trim(),
				client_secret: idpClientSecret.trim(),
				metadata_xml: idpMetadataXml.trim(),
				jit_provisioning: true,
				default_role: 'member',
				group_claim: 'groups',
				enabled: idpEnabled
			});
			notice = 'Upstream IdP registered.';
			await loadAll();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to add IdP';
		}
	}

	async function handleTestIdp(id: string) {
		error = null;
		try {
			const res = await testOrgIdp(id);
			notice = res.ok
				? 'Dry-run IdP validation PASSED all checks.'
				: `Dry-run IdP validation FAILED: ${JSON.stringify(res.checks)}`;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Dry-run test failed';
		}
	}

	async function handleDeleteIdp(id: string) {
		await deleteOrgIdp(id).catch(() => {});
		await loadAll();
	}

	async function handleMintScimToken(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		try {
			const res = await createScimToken(scimTokenName.trim() || 'SCIM Sync');
			issuedScimToken = res.token;
		} catch (err) {
			error = err instanceof Error ? err.message : 'Could not mint SCIM token';
		}
	}
</script>

<div class="space-y-8">
	<div>
		<h1 class="text-2xl font-bold text-[#fafaf9]">Self-Service Organization SSO &amp; Domain Portal</h1>
		<p class="text-sm text-[#a8a29e]">
			Configure public vs. business email policies, verify DNS domains for Home Realm Discovery, attach upstream OIDC/SAML IdPs, and mint SCIM 2.0 Directory Sync tokens.
		</p>
	</div>

	{#if error}
		<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/12 px-4 py-3 text-sm text-[#fca5a5]">
			{error}
		</div>
	{/if}
	{#if notice}
		<div class="rounded-lg border border-[#10b981]/50 bg-[#10b981]/12 px-4 py-3 text-sm text-[#6ee7b7]">
			{notice}
		</div>
	{/if}

	{#if loading}
		<div class="vs-card p-6 text-sm text-[#a8a29e]">Loading organization configuration...</div>
	{:else if !session}
		<div class="vs-card p-6 space-y-3">
			<p class="text-sm text-[#d6d3d1]">Sign in as an organization administrator to configure SSO and domain policies.</p>
			<a href="{base}/login?next={encodeURIComponent(`${base}/org`)}" class="vs-btn-primary text-sm">Sign In</a>
		</div>
	{:else}
		<section class="vs-card p-6 space-y-4">
			<h2 class="text-lg font-semibold text-[#fde68a]">Email Domain &amp; Session Expiration Policy</h2>
			<form onsubmit={savePolicy} class="grid gap-4 md:grid-cols-2">
				<div>
					<label for="email-policy" class="block text-xs uppercase text-[#a8a29e] mb-1">Allowed Email Accounts</label>
					<select id="email-policy" bind:value={policy.email_policy} class="vs-input">
						<option value="allow_public">Allow Public Accounts (Gmail, Outlook, etc.)</option>
						<option value="business_domains_only">Business Domains Only (Block consumer email)</option>
						<option value="verified_domains_only">Verified Company Domains Only (Strict HRD)</option>
					</select>
				</div>
				<div class="flex items-center gap-6 pt-5">
					<label class="flex items-center gap-2 text-xs text-[#e7e5e4]">
						<input type="checkbox" bind:checked={policy.session_sliding} class="accent-[#dc2626]" />
						Sliding Session Expiration
					</label>
					<label class="flex items-center gap-2 text-xs text-[#e7e5e4]">
						<input type="checkbox" bind:checked={policy.break_glass_enabled} class="accent-[#dc2626]" />
						Break-Glass Local Admin
					</label>
				</div>
				<div>
					<label for="idle" class="block text-xs uppercase text-[#a8a29e] mb-1">Idle Timeout (seconds)</label>
					<input id="idle" type="number" min="60" bind:value={policy.session_idle_secs} class="vs-input" />
				</div>
				<div>
					<label for="abs" class="block text-xs uppercase text-[#a8a29e] mb-1">Hard Absolute Timeout (seconds)</label>
					<input id="abs" type="number" min="60" bind:value={policy.session_absolute_secs} class="vs-input" />
				</div>
				<div class="md:col-span-2">
					<button type="submit" class="vs-btn-primary">Save Organization Policy</button>
				</div>
			</form>
		</section>

		<section class="vs-card p-6 space-y-4">
			<h2 class="text-lg font-semibold text-[#fde68a]">Verified Organization Domains (DNS TXT)</h2>
			<form onsubmit={handleAddDomain} class="flex flex-col sm:flex-row gap-3">
				<input type="text" bind:value={newDomain} placeholder="acme.com" class="vs-input" required />
				<button type="submit" class="vs-btn-primary whitespace-nowrap">Add Domain</button>
			</form>
			{#if domains.length > 0}
				<div class="space-y-2">
					{#each domains as d}
						<div class="rounded-lg border border-[#292524] bg-[#0c0a09] p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
							<div class="space-y-1">
								<div class="font-semibold text-[#fafaf9]">
									{d.domain}
									<span class="ml-2 rounded-full px-2 py-0.5 text-[10px] {d.verified ? 'bg-[#10b981]/15 text-[#6ee7b7]' : 'bg-[#f59e0b]/15 text-[#fde68a]'}">
										{d.verified ? 'verified' : 'pending DNS TXT'}
									</span>
								</div>
								<div class="font-mono text-[#a8a29e]">TXT {d.txt_record_name} = "{d.verification_token}"</div>
							</div>
							{#if !d.verified}
								<button type="button" onclick={() => handleVerifyDomain(d)} class="vs-btn-secondary text-xs">
									Verify TXT
								</button>
							{/if}
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="vs-card p-6 space-y-4">
			<h2 class="text-lg font-semibold text-[#fde68a]">Upstream Identity Providers (OIDC / SAML 2.0)</h2>
			<form onsubmit={handleAddIdp} class="grid gap-3 md:grid-cols-2">
				<input type="text" bind:value={idpName} placeholder="Display name (e.g. Okta Prod)" class="vs-input" required />
				<select bind:value={idpProtocol} class="vs-input">
					<option value="oidc">OpenID Connect (OIDC)</option>
					<option value="saml">SAML 2.0</option>
				</select>
				{#if idpProtocol === 'oidc'}
					<input type="url" bind:value={idpIssuer} placeholder="https://tenant.okta.com" class="vs-input" />
					<input type="text" bind:value={idpClientId} placeholder="OIDC Client ID" class="vs-input" />
					<input type="password" bind:value={idpClientSecret} placeholder="OIDC Client Secret" class="vs-input" />
				{:else}
					<textarea bind:value={idpMetadataXml} rows="3" placeholder="Paste SAML 2.0 EntityDescriptor XML..." class="vs-input md:col-span-2"></textarea>
				{/if}
				<label class="flex items-center gap-2 text-xs text-[#e7e5e4]">
					<input type="checkbox" bind:checked={idpEnabled} class="accent-[#dc2626]" />
					Enable for Home Realm Discovery
				</label>
				<button type="submit" class="vs-btn-primary md:col-span-2">Register Upstream IdP</button>
			</form>
			{#if idps.length > 0}
				<div class="space-y-2">
					{#each idps as idp}
						<div class="rounded-lg border border-[#292524] bg-[#0c0a09] p-3 flex flex-wrap items-center justify-between gap-3 text-xs">
							<div>
								<div class="font-semibold text-[#fafaf9]">{idp.name} <span class="uppercase text-[#fde68a]">({idp.protocol})</span></div>
								<div class="font-mono text-[#a8a29e]">{idp.issuer_url || 'SAML Metadata XML'}</div>
							</div>
							<div class="flex gap-2">
								<button type="button" onclick={() => handleTestIdp(idp.id)} class="vs-btn-secondary text-xs">Test Connection</button>
								<button type="button" onclick={() => handleDeleteIdp(idp.id)} class="vs-btn-danger text-xs">Delete</button>
							</div>
						</div>
					{/each}
				</div>
			{/if}
		</section>

		<section class="vs-card p-6 space-y-4">
			<h2 class="text-lg font-semibold text-[#fde68a]">Directory Sync (SCIM 2.0 Users &amp; Groups Token)</h2>
			<p class="text-xs text-[#a8a29e]">
				Paste the bearer token below into Okta, Entra ID, or Google Workspace pointing at <code class="text-[#e7e5e4]">/scim/v2</code>.
			</p>
			<form onsubmit={handleMintScimToken} class="flex flex-col sm:flex-row gap-3">
				<input type="text" bind:value={scimTokenName} placeholder="Okta Directory Sync" class="vs-input" required />
				<button type="submit" class="vs-btn-primary whitespace-nowrap">Generate SCIM Token</button>
			</form>
			{#if issuedScimToken}
				<div class="rounded-lg border border-[#10b981]/45 bg-[#10b981]/10 p-4 space-y-1">
					<div class="text-xs font-semibold uppercase text-[#6ee7b7]">SCIM Bearer Token (Copy Now — Shown Once)</div>
					<code class="block break-all rounded bg-[#0c0a09] p-2.5 font-mono text-xs text-[#fde68a]">{issuedScimToken}</code>
				</div>
			{/if}
		</section>
	{/if}
</div>
