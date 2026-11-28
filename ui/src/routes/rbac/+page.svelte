<script lang="ts">
	import { base } from '$app/paths';
	import { onMount } from 'svelte';
	import {
		assignRoleToGroup,
		createRbacGroup,
		createRbacPermission,
		createRbacRole,
		getCurrentSession,
		getEffectiveAccess,
		grantPermissionToRole,
		listRbacGroups,
		listRbacPermissions,
		listRbacRoles,
		type AppPermission,
		type AppRole,
		type RbacGroup,
		type SessionInfo
	} from '$lib/api';

	let session = $state<SessionInfo | null>(null);
	let roles = $state<AppRole[]>([]);
	let perms = $state<AppPermission[]>([]);
	let groups = $state<RbacGroup[]>([]);
	let loading = $state(true);
	let error = $state<string | null>(null);
	let notice = $state<string | null>(null);

	let roleName = $state('');
	let roleAppId = $state('vaelsgard');
	let permName = $state('');
	let permAppId = $state('vaelsgard');
	let groupName = $state('');

	let grantRoleId = $state('');
	let grantPermId = $state('');
	let linkGroupId = $state('');
	let linkRoleId = $state('');

	let inspectAppId = $state('vaelsgard');
	let effective = $state<{ groups: string[]; roles: string[]; permissions: string[] } | null>(null);

	async function loadAll() {
		loading = true;
		error = null;
		try {
			session = await getCurrentSession();
			if (session) {
				const [r, p, g] = await Promise.all([
					listRbacRoles(),
					listRbacPermissions(),
					listRbacGroups()
				]);
				roles = r;
				perms = p;
				groups = g;
				effective = await getEffectiveAccess(session.user_id, inspectAppId || undefined).catch(() => null);
			}
		} catch (e) {
			error = e instanceof Error ? e.message : 'Failed to load RBAC data';
		} finally {
			loading = false;
		}
	}

	onMount(() => {
		loadAll();
	});

	async function handleCreateRole(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		try {
			await createRbacRole(roleName.trim(), roleAppId.trim() || undefined);
			roleName = '';
			notice = 'Role created.';
			await loadAll();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to create role';
		}
	}

	async function handleCreatePerm(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		try {
			await createRbacPermission(permName.trim(), permAppId.trim() || undefined);
			permName = '';
			notice = 'Permission created.';
			await loadAll();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to create permission';
		}
	}

	async function handleCreateGroup(e: SubmitEvent) {
		e.preventDefault();
		error = null;
		try {
			await createRbacGroup(groupName.trim());
			groupName = '';
			notice = 'Group created.';
			await loadAll();
		} catch (err) {
			error = err instanceof Error ? err.message : 'Failed to create group';
		}
	}

	async function handleGrantPerm(e: SubmitEvent) {
		e.preventDefault();
		if (!grantRoleId || !grantPermId) return;
		await grantPermissionToRole(grantRoleId, grantPermId);
		notice = 'Permission granted to role.';
		await loadAll();
	}

	async function handleAssignGroupRole(e: SubmitEvent) {
		e.preventDefault();
		if (!linkGroupId || !linkRoleId) return;
		await assignRoleToGroup(linkGroupId, linkRoleId);
		notice = 'Role assigned to group.';
		await loadAll();
	}
</script>

<div class="space-y-8">
	<div>
		<h1 class="text-2xl font-bold text-[#fafaf9]">Org-Wide &amp; Per-App RBAC</h1>
		<p class="text-sm text-[#a8a29e]">
			Define organization-wide or per-application roles (e.g., <code class="text-[#fde68a]">vaelsgard:vault-editor</code>), attach granular permissions to roles, and bind roles to SCIM-synced groups.
		</p>
	</div>

	{#if error}
		<div class="rounded-lg border border-[#dc2626]/50 bg-[#dc2626]/12 px-4 py-3 text-sm text-[#fca5a5]">{error}</div>
	{/if}
	{#if notice}
		<div class="rounded-lg border border-[#10b981]/50 bg-[#10b981]/12 px-4 py-3 text-sm text-[#6ee7b7]">{notice}</div>
	{/if}

	{#if loading}
		<div class="vs-card p-6 text-sm text-[#a8a29e]">Loading RBAC graph...</div>
	{:else if !session}
		<div class="vs-card p-6 space-y-3">
			<p class="text-sm text-[#d6d3d1]">Sign in to manage roles, permissions, and groups.</p>
			<a href="{base}/login?next={encodeURIComponent(`${base}/rbac`)}" class="vs-btn-primary text-sm">Sign In</a>
		</div>
	{:else}
		<div class="grid gap-6 lg:grid-cols-3">
			<section class="vs-card p-5 space-y-4">
				<h2 class="text-base font-semibold text-[#fde68a]">Roles ({roles.length})</h2>
				<form onsubmit={handleCreateRole} class="space-y-2">
					<input type="text" bind:value={roleName} placeholder="Role name (e.g. vault-editor)" class="vs-input" required />
					<input type="text" bind:value={roleAppId} placeholder="App ID (blank = org-wide)" class="vs-input" />
					<button type="submit" class="vs-btn-primary w-full text-xs">Create Role</button>
				</form>
				<ul class="space-y-1.5 text-xs">
					{#each roles as r}
						<li class="rounded border border-[#292524] bg-[#0c0a09] px-2.5 py-2 flex justify-between gap-2">
							<span class="font-mono text-[#fafaf9]">{r.app_id ? `${r.app_id}:${r.name}` : r.name}</span>
							<span class="text-[#a8a29e]">{r.app_id ? 'per-app' : 'org-wide'}</span>
						</li>
					{/each}
				</ul>
			</section>

			<section class="vs-card p-5 space-y-4">
				<h2 class="text-base font-semibold text-[#fde68a]">Permissions ({perms.length})</h2>
				<form onsubmit={handleCreatePerm} class="space-y-2">
					<input type="text" bind:value={permName} placeholder="Permission (e.g. secrets:rotate)" class="vs-input" required />
					<input type="text" bind:value={permAppId} placeholder="App ID (blank = org-wide)" class="vs-input" />
					<button type="submit" class="vs-btn-primary w-full text-xs">Create Permission</button>
				</form>
				<ul class="space-y-1.5 text-xs">
					{#each perms as p}
						<li class="rounded border border-[#292524] bg-[#0c0a09] px-2.5 py-2 flex justify-between gap-2">
							<span class="font-mono text-[#fafaf9]">{p.app_id ? `${p.app_id}:${p.name}` : p.name}</span>
							<span class="text-[#a8a29e]">{p.app_id ? 'per-app' : 'org-wide'}</span>
						</li>
					{/each}
				</ul>
			</section>

			<section class="vs-card p-5 space-y-4">
				<h2 class="text-base font-semibold text-[#fde68a]">Groups ({groups.length})</h2>
				<form onsubmit={handleCreateGroup} class="space-y-2">
					<input type="text" bind:value={groupName} placeholder="Group name (e.g. engineering)" class="vs-input" required />
					<button type="submit" class="vs-btn-primary w-full text-xs">Create Group</button>
				</form>
				<ul class="space-y-1.5 text-xs">
					{#each groups as g}
						<li class="rounded border border-[#292524] bg-[#0c0a09] px-2.5 py-2 flex justify-between gap-2">
							<span class="font-mono text-[#fafaf9]">{g.name}</span>
							<span class="text-[#a8a29e]">{g.external_id ?? 'local'}</span>
						</li>
					{/each}
				</ul>
			</section>
		</div>

		<section class="grid gap-6 md:grid-cols-2">
			<form onsubmit={handleGrantPerm} class="vs-card p-5 space-y-3">
				<h3 class="text-sm font-semibold text-[#fde68a]">Assign Permission → Role</h3>
				<select bind:value={grantRoleId} class="vs-input" required>
					<option value="">Select role...</option>
					{#each roles as r}
						<option value={r.id}>{r.app_id ? `${r.app_id}:${r.name}` : r.name}</option>
					{/each}
				</select>
				<select bind:value={grantPermId} class="vs-input" required>
					<option value="">Select permission...</option>
					{#each perms as p}
						<option value={p.id}>{p.app_id ? `${p.app_id}:${p.name}` : p.name}</option>
					{/each}
				</select>
				<button type="submit" class="vs-btn-secondary w-full text-xs">Grant Permission</button>
			</form>

			<form onsubmit={handleAssignGroupRole} class="vs-card p-5 space-y-3">
				<h3 class="text-sm font-semibold text-[#fde68a]">Assign Role → Group</h3>
				<select bind:value={linkGroupId} class="vs-input" required>
					<option value="">Select group...</option>
					{#each groups as g}
						<option value={g.id}>{g.name}</option>
					{/each}
				</select>
				<select bind:value={linkRoleId} class="vs-input" required>
					<option value="">Select role...</option>
					{#each roles as r}
						<option value={r.id}>{r.app_id ? `${r.app_id}:${r.name}` : r.name}</option>
					{/each}
				</select>
				<button type="submit" class="vs-btn-secondary w-full text-xs">Assign Role to Group</button>
			</form>
		</section>

		{#if effective}
			<section class="vs-card p-5 space-y-2 text-xs">
				<div class="font-semibold text-[#fde68a]">Your Effective Resolved Access (app={inspectAppId})</div>
				<div class="text-[#d6d3d1]"><strong>Groups:</strong> {effective.groups.join(', ') || 'none'}</div>
				<div class="text-[#d6d3d1]"><strong>Roles:</strong> {effective.roles.join(', ') || 'none'}</div>
				<div class="text-[#d6d3d1]"><strong>Permissions:</strong> {effective.permissions.join(', ') || 'none'}</div>
			</section>
		{/if}
	{/if}
</div>
