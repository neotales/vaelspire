// Browser WebAuthn (Passkey) helpers using native navigator.credentials API.

function base64UrlToBytes(input: string): Uint8Array {
	const padded = input.replace(/-/g, '+').replace(/_/g, '/');
	const padLen = (4 - (padded.length % 4)) % 4;
	const binary = atob(padded + '='.repeat(padLen));
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i++) {
		bytes[i] = binary.charCodeAt(i);
	}
	return bytes;
}

function bytesToBase64Url(buf: ArrayBuffer): string {
	const bytes = new Uint8Array(buf);
	let binary = '';
	for (let i = 0; i < bytes.length; i++) {
		binary += String.fromCharCode(bytes[i]);
	}
	return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function isWebAuthnSupported(): boolean {
	return (
		typeof window !== 'undefined' &&
		typeof navigator !== 'undefined' &&
		typeof navigator.credentials !== 'undefined' &&
		typeof PublicKeyCredential !== 'undefined'
	);
}

export async function createBrowserPasskey(
	challengeResponse: Record<string, unknown>
): Promise<Record<string, unknown>> {
	const pubKey = (challengeResponse.publicKey ?? challengeResponse) as Record<string, unknown>;
	const user = pubKey.user as Record<string, unknown>;
	const exclude = Array.isArray(pubKey.excludeCredentials)
		? pubKey.excludeCredentials.map((c: Record<string, unknown>) => ({
				...c,
				id: base64UrlToBytes(String(c.id))
			}))
		: [];

	const publicKeyOptions: PublicKeyCredentialCreationOptions = {
		...(pubKey as unknown as PublicKeyCredentialCreationOptions),
		challenge: base64UrlToBytes(String(pubKey.challenge)) as BufferSource,
		user: {
			...(user as unknown as PublicKeyCredentialUserEntity),
			id: base64UrlToBytes(String(user.id)) as BufferSource
		},
		excludeCredentials: exclude as unknown as PublicKeyCredentialDescriptor[]
	};

	const cred = (await navigator.credentials.create({
		publicKey: publicKeyOptions
	})) as PublicKeyCredential | null;
	if (!cred) {
		throw new Error('Passkey registration was cancelled.');
	}
	const resp = cred.response as AuthenticatorAttestationResponse;
	return {
		id: cred.id,
		rawId: bytesToBase64Url(cred.rawId),
		type: cred.type,
		response: {
			attestationObject: bytesToBase64Url(resp.attestationObject),
			clientDataJSON: bytesToBase64Url(resp.clientDataJSON)
		}
	};
}

export async function authenticateBrowserPasskey(
	challengeResponse: Record<string, unknown>
): Promise<Record<string, unknown>> {
	const pubKey = (challengeResponse.publicKey ?? challengeResponse) as Record<string, unknown>;
	const allow = Array.isArray(pubKey.allowCredentials)
		? pubKey.allowCredentials.map((c: Record<string, unknown>) => ({
				...c,
				id: base64UrlToBytes(String(c.id))
			}))
		: [];

	const publicKeyOptions: PublicKeyCredentialRequestOptions = {
		...(pubKey as unknown as PublicKeyCredentialRequestOptions),
		challenge: base64UrlToBytes(String(pubKey.challenge)) as BufferSource,
		allowCredentials: allow as unknown as PublicKeyCredentialDescriptor[]
	};

	const cred = (await navigator.credentials.get({
		publicKey: publicKeyOptions
	})) as PublicKeyCredential | null;
	if (!cred) {
		throw new Error('Passkey sign-in was cancelled.');
	}
	const resp = cred.response as AuthenticatorAssertionResponse;
	return {
		id: cred.id,
		rawId: bytesToBase64Url(cred.rawId),
		type: cred.type,
		response: {
			authenticatorData: bytesToBase64Url(resp.authenticatorData),
			clientDataJSON: bytesToBase64Url(resp.clientDataJSON),
			signature: bytesToBase64Url(resp.signature),
			userHandle: resp.userHandle ? bytesToBase64Url(resp.userHandle) : null
		}
	};
}
