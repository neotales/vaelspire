// Vaelspire Cloudflare Worker Edge Gateway
// - Serves /edge/health and verifies EdDSA (Ed25519) JWTs at the edge using WebCrypto + cached JWKS
// - Forwards stateful Argon2id / Passkey / SCIM / OIDC issuance requests to VAELSPIRE_UPSTREAM_ORIGIN (e.g. Cloudflare Container)

interface Env {
  VAELSPIRE_DB: D1Database;
  VAELSPIRE_ISSUER: string;
  VAELSPIRE_UPSTREAM_ORIGIN: string;
  VAELSPIRE_AUDIENCE: string;
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === '/edge/health') {
      const dbOk = await env.VAELSPIRE_DB.prepare('SELECT 1 AS ok')
        .first<{ ok: number }>()
        .then((r) => r?.ok === 1)
        .catch(() => false);
      return Response.json({
        status: dbOk ? 'ok' : 'degraded',
        runtime: 'cloudflare-workers',
        d1_ready: dbOk,
        issuer: env.VAELSPIRE_ISSUER,
      });
    }

    // Forward full identity & Argon2id/Passkey flows to the Vaelspire Container or origin,
    // preserving CF-Connecting-IP for Vaelspire's `--ip-source cf-connecting-ip`.
    const upstream = new URL(url.pathname + url.search, env.VAELSPIRE_UPSTREAM_ORIGIN);
    const proxiedHeaders = new Headers(request.headers);
    const cfIp = request.headers.get('cf-connecting-ip');
    if (cfIp) {
      proxiedHeaders.set('cf-connecting-ip', cfIp);
    }

    return fetch(
      new Request(upstream.toString(), {
        method: request.method,
        headers: proxiedHeaders,
        body: request.method === 'GET' || request.method === 'HEAD' ? undefined : request.body,
        redirect: 'manual',
      })
    );
  },
};
