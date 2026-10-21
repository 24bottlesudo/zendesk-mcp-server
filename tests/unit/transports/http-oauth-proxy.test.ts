import { HttpResponse, http } from 'msw';
import { afterEach, describe, expect, it } from 'vitest';
import type { Config } from '../../../src/config';
import { startHttpTransport } from '../../../src/transports/http';
import { mswServer } from '../../setup';

const baseConfig: Config = {
  subdomain: 'testsubdomain',
  oauthClientId: 'test_zendesk',
  logLevel: 'error',
  mode: 'all',
  readOnly: false,
  transport: 'http',
  host: '127.0.0.1',
  port: 0,
  corsOrigins: [],
  publicUrl: 'https://mcp.example.com',
};

const ZENDESK_TOKEN_URL = 'https://testsubdomain.zendesk.com/oauth/tokens';

describe('OAuth proxy routes (/authorize and /token)', () => {
  let handle: Awaited<ReturnType<typeof startHttpTransport>> | undefined;

  afterEach(async () => {
    await handle?.close();
    handle = undefined;
  });

  describe('GET /authorize', () => {
    const authorizeQuery = new URLSearchParams({
      response_type: 'code',
      client_id: 'testsubdomain_zendesk',
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
      code_challenge: 'abc123challenge',
      code_challenge_method: 'S256',
      state: 'xyz-state',
      scope: 'read write',
      resource: 'https://mcp.example.com',
    });

    it('redirects (302) to the Zendesk authorization endpoint', async () => {
      handle = await startHttpTransport(baseConfig);
      const res = await fetch(`http://127.0.0.1:${handle.port}/authorize?${authorizeQuery}`, {
        redirect: 'manual',
      });
      expect(res.status).toBe(302);
      const location = new URL(res.headers.get('location') ?? '');
      expect(location.origin).toBe('https://testsubdomain.zendesk.com');
      expect(location.pathname).toBe('/oauth/authorizations/new');
    });

    it('preserves the PKCE and client parameters', async () => {
      handle = await startHttpTransport(baseConfig);
      const res = await fetch(`http://127.0.0.1:${handle.port}/authorize?${authorizeQuery}`, {
        redirect: 'manual',
      });
      const params = new URL(res.headers.get('location') ?? '').searchParams;
      expect(params.get('response_type')).toBe('code');
      expect(params.get('client_id')).toBe('testsubdomain_zendesk');
      expect(params.get('redirect_uri')).toBe('https://claude.ai/api/mcp/auth_callback');
      expect(params.get('code_challenge')).toBe('abc123challenge');
      expect(params.get('code_challenge_method')).toBe('S256');
      expect(params.get('state')).toBe('xyz-state');
      expect(params.get('scope')).toBe('read write');
    });

    it('drops the RFC 8707 resource parameter, which Zendesk does not understand', async () => {
      handle = await startHttpTransport(baseConfig);
      const res = await fetch(`http://127.0.0.1:${handle.port}/authorize?${authorizeQuery}`, {
        redirect: 'manual',
      });
      const params = new URL(res.headers.get('location') ?? '').searchParams;
      expect(params.has('resource')).toBe(false);
    });

    it('rejects non-GET methods with 405', async () => {
      handle = await startHttpTransport(baseConfig);
      const res = await fetch(`http://127.0.0.1:${handle.port}/authorize`, { method: 'POST' });
      expect(res.status).toBe(405);
    });
  });

  describe('POST /token', () => {
    const tokenForm = new URLSearchParams({
      grant_type: 'authorization_code',
      code: 'auth-code-1',
      redirect_uri: 'https://claude.ai/api/mcp/auth_callback',
      client_id: 'testsubdomain_zendesk',
      code_verifier: 'verifier-1',
      resource: 'https://mcp.example.com',
    });

    const postToken = (port: number, body: URLSearchParams) =>
      fetch(`http://127.0.0.1:${port}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: body.toString(),
      });

    it('forwards the form body to the Zendesk token endpoint and returns its response', async () => {
      let forwarded = '';
      let forwardedContentType: string | null = null;
      mswServer.use(
        http.post(ZENDESK_TOKEN_URL, async ({ request }) => {
          forwarded = await request.text();
          forwardedContentType = request.headers.get('content-type');
          return HttpResponse.json({
            access_token: 'zd-access',
            token_type: 'bearer',
            scope: 'read write',
          });
        }),
      );
      handle = await startHttpTransport(baseConfig);

      const res = await postToken(handle.port, tokenForm);

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({
        access_token: 'zd-access',
        token_type: 'bearer',
        scope: 'read write',
      });
      expect(forwardedContentType).toContain('application/x-www-form-urlencoded');
      const sent = new URLSearchParams(forwarded);
      expect(sent.get('grant_type')).toBe('authorization_code');
      expect(sent.get('code')).toBe('auth-code-1');
      expect(sent.get('code_verifier')).toBe('verifier-1');
      expect(sent.get('client_id')).toBe('testsubdomain_zendesk');
      expect(sent.has('resource')).toBe(false);
    });

    it('marks the token response as non-cacheable (RFC 6749 section 5.1)', async () => {
      mswServer.use(
        http.post(ZENDESK_TOKEN_URL, () =>
          HttpResponse.json({ access_token: 'zd-access', token_type: 'bearer' }),
        ),
      );
      handle = await startHttpTransport(baseConfig);

      const res = await postToken(handle.port, tokenForm);

      expect(res.headers.get('cache-control')).toBe('no-store');
    });

    it('passes a Zendesk error status and body through unchanged', async () => {
      mswServer.use(
        http.post(ZENDESK_TOKEN_URL, () =>
          HttpResponse.json({ error: 'invalid_grant' }, { status: 400 }),
        ),
      );
      handle = await startHttpTransport(baseConfig);

      const res = await postToken(handle.port, tokenForm);

      expect(res.status).toBe(400);
      expect(await res.json()).toEqual({ error: 'invalid_grant' });
    });

    it('supports the refresh_token grant', async () => {
      let forwarded = '';
      mswServer.use(
        http.post(ZENDESK_TOKEN_URL, async ({ request }) => {
          forwarded = await request.text();
          return HttpResponse.json({ access_token: 'zd-new', token_type: 'bearer' });
        }),
      );
      handle = await startHttpTransport(baseConfig);

      const res = await postToken(
        handle.port,
        new URLSearchParams({
          grant_type: 'refresh_token',
          refresh_token: 'refresh-1',
          client_id: 'testsubdomain_zendesk',
        }),
      );

      expect(res.status).toBe(200);
      const sent = new URLSearchParams(forwarded);
      expect(sent.get('grant_type')).toBe('refresh_token');
      expect(sent.get('refresh_token')).toBe('refresh-1');
    });

    it('returns 502 with an OAuth server_error when Zendesk is unreachable', async () => {
      mswServer.use(http.post(ZENDESK_TOKEN_URL, () => HttpResponse.error()));
      handle = await startHttpTransport(baseConfig);

      const res = await postToken(handle.port, tokenForm);

      expect(res.status).toBe(502);
      const body = (await res.json()) as { error: string; error_description: string };
      expect(body.error).toBe('server_error');
      expect(body.error_description).toMatch(/^[\x20-\x7e]+$/);
    });

    it('rejects an oversized body with 413', async () => {
      handle = await startHttpTransport(baseConfig);
      const res = await fetch(`http://127.0.0.1:${handle.port}/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: `code=${'a'.repeat(128 * 1024)}`,
      });
      expect(res.status).toBe(413);
    });

    it('rejects non-POST methods with 405', async () => {
      handle = await startHttpTransport(baseConfig);
      const res = await fetch(`http://127.0.0.1:${handle.port}/token`);
      expect(res.status).toBe(405);
    });
  });
});
