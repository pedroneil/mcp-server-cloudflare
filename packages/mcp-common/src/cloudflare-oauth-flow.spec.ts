import { getOAuthApi } from '@cloudflare/workers-oauth-provider'
import { env } from 'cloudflare:test'
import { http, HttpResponse } from 'msw'
import { describe, expect, it } from 'vitest'

import { createAuthHandlers } from './cloudflare-oauth-handler'
import { createCloudflareOAuthRouter } from './oauth-router'
import { server } from './test/msw-server'

import type { OAuthProviderOptions } from '@cloudflare/workers-oauth-provider'
import type { MetricsTracker } from '@repo/mcp-observability'
import type { CloudflareOAuthEnv } from './oauth-router'

// The authorize, consent and callback routes against the real workers-oauth-provider helpers and
// KV; only Cloudflare's token endpoint and API are mocked.

const ORIGIN = 'https://mcp.example.com'
const RESOURCE = `${ORIGIN}/mcp`
const CLIENT_REDIRECT = 'https://client.example.com/callback'
const SCOPES = { 'account:read': 'Read accounts', 'user:read': 'Read user' }
const metrics = { logEvent() {} } as unknown as MetricsTracker
const kv = (env as unknown as { OAUTH_KV: KVNamespace }).OAUTH_KV

const providerOptions = {
	apiRoute: '/mcp',
	apiHandler: { fetch: () => new Response('unused') },
	defaultHandler: { fetch: () => new Response('unused') },
	authorizeEndpoint: '/oauth/authorize',
	tokenEndpoint: '/token',
	clientRegistrationEndpoint: '/register',
	resourceMetadata: { resource: RESOURCE },
} satisfies OAuthProviderOptions<{ OAUTH_KV: KVNamespace }>

const helpers = getOAuthApi(providerOptions, { OAUTH_KV: kv })
const authEnv = {
	OAUTH_KV: kv,
	OAUTH_PROVIDER: helpers,
	MCP_COOKIE_ENCRYPTION_KEY: 'test-cookie-encryption-key',
	CLOUDFLARE_CLIENT_ID: 'cf-client',
	CLOUDFLARE_CLIENT_SECRET: 'cf-secret',
}
const executionCtx = {
	props: {},
	waitUntil() {},
	passThroughOnException() {},
} as ExecutionContext

/** One browser: keeps the cookies the routes set. */
class Browser {
	private cookies = new Map<string, string>()
	private app = createAuthHandlers({ scopes: SCOPES, metrics })

	async fetch(url: string, init: RequestInit = {}): Promise<Response> {
		const headers = new Headers(init.headers)
		if (this.cookies.size > 0) {
			headers.set('Cookie', [...this.cookies].map(([k, v]) => `${k}=${v}`).join('; '))
		}
		const response = await this.app.fetch(
			new Request(new URL(url, ORIGIN), { ...init, headers }),
			authEnv,
			executionCtx
		)
		for (const cookie of response.headers.getSetCookie()) {
			const [pair, ...attributes] = cookie.split(';')
			const [name, value] = pair.split('=')
			if (attributes.some((a) => a.trim().toLowerCase() === 'max-age=0')) this.cookies.delete(name)
			else this.cookies.set(name, value)
		}
		return response
	}

	postConsent(handle: string, decision: 'approve' | 'deny') {
		return this.fetch('/oauth/authorize', {
			method: 'POST',
			headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
			body: new URLSearchParams({ handle, decision }),
		})
	}
}

async function s256(value: string): Promise<string> {
	const digest = new Uint8Array(
		await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value))
	)
	return btoa(String.fromCharCode(...digest))
		.replace(/\+/g, '-')
		.replace(/\//g, '_')
		.replace(/=+$/, '')
}

async function authorizeUrl(): Promise<string> {
	const client = await helpers.createClient({
		redirectUris: [CLIENT_REDIRECT],
		tokenEndpointAuthMethod: 'none',
		clientName: 'Flow Test Client',
	})
	const params = new URLSearchParams({
		response_type: 'code',
		client_id: client.clientId,
		redirect_uri: CLIENT_REDIRECT,
		state: 'client-state',
		code_challenge: await s256('client-verifier-'.repeat(4)),
		code_challenge_method: 'S256',
		resource: RESOURCE,
	})
	return `/oauth/authorize?${params}`
}

function consentHandle(html: string): string {
	const handle = html.match(/name="handle" value="([^"]+)"/)?.[1]
	if (!handle) throw new Error('consent page has no handle')
	return handle
}

/** Mock Cloudflare's token endpoint and identity API; returns the token request's form. */
function mockCloudflare(): { tokenForm?: URLSearchParams } {
	const seen: { tokenForm?: URLSearchParams } = {}
	server.use(
		http.post('https://dash.cloudflare.com/oauth2/token', async ({ request }) => {
			seen.tokenForm = new URLSearchParams(await request.text())
			return HttpResponse.json({
				access_token: 'cf-access',
				refresh_token: 'cf-refresh',
				expires_in: 3600,
				scope: 'account:read user:read',
				token_type: 'bearer',
			})
		}),
		http.get('https://api.cloudflare.com/client/v4/user', () =>
			HttpResponse.json({
				success: true,
				result: { id: 'user-1', email: 'user@example.com' },
				errors: [],
				messages: [],
			})
		),
		http.get('https://api.cloudflare.com/client/v4/accounts', () =>
			HttpResponse.json({
				success: true,
				result: [{ id: 'account-1', name: 'Account One' }],
				errors: [],
				messages: [],
			})
		)
	)
	return seen
}

describe('OAuth consent and Cloudflare sign-in', () => {
	it('approves, signs in at Cloudflare, and returns a code to the client', async () => {
		const browser = new Browser()
		const page = await browser.fetch(await authorizeUrl())
		expect(page.status).toBe(200)
		expect(page.headers.get('x-frame-options')).toBe('DENY')
		const html = await page.text()
		expect(html).toContain('Flow Test Client')
		expect(html).toContain(CLIENT_REDIRECT)

		const toCloudflare = await browser.postConsent(consentHandle(html), 'approve')
		expect(toCloudflare.status).toBe(302)
		const cloudflareUrl = new URL(toCloudflare.headers.get('location') ?? '')
		expect(cloudflareUrl.origin + cloudflareUrl.pathname).toBe(
			'https://dash.cloudflare.com/oauth2/auth'
		)
		expect(cloudflareUrl.searchParams.get('redirect_uri')).toBe(`${ORIGIN}/oauth/callback`)
		expect(cloudflareUrl.searchParams.get('scope')).toBe('account:read user:read')
		const state = cloudflareUrl.searchParams.get('state') ?? ''

		const seen = mockCloudflare()
		const callback = `/oauth/callback?code=cf-code&state=${encodeURIComponent(state)}`
		const toClient = await browser.fetch(callback)
		expect(toClient.status).toBe(302)
		const clientUrl = new URL(toClient.headers.get('location') ?? '')
		expect(clientUrl.origin + clientUrl.pathname).toBe(CLIENT_REDIRECT)
		expect(clientUrl.searchParams.get('state')).toBe('client-state')
		expect(clientUrl.searchParams.get('code')).toBeTruthy()

		// The PKCE verifier beginUpstream() kept server-side matches the challenge sent to Cloudflare.
		expect(seen.tokenForm?.get('code')).toBe('cf-code')
		expect(await s256(seen.tokenForm?.get('code_verifier') ?? '')).toBe(
			cloudflareUrl.searchParams.get('code_challenge')
		)

		// The upstream state works once.
		const replay = await browser.fetch(callback)
		expect(replay.status).toBe(400)
	})

	it('skips the consent page for a client this browser already approved', async () => {
		const browser = new Browser()
		const url = await authorizeUrl()
		const page = await browser.fetch(url)
		await browser.postConsent(consentHandle(await page.text()), 'approve')

		const again = await browser.fetch(url)
		expect(again.status).toBe(302)
		expect(new URL(again.headers.get('location') ?? '').host).toBe('dash.cloudflare.com')

		// Another browser is asked.
		const elsewhere = await new Browser().fetch(url)
		expect(elsewhere.status).toBe(200)
	})

	it('sends access_denied back to the client when the user cancels', async () => {
		const browser = new Browser()
		const page = await browser.fetch(await authorizeUrl())

		const denied = await browser.postConsent(consentHandle(await page.text()), 'deny')
		expect(denied.status).toBe(302)
		const clientUrl = new URL(denied.headers.get('location') ?? '')
		expect(clientUrl.origin + clientUrl.pathname).toBe(CLIENT_REDIRECT)
		expect(clientUrl.searchParams.get('error')).toBe('access_denied')
		expect(clientUrl.searchParams.get('state')).toBe('client-state')
	})

	it('sends access_denied back to the client when Cloudflare sign-in is declined', async () => {
		const browser = new Browser()
		const page = await browser.fetch(await authorizeUrl())
		const toCloudflare = await browser.postConsent(consentHandle(await page.text()), 'approve')
		const state = new URL(toCloudflare.headers.get('location') ?? '').searchParams.get('state')

		const declined = await browser.fetch(
			`/oauth/callback?error=access_denied&state=${encodeURIComponent(state ?? '')}`
		)
		expect(declined.status).toBe(302)
		const clientUrl = new URL(declined.headers.get('location') ?? '')
		expect(clientUrl.origin + clientUrl.pathname).toBe(CLIENT_REDIRECT)
		expect(clientUrl.searchParams.get('error')).toBe('access_denied')
		expect(clientUrl.searchParams.get('state')).toBe('client-state')
	})

	it('refuses a consent form or callback from another browser', async () => {
		const browser = new Browser()
		const page = await browser.fetch(await authorizeUrl())
		const handle = consentHandle(await page.text())

		const forged = await new Browser().postConsent(handle, 'approve')
		expect(forged.status).toBe(400)

		const toCloudflare = await browser.postConsent(handle, 'approve')
		const state = new URL(toCloudflare.headers.get('location') ?? '').searchParams.get('state')
		const stolen = await new Browser().fetch(
			`/oauth/callback?code=cf-code&state=${encodeURIComponent(state ?? '')}`
		)
		expect(stolen.status).toBe(400)
	})
})

// 0.x advertised a resource per URL: `/mcp`, `/sse`, and the bare origin at the root metadata URL.
// Grants bound to the last two can't be refreshed now; the client must be told to sign in again.
describe('grants made before the move to /mcp', () => {
	const router = createCloudflareOAuthRouter<CloudflareOAuthEnv>({
		apiHandler: { fetch: () => new Response('ok') },
		scopes: SCOPES,
		metrics,
		mcpRequestPolicy: {
			allowedHostnames: ['mcp.example.com'],
			allowedOriginHostnames: ['mcp.example.com'],
		},
	})
	const routerEnv = {
		...authEnv,
		DEV_CLOUDFLARE_API_TOKEN: '',
		DEV_CLOUDFLARE_EMAIL: '',
		DEV_DISABLE_OAUTH: 'false',
	} as unknown as CloudflareOAuthEnv
	const token = (body: Record<string, string>) =>
		router.fetch(
			new Request(`${ORIGIN}/token`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
				body: new URLSearchParams(body),
			}),
			routerEnv,
			executionCtx
		)

	it.each([
		['the bare origin', `${ORIGIN}/`],
		['/sse', `${ORIGIN}/sse`],
	])(
		'answers a refresh of a grant bound to %s with invalid_grant, so the client signs in again',
		async (_label, oldResource) => {
			const authRequest = await helpers.parseAuthRequest(
				new Request(new URL(await authorizeUrl(), ORIGIN))
			)
			const { redirectTo } = await helpers.completeAuthorization({
				request: authRequest,
				userId: 'user-1',
				metadata: {},
				scope: authRequest.scope,
				props: {},
			})
			const issued = await token({
				grant_type: 'authorization_code',
				code: new URL(redirectTo).searchParams.get('code') ?? '',
				redirect_uri: CLIENT_REDIRECT,
				code_verifier: 'client-verifier-'.repeat(4),
				client_id: authRequest.clientId,
				resource: RESOURCE,
			})
			expect(issued.status).toBe(200)
			const { refresh_token: refreshToken } = await issued.json<{ refresh_token: string }>()

			// Store the grant as a 0.x server bound it.
			const [userId, grantId] = refreshToken.split(':')
			const grantKey = `grant:${userId}:${grantId}`
			const grant = await kv.get<Record<string, unknown>>(grantKey, 'json')
			await kv.put(grantKey, JSON.stringify({ ...grant, resource: oldResource }))

			// MCP clients repeat their grant's resource on refresh.
			const refreshed = await token({
				grant_type: 'refresh_token',
				refresh_token: refreshToken,
				client_id: authRequest.clientId,
				resource: oldResource,
			})
			expect(refreshed.status).toBe(400)
			await expect(refreshed.json()).resolves.toMatchObject({ error: 'invalid_grant' })
		}
	)
})

describe('createCloudflareOAuthRouter OAuth lifecycle', () => {
	const router = createCloudflareOAuthRouter<CloudflareOAuthEnv>({
		apiHandler: { fetch: () => new Response('ok') },
		scopes: SCOPES,
		metrics,
		mcpRequestPolicy: {
			allowedHostnames: ['mcp.example.com'],
			allowedOriginHostnames: ['mcp.example.com'],
		},
	})
	const routerEnv = {
		...authEnv,
		DEV_CLOUDFLARE_API_TOKEN: '',
		DEV_CLOUDFLARE_EMAIL: '',
		DEV_DISABLE_OAUTH: 'false',
	} as unknown as CloudflareOAuthEnv

	it('slides grant expiry on refresh and renews active DCR client registrations past 30 and 90 days', async () => {
		mockCloudflare()

		const registered = await router.fetch(
			new Request(`${ORIGIN}/register`, {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({
					redirect_uris: [CLIENT_REDIRECT],
					token_endpoint_auth_method: 'none',
					client_name: 'VS Code MCP Client',
				}),
			}),
			routerEnv,
			executionCtx
		)
		expect(registered.status).toBe(201)
		const { client_id: clientId } = await registered.json<{ client_id: string }>()

		const verifier = 'client-verifier-'.repeat(4)
		const authUrl = new URL(`${ORIGIN}/oauth/authorize`)
		authUrl.searchParams.set('response_type', 'code')
		authUrl.searchParams.set('client_id', clientId)
		authUrl.searchParams.set('redirect_uri', CLIENT_REDIRECT)
		authUrl.searchParams.set('state', 'client-state')
		authUrl.searchParams.set('code_challenge', await s256(verifier))
		authUrl.searchParams.set('code_challenge_method', 'S256')
		authUrl.searchParams.set('resource', RESOURCE)

		const authRequest = await helpers.parseAuthRequest(new Request(authUrl))
		const { redirectTo } = await helpers.completeAuthorization({
			request: authRequest,
			userId: 'user-1',
			metadata: {},
			scope: authRequest.scope,
			props: {
				type: 'user_token',
				accessToken: 'cf-access-initial',
				refreshToken: 'cf-refresh-initial',
				user: { id: 'user-1', email: 'user@example.com' },
				accounts: [{ id: 'account-1', name: 'Account One' }],
			},
		})

		const token = (body: Record<string, string>) =>
			router.fetch(
				new Request(`${ORIGIN}/token`, {
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams(body),
				}),
				routerEnv,
				executionCtx
			)

		const issued = await token({
			grant_type: 'authorization_code',
			code: new URL(redirectTo).searchParams.get('code') ?? '',
			redirect_uri: CLIENT_REDIRECT,
			code_verifier: verifier,
			client_id: clientId,
			resource: RESOURCE,
		})
		expect(issued.status).toBe(200)
		const { refresh_token: firstRefreshToken } = await issued.json<{ refresh_token: string }>()

		const [userId, grantId] = firstRefreshToken.split(':')
		const grantKey = `grant:${userId}:${grantId}`
		const clientKey = `client:${clientId}`

		const initialGrant = await kv.get<{ expiresAt: number }>(grantKey, 'json')
		const initialClient = await kv.get<{ registrationExpiresAt: number }>(clientKey, 'json')
		expect(initialGrant?.expiresAt).toBeDefined()
		expect(initialClient?.registrationExpiresAt).toBeDefined()

		// Simulate 20 days elapsed: the grant has 10 days left, and the DCR client has 40 days left
		// (past half of its 90-day clientRegistrationTTL, so renewal is due on the next refresh).
		const now = Math.floor(Date.now() / 1000)
		const agedGrantExpiry = now + 10 * 24 * 60 * 60
		const agedClientExpiry = now + 40 * 24 * 60 * 60
		await kv.put(grantKey, JSON.stringify({ ...initialGrant, expiresAt: agedGrantExpiry }))
		await kv.put(
			clientKey,
			JSON.stringify({ ...initialClient, registrationExpiresAt: agedClientExpiry })
		)

		const refreshed = await token({
			grant_type: 'refresh_token',
			refresh_token: firstRefreshToken,
			client_id: clientId,
			resource: RESOURCE,
		})
		expect(refreshed.status).toBe(200)

		const updatedGrant = await kv.get<{ expiresAt: number }>(grantKey, 'json')
		const updatedClient = await kv.get<{ registrationExpiresAt: number }>(clientKey, 'json')

		// Grant expiry slid forward to ~30 days from now instead of staying capped at the initial 30-day cliff.
		expect(updatedGrant!.expiresAt).toBeGreaterThanOrEqual(now + 30 * 24 * 60 * 60 - 10)
		// Active DCR client registration renewed back to ~90 days from now so it never expires while in use.
		expect(updatedClient!.registrationExpiresAt).toBeGreaterThanOrEqual(
			now + 90 * 24 * 60 * 60 - 10
		)
	})
})
