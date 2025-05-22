// worker.js
import { jwtVerify } from 'jose';

const ISSUER = 'https://app.authorium.com';
const AUDIENCE = 'docs.authorium.com';
const PROTECTED_HOSTS = new Set(['docs.authorium.com', 'authorium.writedocs.io']);
const OKTA_LINK = 'https://authorium.okta.com/home/authorium_authoriumdocs_1/0oafoc1fp1tjmCraq4h7/alnfoc2pvn29cVcFU4h7';

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const host = url.hostname;
		const fullUrl = url.toString();

		if (PROTECTED_HOSTS.has(host)) {
			// 1) Extract token from cookie or Authorization header
			const ck = request.headers.get('Cookie') || '';
			let token = ck.match(/(?:^|; )token=([^;]+)/)?.[1];
			if (!token) {
				const auth = request.headers.get('Authorization') || '';
				if (auth.startsWith('Bearer ')) token = auth.slice(7).trim();
			}

			// 2) No token → redirect to Okta SSO
			if (!token) {
				const redirectParam = `?fromURI=${encodeURIComponent(fullUrl)}`;
				return Response.redirect(OKTA_LINK + redirectParam, 302);
			}

			// 3) Verify JWT
			try {
				const secretUint8 = new TextEncoder().encode(env.JWT_SECRET);
				const { payload } = await jwtVerify(token, secretUint8, {
					issuer: ISSUER,
					audience: AUDIENCE,
				});

				// 4) Proxy the request and inject user_info cookie
				const upstream = await fetch(request);
				const userInfo = {
					...payload,
				};
				const userB64 = btoa(JSON.stringify(userInfo));
				const response = new Response(upstream.body, upstream);
				response.headers.append('Set-Cookie', `user_info=${userB64}; Path=/; Secure; SameSite=Lax`);
				return response;
			} catch (err) {
				return new Response(`Unauthorized – ${err.message}`, { status: 401 });
				// invalid token → redirect to Okta again
				// const redirectParam = `?fromURI=${encodeURIComponent(fullUrl)}`;
				// return Response.redirect(OKTA_LINK + redirectParam, 302);
			}
		}

		// 5) All other hosts: just proxy
		return fetch(request);
	},
};
