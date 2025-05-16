// worker.js
import { jwtVerify } from 'jose';

const ISSUER = 'https://login.authorium.com/';
const AUDIENCE = 'docs.authorium.com';

export default {
	async fetch(request, env) {
		const url = new URL(request.url);
		const host = url.hostname;
		const fullUrl = url.toString();
		const oktaLink = env.OKTA_EMBED_LINK;

		// 1) If it’s your docs host but no valid token → redirect to Okta
		if (host === 'authorium-test.writedocs.io') {
			// try to pull the token from cookie / auth header...
			const ck = request.headers.get('Cookie') || '';
			let token = ck.match(/(?:^|; )token=([^;]+)/)?.[1];
			if (!token) {
				const auth = request.headers.get('Authorization') || '';
				if (auth.startsWith('Bearer ')) token = auth.slice(7).trim();
			}

			if (!token) {
				// include the original URL so Okta can send them back
				const redirectParam = `?fromURI=${encodeURIComponent(fullUrl)}`;
				return Response.redirect(oktaLink + redirectParam, 302);
			}

			// …otherwise, verify as before…
			try {
				const secret = new TextEncoder().encode(env.JWT_SECRET);
				await jwtVerify(token, secret, { issuer: ISSUER, audience: AUDIENCE });
			} catch {
				// invalid token → same redirect
				const redirectParam = `?fromURI=${encodeURIComponent(fullUrl)}`;
				return Response.redirect(oktaLink + redirectParam, 302);
			}
		}

		// 2) Proxy through to your static docs
		return fetch(request);
	},
};
