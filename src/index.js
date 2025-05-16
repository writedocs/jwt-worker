// worker.js
import { jwtVerify } from 'jose';

/**
 * Configuration
 */
const ISSUER = 'https://login.authorium.com/';
const AUDIENCE = 'docs.authorium.com';

export default {
	/**
	 * @param {Request} request
	 * @param {Object}  env      – your Wrangler secrets (env.JWT_SECRET)
	 */
	async fetch(request, env) {
		const url = new URL(request.url);

		if (url.hostname === 'authorium-test.writedocs.io') {
			// 1) try cookie
			const cookieHeader = request.headers.get('Cookie') || '';
			const cookieMatch = cookieHeader.match(/(?:^|; )token=([^;]+)/);
			let token = cookieMatch?.[1];

			// 2) if no cookie, try Authorization header
			if (!token) {
				const auth = request.headers.get('Authorization') || '';
				if (auth.startsWith('Bearer ')) {
					token = auth.slice(7).trim();
				}
			}

			// 3) if still no token, block
			if (!token) {
				return new Response('Unauthorized – no token provided', { status: 401 });
			}

			// 4) verify HS256 JWT
			try {
				const secretUint8 = new TextEncoder().encode(env.JWT_SECRET);
				await jwtVerify(token, secretUint8, {
					issuer: ISSUER,
					audience: AUDIENCE,
				});
				// → valid, fall through to fetch below
			} catch (err) {
				return new Response(`Unauthorized – ${err.message}`, { status: 401 });
			}
		}

		// 5) proxy to static assets (or another origin)
		return fetch(request);
	},
};
