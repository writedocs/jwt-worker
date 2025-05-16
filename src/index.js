// worker.js
import { jwtVerify } from 'jose';

/**
 * Configuration
 */
// const ISSUER   = 'https://login.authorium.com/'
// const AUDIENCE = 'docs.authorium.com'

export default {
	/**
	 * @param {Request} request
	 * @param {Object} env        — contains your Wrangler secrets (e.g. env.JWT_SECRET)
	 */
	async fetch(request, env) {
		const url = new URL(request.url);

		// Protect everything under docs.authorium.com
		if (url.hostname === 'authorium-test.writedocs.io') {
			// 1. grab the token from the "token" cookie
			const cookieHeader = request.headers.get('Cookie') || '';
			const m = cookieHeader.match(/(?:^|; )token=([^;]+)/);
			const token = m?.[1];

			if (!token) {
				return new Response('Unauthorized', { status: 401 });
			}

			// 2. verify the token using your HS256 secret
			try {
				// env.JWT_SECRET is the secret you stored with `wrangler secret put JWT_SECRET`
				const secretUint8 = new TextEncoder().encode(env.JWT_SECRET);
				await jwtVerify(token, key);

				// await jwtVerify(token, secretUint8, {
				//   issuer:   ISSUER,
				//   audience: AUDIENCE,
				// })
			} catch (err) {
				return new Response('Unauthorized', { status: 401 });
			}
		}

		// 3. If verification passed (or it’s not the docs host), proxy the request
		return fetch(request);
	},
};
