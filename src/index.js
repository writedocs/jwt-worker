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
	 * @param {Object}  env      — your Wrangler secrets
	 */
	async fetch(request, env) {
		const url = new URL(request.url);

		if (url.hostname === 'authorium-test.writedocs.io') {
			// 1) pull token from cookie
			const cookieHeader = request.headers.get('Cookie') || '';
			const m = cookieHeader.match(/(?:^|; )token=([^;]+)/);
			const token = m?.[1];

			if (!token) {
				return new Response('Unauthorized – no token', { status: 401 });
			}

			// 2) verify with the HS256 secret you stored via wrangler secret put JWT_SECRET
			try {
				const secretUint8 = new TextEncoder().encode(env.JWT_SECRET);
				// pass secretUint8, and optionally verify issuer/audience
				await jwtVerify(token, secretUint8, {
					issuer: ISSUER,
					audience: AUDIENCE,
				});
				// if you want the decoded payload:
				// const { payload } = await jwtVerify(token, secretUint8, { issuer: ISSUER, audience: AUDIENCE });
				// console.log('✅ verified, payload:', payload);
			} catch (err) {
				// log the real error in the body so you can tail your Worker logs
				return new Response(`Unauthorized – ${err.message}`, { status: 401 });
			}
		}

		// 3) proxy through to your static files
		return fetch(request);
	},
};
