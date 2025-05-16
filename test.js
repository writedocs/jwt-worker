import { SignJWT } from 'jose';

async function createToken() {
	const secret = new TextEncoder().encode('my-secret');
	const now = Math.floor(Date.now() / 1000);

	const token = await new SignJWT({ sub: 'test-user' })
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuer('https://login.authorium.com/')
		.setAudience('docs.authorium.com')
		.setIssuedAt(now)
		.setExpirationTime(now + 60 * 60) // 1 hour
		.sign(secret);

	console.log(token);
}

createToken();
