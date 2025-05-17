import { SignJWT } from 'jose';

async function createToken() {
	const secret = new TextEncoder().encode('my-secret');
	const now = Math.floor(Date.now() / 1000);

	const token = await new SignJWT({ sub: 'test-user' })
		.setProtectedHeader({ alg: 'HS256' })
		.setIssuer('https://app.authorium.com')
		.setAudience('docs.authorium.com')
		.setIssuedAt(now)
		.setExpirationTime(now + 60 * 60) // 1 hour
		.sign(secret);

	console.log(token);
}

createToken();

// Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0LXVzZXIiLCJpc3MiOiJodHRwczovL2FwcC5hdXRob3JpdW0uY29tIiwiYXVkIjoiZG9jcy5hdXRob3JpdW0uY29tIiwiaWF0IjoxNzQ3NTA5MTcyLCJleHAiOjE3NDc1MTI3NzJ9.1LZa72dY4V1o8CgxbHRyy9VrZnHIWEUyt9v6DrATfts
