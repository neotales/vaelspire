import tailwindcss from '@tailwindcss/vite';
import { sveltekit } from '@sveltejs/kit/vite';
import { defineConfig } from 'vite';

export default defineConfig({
	plugins: [tailwindcss(), sveltekit()],
	server: {
		proxy: {
			'/health': 'http://127.0.0.1:8080',
			'/ready': 'http://127.0.0.1:8080',
			'/metrics': 'http://127.0.0.1:8080',
			'/.well-known': 'http://127.0.0.1:8080',
			'/sign-up': 'http://127.0.0.1:8080',
			'/sign-in': 'http://127.0.0.1:8080',
			'/sign-out': 'http://127.0.0.1:8080',
			'/session': 'http://127.0.0.1:8080',
			'/sessions': 'http://127.0.0.1:8080',
			'/api-keys': 'http://127.0.0.1:8080',
			'/oauth2': 'http://127.0.0.1:8080',
			'/admin': 'http://127.0.0.1:8080',
			'/scim': 'http://127.0.0.1:8080',
			'/saml': 'http://127.0.0.1:8080',
			'/forward-auth': 'http://127.0.0.1:8080'
		}
	}
});
