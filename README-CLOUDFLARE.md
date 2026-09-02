TORIYA NOVA BUSINESS LAB — Cloudflare Worker version

Upload/replace in the GitHub repository:
- index.html
- worker.js
- wrangler.jsonc
- package.json

You may leave server.js in the repository: Cloudflare does not use it.

Cloudflare Workers Builds:
- Build command: npm install && npm run build
- Deploy command: npx wrangler deploy

After deployment add Worker variables/secrets:
- BOT_TOKEN = Telegram bot token (Secret)
- CHANNEL_ID = @tori_ya_nova
- OWNER_CHAT_ID = 6894849502
- INIT_DATA_MAX_AGE_SEC = 86400 (optional)
