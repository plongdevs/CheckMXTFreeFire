# Garena Free Fire Tools - Web Application

Web-based version of the Garena Free Fire CLI tools with authentication and modern UI.

## Features

- **User Authentication**: Register and login with JWT tokens
- **Add Recovery Email**: Add recovery email to Garena accounts
- **Check Recovery Email**: Check email status and pending requests
- **Check Linked Platforms**: View all linked platforms (Facebook, Gmail, Apple, etc.)
- **Cancel Recovery Email**: Cancel pending email requests
- **Revoke Access Token**: Revoke current access tokens
- **EAT to Access Token**: Convert EAT tokens to Access Tokens
- **EAT to JWT**: Convert EAT tokens directly to JWT
- **Access to JWT**: Convert Access Tokens to JWT
- **Guest to JWT**: Convert guest credentials to JWT

## Deployment

- **Backend**: Vercel (Python Serverless Functions)
- **Frontend**: Cloudflare Pages (static hosting)

See [DEPLOYMENT_VERCEL_CLOUDFLARE.md](DEPLOYMENT_VERCEL_CLOUDFLARE.md) for detailed deployment instructions.

## Quick Deploy

**Backend (Vercel):**
```bash
vercel login
vercel --prod
```

**Frontend (Cloudflare Pages):**
```bash
cd frontend
wrangler login
wrangler pages deploy . --project-name=garena-tools
```

## Project Structure

```
ToolsGopCli/
├── api/
│   ├── index.py             # Vercel serverless functions
│   ├── garena_tools.py      # Garena API functions
│   └── requirements.txt     # Python dependencies
├── frontend/
│   ├── index.html           # Main UI
│   ├── app.js               # Frontend logic
│   ├── _redirects           # Cloudflare Pages config
│   └── _headers             # Security headers
├── vercel.json             # Vercel configuration
├── requirements.txt         # Root dependencies
└── Full.py                 # Original CLI tool (reference)
```

## Security Notes

- Change the `JWT_SECRET_KEY` environment variable on Vercel for production
- Use environment variables for sensitive data
- Enable HTTPS in production (Vercel and Cloudflare Pages provide this)
- Implement rate limiting for API endpoints

## Original CLI Tool

The original CLI tool is preserved as `Full.py` for reference.
