# Vercel Backend + Cloudflare Pages Frontend Deployment

## Deployment Strategy

- **Backend**: Vercel (Python Serverless Functions)
- **Frontend**: Cloudflare Pages (static hosting)

## Step 1: Deploy Backend to Vercel

1. **Install Vercel CLI**
```bash
npm install -g vercel
```

2. **Login to Vercel**
```bash
vercel login
```

3. **Deploy**
```bash
cd c:/Users/ADMIN/Desktop/ToolsGopCli
vercel --prod
```

Or use Vercel Dashboard:
1. Go to vercel.com
2. Click "Add New Project"
3. Import your GitHub repository
4. Configure:
  - **Framework Preset**: Other
  - **Root Directory**: . (root)
  - **Build Command**: (leave empty)
  - **Output Directory**: . (current directory)
- Add Environment Variable:
  - `JWT_SECRET_KEY`: Generate a secure key
- Click "Deploy"

4. **Get your Vercel URL** (e.g., `https://your-app.vercel.app`)

## Step 2: Deploy Frontend to Cloudflare Pages

1. **Install Wrangler CLI**
```bash
npm install -g wrangler
```

2. **Login to Cloudflare**
```bash
wrangler login
```

3. **Deploy frontend**
```bash
cd c:/Users/ADMIN/Desktop/ToolsGopCli/frontend
wrangler pages deploy . --project-name=garena-tools
```

Or use Cloudflare Dashboard:
1. Go to Cloudflare Dashboard > Pages
2. Click "Create a project"
3. Select "Upload assets"
4. Upload the `frontend` folder
5. Deploy

4. **Get your Cloudflare Pages URL** (e.g., `https://garena-tools.pages.dev`)

## Step 3: Update Frontend API URL

After deploying backend to Vercel, update `frontend/app.js`:
```javascript
const API_BASE = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1' 
    ? 'http://localhost:8000' 
    : 'https://your-app.vercel.app'; // Replace with your Vercel URL
```

## Step 4: Configure CORS

Update `api/index.py` to allow your Cloudflare Pages domain:
```python
CORS(app, resources={r"/*": {"origins": ["https://your-pages.pages.dev"]}})
```

Or allow all origins (for development):
```python
CORS(app, resources={r"/*": {"origins": "*"}})
```

## Step 5: Redeploy

1. Push changes to GitHub
2. Vercel will auto-redeploy
3. Cloudflare Pages will need manual redeploy or connect to GitHub

## Quick Start Commands

**Backend (Vercel):**
```bash
cd c:/Users/ADMIN/Desktop/ToolsGopCli
vercel login
vercel --prod
```

**Frontend (Cloudflare Pages):**
```bash
cd c:/Users/ADMIN/Desktop/ToolsGopCli/frontend
wrangler login
wrangler pages deploy . --project-name=garena-tools
```

## Environment Variables

**Vercel:**
- `JWT_SECRET_KEY`: Generate secure random key (use https://generate-random.org/api-key-generator)
- `DB_FILE`: users.json (default)

**Cloudflare Pages:**
- No environment variables needed for frontend

## Free Tier Limits

- **Vercel**: 100GB bandwidth/month, 6GB build/month
- **Cloudflare Pages**: Unlimited bandwidth, 500 builds/month

## Alternative: Deploy Everything to Vercel

If you prefer a single platform, deploy both to Vercel:
1. Backend: Serverless Functions (Python)
2. Frontend: Static files
3. Both on same domain
4. No CORS needed (same origin)

## Troubleshooting

**Vercel Python Build Error:**
- Ensure `api/requirements.txt` exists
- Check Python version compatibility (3.11+)
- Verify all dependencies are compatible

**CORS Error:**
- Ensure CORS is configured in `api/index.py`
- Check that the frontend URL is allowed
- Use browser DevTools to check CORS headers

**Database Persistence:**
- Vercel serverless functions are stateless
- Use Vercel KV or external database for production
- Current implementation uses file-based storage (not recommended for production)
