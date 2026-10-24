/**
 * Full-stack Express server for PhishLens
 * Mounts Vite dev middleware in development, exposes secure API routes,
 * and enforces strict SSRF and request body limits.
 */

import express, { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import dotenv from 'dotenv';
import { analyzeUrl, analyzeText, analyzePage } from './src/lib/analysis/rule-engine.ts';
import { SafeBrowsingProvider } from './src/lib/analysis/reputation-provider.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
const isProduction = process.env.NODE_ENV === 'production';

// Strict body limit to prevent memory exhaustion / DoS
app.use(express.json({ limit: '100kb' }));

// CORS configuration (deliberate support for extension popup and local frontend)
app.use((req: Request, res: Response, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') {
    res.sendStatus(204);
    return;
  }
  next();
});

// Threat intelligence provider instance
const reputationProvider = new SafeBrowsingProvider();

// API: Health check & engine metadata
app.get('/api/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    product: 'PhishLens Phishing Detection Engine',
    version: '1.0.0',
    threatIntelligenceProvider: {
      name: reputationProvider.name,
      configured: reputationProvider.isConfigured(),
    },
    timestamp: new Date().toISOString(),
  });
});

// API: Analyze URL
// Note: SSRF protection — Never navigates or fetches arbitrary user URLs from server
app.post('/api/analyze/url', async (req: Request, res: Response) => {
  try {
    const { url } = req.body || {};
    if (!url || typeof url !== 'string') {
      res.status(400).json({
        error: 'Invalid request: "url" string is required in JSON body.',
      });
      return;
    }

    if (url.length > 4096) {
      res.status(400).json({
        error: 'Invalid request: URL exceeds 4,096 character limit.',
      });
      return;
    }

    const result = await analyzeUrl(url, reputationProvider);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({
      error: 'An unexpected error occurred during URL inspection.',
      details: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

// API: Analyze Text (Email or Message)
app.post('/api/analyze/text', async (req: Request, res: Response) => {
  try {
    const { text, type, sender } = req.body || {};
    if (!text || typeof text !== 'string') {
      res.status(400).json({
        error: 'Invalid request: "text" string is required in JSON body.',
      });
      return;
    }

    if (text.length > 50000) {
      res.status(400).json({
        error: 'Invalid request: Text exceeds 50,000 character limit.',
      });
      return;
    }

    const targetType = type === 'email' ? 'email' : 'message';
    const optionalSender = typeof sender === 'string' ? sender : undefined;

    const result = await analyzeText(text, targetType, optionalSender, reputationProvider);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({
      error: 'An unexpected error occurred during text inspection.',
      details: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

// API: Analyze Page (DOM signals from Extension)
app.post('/api/analyze/page', async (req: Request, res: Response) => {
  try {
    const pageInput = req.body;
    if (!pageInput || typeof pageInput.url !== 'string') {
      res.status(400).json({
        error: 'Invalid request: "url" is required in page signals payload.',
      });
      return;
    }

    const result = await analyzePage(pageInput, reputationProvider);
    res.json(result);
  } catch (err: unknown) {
    res.status(500).json({
      error: 'An unexpected error occurred during page inspection.',
      details: err instanceof Error ? err.message : 'Unknown error',
    });
  }
});

// Serve built Chrome Extension bundle for popup preview & verification
app.use('/extension-preview', express.static(path.resolve(__dirname, 'extension/dist')));

// Vite Middleware integration for Full-Stack development
async function startServer() {
  if (!isProduction) {
    const { createServer } = await import('vite');
    const vite = await createServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    // Serve production static build
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[PhishLens] Server running at http://0.0.0.0:${PORT} (${isProduction ? 'production' : 'development'})`);
  });
}

startServer().catch(err => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
