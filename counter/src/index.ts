/// <reference types="@cloudflare/workers-types" />
import { challenges } from '../../src/data/challenges.mjs';

interface Env {
  DB: D1Database;
}

interface CountRow {
  views: number;
  likes: number;
}

const slugs = new Set(challenges.map((challenge) => challenge.slug));
const allowedOrigin = 'https://thetrustypwo.github.io';
const voterPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

function originAllowed(origin: string | null): origin is string {
  if (!origin) return false;
  if (origin === allowedOrigin) return true;
  try {
    const url = new URL(origin);
    return url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname);
  } catch {
    return false;
  }
}

function response(origin: string, body: object | null, status = 200): Response {
  return new Response(body === null ? null : JSON.stringify(body), {
    status,
    headers: {
      'Access-Control-Allow-Origin': origin,
      'Access-Control-Allow-Methods': 'POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
      'Cache-Control': 'no-store',
      'Content-Type': 'application/json; charset=utf-8',
      'Vary': 'Origin',
    },
  });
}

async function readPayload(request: Request): Promise<{ slug: string; voterId: string; sessionId: string } | null> {
  const contentLength = Number(request.headers.get('Content-Length'));
  if (Number.isFinite(contentLength) && contentLength > 256) return null;
  const raw = await request.text();
  if (raw.length > 256) return null;
  try {
    const body = JSON.parse(raw);
    if (typeof body?.slug !== 'string' || !slugs.has(body.slug)) return null;
    if (typeof body?.voterId !== 'string' || !voterPattern.test(body.voterId)) return null;
    if (body.sessionId !== undefined && (typeof body.sessionId !== 'string' || !voterPattern.test(body.sessionId))) return null;
    // Keep older published clients working until GitHub Pages finishes deploying.
    return { slug: body.slug, voterId: body.voterId, sessionId: body.sessionId ?? `legacy:${body.voterId}` };
  } catch {
    return null;
  }
}

async function state(env: Env, slug: string, voterId: string) {
  const [countRow, vote] = await Promise.all([
    env.DB.prepare('SELECT views, likes FROM challenge_counts WHERE slug = ?').bind(slug).first<CountRow>(),
    env.DB.prepare('SELECT 1 AS liked FROM challenge_likes WHERE slug = ? AND voter_id = ?').bind(slug, voterId).first(),
  ]);
  return { views: countRow?.views ?? 0, likes: countRow?.likes ?? 0, liked: Boolean(vote) };
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const origin = request.headers.get('Origin');
    if (!originAllowed(origin)) return new Response('Forbidden', { status: 403 });
    if (request.method === 'OPTIONS') return response(origin, null, 204);
    if (request.method !== 'POST') return response(origin, { error: 'Method not allowed' }, 405);

    const action = new URL(request.url).pathname;
    if (!['/view', '/state', '/like', '/unlike'].includes(action)) {
      return response(origin, { error: 'Not found' }, 404);
    }
    const payload = await readPayload(request);
    if (!payload) return response(origin, { error: 'Invalid challenge or browser ID' }, 400);
    const { slug, voterId, sessionId } = payload;

    try {
      if (action === '/view') {
        await env.DB.prepare('INSERT OR IGNORE INTO challenge_views (slug, session_id) VALUES (?, ?)').bind(slug, sessionId).run();
      } else if (action === '/like') {
        await env.DB.prepare('INSERT OR IGNORE INTO challenge_likes (slug, voter_id) VALUES (?, ?)').bind(slug, voterId).run();
      } else if (action === '/unlike') {
        await env.DB.prepare('DELETE FROM challenge_likes WHERE slug = ? AND voter_id = ?').bind(slug, voterId).run();
      }
      return response(origin, await state(env, slug, voterId));
    } catch {
      return response(origin, { error: 'Counts are temporarily unavailable' }, 503);
    }
  },
};
