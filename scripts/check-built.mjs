import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const entries = JSON.parse(await fs.readFile(path.join(siteRoot, 'src/data/generated.json'), 'utf8'));
const requestedBase = process.env.SITE_BASE || '/';
const base = `/${requestedBase.replace(/^\/+|\/+$/g, '')}/`.replace('//', '/');
const origin = process.env.CHECK_ORIGIN || 'http://127.0.0.1:4322';
const pages = [base, ...entries.map((entry) => `${base}challenges/${entry.slug}/`)];
const localUrls = new Set();
let references = 0;
let images = 0;
let downloads = 0;
let frames = 0;

for (const page of pages) {
  const response = await fetch(origin + page);
  if (!response.ok) throw new Error(`${page}: HTTP ${response.status}`);
  const html = await response.text();
  const entry = entries.find((item) => page.includes(`/challenges/${item.slug}/`));
  if (entry) {
    if (!html.includes(`<h1>${entry.title}</h1>`)) throw new Error(`${page}: title missing`);
    if (!html.includes(`aria-label="${entry.title} writeup"`)) throw new Error(`${page}: article missing`);
    if (!html.includes(`aria-current="page"`)) throw new Error(`${page}: selected route missing`);
    const frameCount = (html.match(/<iframe\b/g) || []).length;
    if (frameCount !== Number(Boolean(entry.explainer))) throw new Error(`${page}: explainer frame mismatch`);
  }
  for (const match of html.matchAll(/\b(href|src|srcset)="([^"]+)"/g)) {
    const [, kind, raw] = match;
    if (/^(?:https?:|mailto:|data:)/.test(raw)) continue;
    if (raw.startsWith('#')) {
      const anchor = decodeURIComponent(raw.slice(1));
      if (!html.includes(`id="${anchor}"`)) throw new Error(`${page}: missing fragment ${raw}`);
      continue;
    }
    const target = new URL(raw, origin + page);
    if (target.origin !== origin) continue;
    if (!target.pathname.startsWith(base)) throw new Error(`${page}: URL escapes base: ${raw}`);
    localUrls.add(target.pathname);
    references++;
    if ((kind === 'src' || kind === 'srcset') && raw.includes('/media/')) images++;
    if (kind === 'src' && raw.includes('/explainers/')) frames++;
    if (kind === 'href' && raw.includes('/downloads/')) downloads++;
  }
}

for (const pathname of localUrls) {
  const response = await fetch(origin + pathname);
  if (!response.ok) throw new Error(`${pathname}: HTTP ${response.status}`);
}
const expectedImages = entries.reduce((sum, entry) => sum + (entry.html.match(/<img\b/g) || []).length + (entry.html.match(/<source\b/g) || []).length, 0);
const expectedDownloads = entries.reduce((sum, entry) => sum + entry.resources.length, 0);
const expectedFrames = entries.filter((entry) => entry.explainer).length;
if (images !== expectedImages || frames !== expectedFrames || downloads !== expectedDownloads) throw new Error(`Unexpected asset count: ${images}/${expectedImages} images, ${frames}/${expectedFrames} frames, ${downloads}/${expectedDownloads} downloads`);
console.log(`Checked ${pages.length} pages, ${references} local references (${localUrls.size} unique), ${images} images, ${frames} explainers, ${downloads} downloads. All returned 200.`);
