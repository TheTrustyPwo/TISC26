import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import MarkdownIt from 'markdown-it';
import sharp from 'sharp';
import { challenges } from '../src/data/challenges.mjs';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const sourceRoot = path.join(siteRoot, 'content');
const publicRoot = path.join(siteRoot, 'public');
const generatedPath = path.join(siteRoot, 'src', 'data', 'generated.json');
const requestedBase = process.env.SITE_BASE || '/';
const base = `/${requestedBase.replace(/^\/+|\/+$/g, '')}/`.replace('//', '/');
const url = (...segments) => base + segments.flatMap((s) => s.split('/')).map(encodeURIComponent).join('/');
const escape = (value) => MarkdownIt().utils.escapeHtml(String(value));
let optimizedImages = 0;
let savedImageBytes = 0;

const altOverrides = {
  'my-printer-has-a-secret': {
    'assets/1.png': 'Gumpla listing found while tracing the deleted auction',
    'assets/2.png': 'Profile link on the hobby site',
    'assets/3.png': 'Auction listing with the seller’s Flickr and hobby site accounts',
    'assets/4.png': 'Seller profile banner showing grey pants',
    'assets/5.png': 'Seller’s own shop and featured model',
  },
  omnitrix: {
    'assets/img_1.png': 'Omnitrix program analysis view',
    'assets/img_2.png': 'Omnitrix connection and message structure analysis',
    'assets/img.png': 'Omnitrix login details shown in the challenge analysis',
    'assets/img_3.png': 'Omnitrix permission check and mode change analysis',
  },
};

function imageDimensions(data, name) {
  if (name.endsWith('.png') && data.subarray(1, 4).toString() === 'PNG') {
    return [data.readUInt32BE(16), data.readUInt32BE(20)];
  }
  if (name.endsWith('.gif') && data.subarray(0, 3).toString() === 'GIF') {
    return [data.readUInt16LE(6), data.readUInt16LE(8)];
  }
  throw new Error(`Unsupported image format: ${name}`);
}

function slugify(value) {
  return value.toLowerCase().normalize('NFKD').replace(/[\u0300-\u036f]/g, '')
    .replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') || 'section';
}

function safeSourceFile(directory, relative) {
  const full = path.resolve(sourceRoot, directory, relative);
  const parent = path.resolve(sourceRoot, directory) + path.sep;
  if (!full.startsWith(parent)) throw new Error(`File escapes challenge directory: ${relative}`);
  return full;
}

async function copyWithinChallenge(challenge, relative, kind, sourceData) {
  const source = safeSourceFile(challenge.directory, relative);
  await fs.access(source);
  const destination = path.join(publicRoot, kind, challenge.slug, ...relative.split('/'));
  await fs.mkdir(path.dirname(destination), { recursive: true });
  if (kind === 'media' && relative.toLowerCase().endsWith('.png')) {
    const original = sourceData || await fs.readFile(source);
    const candidate = await sharp(original).withMetadata().png({ compressionLevel: 9, adaptiveFiltering: true, palette: false }).toBuffer();
    const originalPixels = await sharp(original).ensureAlpha().raw().toBuffer();
    const candidatePixels = await sharp(candidate).ensureAlpha().raw().toBuffer();
    if (candidate.length < original.length && candidatePixels.equals(originalPixels)) {
      await fs.writeFile(destination, candidate);
      optimizedImages++;
      savedImageBytes += original.length - candidate.length;
    } else {
      await fs.writeFile(destination, original);
    }
  } else {
    await fs.copyFile(source, destination);
  }
  return url(kind, challenge.slug, relative);
}

for (const kind of ['media', 'downloads', 'explainers']) {
  const target = path.resolve(publicRoot, kind);
  if (path.dirname(target) !== publicRoot) throw new Error('Unexpected public output path');
  await fs.rm(target, { recursive: true, force: true });
}

const output = [];
for (const challenge of challenges) {
  const source = await fs.readFile(safeSourceFile(challenge.directory, 'writeup.md'), 'utf8');
  const markdown = source.replace(/^# [^\r\n]+\r?\n(?:\r?\n)?/, '');
  const imagePaths = [...markdown.matchAll(/!\[[^\]]*\]\(([^)]+)\)/g)].map((match) => match[1].trim());
  const images = new Map();
  for (const relative of new Set(imagePaths)) {
    if (/^(https?:|data:|\/)/i.test(relative)) throw new Error(`Unexpected image URL: ${relative}`);
    const sourceImage = safeSourceFile(challenge.directory, relative);
    const data = await fs.readFile(sourceImage);
    const [width, height] = imageDimensions(data, relative.toLowerCase());
    const src = await copyWithinChallenge(challenge, relative, 'media', data);
    let stillSrc = null;
    if (relative.toLowerCase().endsWith('.gif')) {
      const stillRelative = relative.replace(/\.gif$/i, '-still.png');
      const stillDestination = path.join(publicRoot, 'media', challenge.slug, ...stillRelative.split('/'));
      await fs.writeFile(stillDestination, await sharp(data, { page: 0 }).png({ compressionLevel: 9 }).toBuffer());
      stillSrc = url('media', challenge.slug, stillRelative);
    }
    images.set(relative, { src, stillSrc, width, height });
  }

  const headings = [];
  const ids = new Map();
  const md = new MarkdownIt({ html: false, linkify: true, typographer: false });
  md.renderer.rules.heading_open = (tokens, index, options, env, self) => {
    const title = tokens[index + 1].content;
    const stem = slugify(title);
    const count = ids.get(stem) || 0;
    ids.set(stem, count + 1);
    const id = count ? `${stem}-${count + 1}` : stem;
    tokens[index].attrSet('id', id);
    if (tokens[index].tag === 'h2' || tokens[index].tag === 'h3') {
      headings.push({ id, title, depth: Number(tokens[index].tag.slice(1)) });
    }
    return self.renderToken(tokens, index, options);
  };
  md.renderer.rules.image = (tokens, index) => {
    const token = tokens[index];
    const relative = token.attrGet('src');
    const media = images.get(relative);
    if (!media) throw new Error(`Unmapped image in ${challenge.slug}: ${relative}`);
    const originalAlt = token.content.trim();
    const alt = altOverrides[challenge.slug]?.[relative] || originalAlt;
    if (!alt || /^(img(?:_\d+)?\.png|assets\/\d+\.png)$/i.test(alt)) throw new Error(`Unhelpful alt in ${challenge.slug}: ${relative}`);
    const image = `<img src="${escape(media.src)}" alt="${escape(alt)}" width="${media.width}" height="${media.height}" loading="lazy" decoding="async">`;
    return media.stillSrc ? `<picture><source media="(prefers-reduced-motion: reduce)" srcset="${escape(media.stillSrc)}">${image}</picture>` : image;
  };
  let html = md.render(markdown);

  let explainer = null;
  if (challenge.explainer) {
    const { file, title, before } = challenge.explainer;
    const sourceFile = safeSourceFile(challenge.directory, file);
    const destination = path.join(publicRoot, 'explainers', `${challenge.slug}.html`);
    await fs.mkdir(path.dirname(destination), { recursive: true });
    const resizeBridge = `<script>(()=>{const main=document.querySelector('main');if(!main)return;const report=()=>parent.postMessage({type:'tisc-explainer-height',height:Math.ceil(main.getBoundingClientRect().height)+40},'*');new ResizeObserver(report).observe(main);addEventListener('load',report);requestAnimationFrame(report)})()<\/script>`;
    if (challenge.slug === 'expcalibur') {
      // The original milestone select has a very long option and expands the
      // embedded document on narrow screens. Constrain only the published copy.
      const original = await fs.readFile(sourceFile, 'utf8');
      const mobileFix = '@media(max-width:580px){#jump{width:100%;min-width:0;max-width:100%}}';
      if (!original.includes('</style>')) throw new Error('EXPCALIBUR explainer style block missing');
      await fs.writeFile(destination, original
        .replace('</style>', `${mobileFix}</style>`)
        .replaceAll('EXPCALIBUR recorded device trace', 'EXPcalibur recorded device trace')
        .replace('id="slider" type="range"', 'id="slider" type="range" aria-label="Trace request"') + resizeBridge);
    } else {
      await fs.writeFile(destination, await fs.readFile(sourceFile, 'utf8') + resizeBridge);
    }
    explainer = { title, src: url('explainers', `${challenge.slug}.html`) };
    const marker = `<h2 id="${before}">`;
    if (!html.includes(marker)) throw new Error(`Explainer insertion point missing: ${challenge.slug}/${before}`);
    const block = `<section class="explainer explainer--${challenge.slug}" aria-labelledby="interactive-${challenge.slug}"><div class="explainer-heading"><h2 id="interactive-${challenge.slug}">${escape(title)}</h2><a href="${escape(explainer.src)}" target="_blank" rel="noopener">Open full screen<span class="sr-only">: ${escape(title)} (new tab)</span></a></div><iframe src="${escape(explainer.src)}" title="${escape(title)}" loading="lazy" sandbox="allow-scripts" referrerpolicy="no-referrer"></iframe></section>`;
    html = html.replace(marker, block + marker);
    const at = headings.findIndex((heading) => heading.id === before);
    headings.splice(at, 0, { id: `interactive-${challenge.slug}`, title, depth: 2 });
  }

  const resources = [];
  for (const [relative, label] of challenge.resources) {
    resources.push({ label, filename: path.basename(relative), href: await copyWithinChallenge(challenge, relative, 'downloads') });
  }
  output.push({ slug: challenge.slug, title: challenge.title, level: challenge.level, placement: challenge.placement || null, marker: challenge.level === null ? '★' : String(challenge.level).padStart(2, '0'), label: challenge.level === null ? 'Special challenge' : `Level ${challenge.level}`, order: output.length + 1, html, headings, resources, explainer, source: `${challenge.directory}/writeup.md` });
  console.log(`${String(output.length).padStart(2, '0')} ${challenge.slug}: ${headings.length} headings, ${images.size} images, ${resources.length} downloads`);
}

await fs.writeFile(generatedPath, JSON.stringify(output, null, 2) + '\n');
console.log(`Prepared ${output.length} challenge pages for base ${base}`);
console.log(`Losslessly compressed ${optimizedImages} PNGs; saved ${(savedImageBytes / 1024).toFixed(1)} KiB. GIFs retained intact.`);
