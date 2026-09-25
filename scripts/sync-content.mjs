import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { challenges } from '../src/data/challenges.mjs';

const siteRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const originalRoot = path.resolve(siteRoot, '..');
const contentRoot = path.join(siteRoot, 'content');
let copied = 0;

for (const challenge of challenges) {
  const directory = path.resolve(originalRoot, challenge.directory);
  const destination = path.resolve(contentRoot, challenge.directory);
  if (!directory.startsWith(originalRoot + path.sep) || !destination.startsWith(contentRoot + path.sep)) {
    throw new Error(`Unexpected challenge directory: ${challenge.directory}`);
  }
  const markdown = await fs.readFile(path.join(directory, 'writeup.md'), 'utf8');
  const files = new Set(['writeup.md']);
  for (const [, image] of markdown.matchAll(/!\[[^\]]*\]\(([^)]+)\)/g)) files.add(image.trim());
  for (const [resource] of challenge.resources) files.add(resource);
  if (challenge.explainer) files.add(challenge.explainer.file);
  for (const relative of files) {
    const from = path.resolve(directory, relative);
    const to = path.resolve(destination, relative);
    if (!from.startsWith(directory + path.sep) || !to.startsWith(destination + path.sep)) {
      throw new Error(`File escapes challenge directory: ${relative}`);
    }
    await fs.mkdir(path.dirname(to), { recursive: true });
    await fs.copyFile(from, to);
    copied++;
  }
}
console.log(`Synced ${copied} selected challenge files into site/content/.`);
