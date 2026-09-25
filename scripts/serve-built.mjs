import { createServer } from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const requestedBase = process.env.SITE_BASE || '/';
const base = `/${requestedBase.replace(/^\/+|\/+$/g, '')}/`.replace('//', '/');
const types = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript', '.svg': 'image/svg+xml', '.png': 'image/png', '.gif': 'image/gif', '.pdf': 'application/pdf', '.json': 'application/json', '.wasm': 'application/wasm', '.txt': 'text/plain' };
const port = Number(process.env.PORT || 4322);

createServer(async (request, response) => {
  const pathname = decodeURIComponent(new URL(request.url || '/', 'http://localhost').pathname);
  if (!pathname.startsWith(base)) {
    response.writeHead(404).end();
    return;
  }
  const relative = pathname.slice(base.length);
  const file = path.resolve(root, relative || 'index.html');
  if (file !== root && !file.startsWith(root + path.sep)) {
    response.writeHead(403).end();
    return;
  }
  let target = file;
  try {
    if ((await fs.stat(target)).isDirectory()) target = path.join(target, 'index.html');
    const data = await fs.readFile(target);
    response.writeHead(200, { 'content-type': `${types[path.extname(target)] || 'application/octet-stream'}; charset=utf-8`, 'content-length': data.length });
    response.end(data);
  } catch {
    response.writeHead(404).end();
  }
}).listen(port, '127.0.0.1', () => console.log(`Built site: http://127.0.0.1:${port}${base}`));
