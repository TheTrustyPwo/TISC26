import { defineConfig } from 'astro/config';

const requestedBase = process.env.SITE_BASE || '/';
const base = `/${requestedBase.replace(/^\/+|\/+$/g, '')}/`.replace('//', '/');

export default defineConfig({
  output: 'static',
  base,
  site: process.env.SITE_URL || undefined,
  trailingSlash: 'always',
});
