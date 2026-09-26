# Writeup counters

The site sends one view request when a writeup opens and offers a reversible like per browser. The Cloudflare Worker stores the counts in D1; its API accepts requests from the published GitHub Pages origin and local development. Browser IDs are random and kept in local storage for each challenge. They are not accounts, so clearing browser storage allows another like.

The database and Worker are deployed separately from GitHub Pages. From the site repository root, after `npm ci` and `npx wrangler login`:

```sh
npx wrangler d1 migrations apply DB --remote --config counter/wrangler.jsonc
npx wrangler deploy --config counter/wrangler.jsonc
```

For local development, run the same migration with `--local`, then `npx wrangler dev --config counter/wrangler.jsonc --port 8787`. Set `PUBLIC_COUNTER_API_URL=http://127.0.0.1:8787` when starting or building the Astro site. GitHub Actions sets the deployed Worker URL for Pages builds.
