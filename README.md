# TISC 2026 writeups site

Self-contained Astro site generated from the selected writeups and artifacts in
`content/`. In the local TISC26 workspace, the original challenge folders stay
in place; run `npm run sync:content` there after editing an original writeup or
artifact. That command copies only files used by the site. The published repo
contains this site directory only and builds without the original folders.
`src/data/challenges.mjs` maps each folder to its route, curated downloads, and optional explainer.
Edit `src/data/cover.mjs` to update the two cover notes beside the
author credit.

## Develop

Requires Node.js 22.12 or later.

```sh
npm ci
npm run dev
```

`npm run build` prepares the Markdown and selected assets, then writes the
static site to `dist/`. `npm run preview` serves a root-path build locally.
For a project-path build, run `SITE_BASE=/TISC26/ npm run serve:built` to
serve `dist/` at the same path GitHub Pages uses.

For a GitHub Pages project path, set `SITE_BASE` and `SITE_URL` when building:

```sh
SITE_BASE=/TISC26/ SITE_URL=https://thetrustypwo.github.io npm run build
```

In PowerShell:

```powershell
$env:SITE_BASE = '/TISC26/'
$env:SITE_URL = 'https://thetrustypwo.github.io'
npm run build
npm run serve:built
```

The workflow in `.github/workflows/pages.yml` sets these values from the GitHub
repository and deploys `dist`. GitHub Actions is the Pages build source. The
workflow runs on `main` and can also be run manually.

Generated media, downloads, and explainer copies live under `public/` during a
build; `src/data/generated.json` is also generated. Edit the manifest or the
files in `content/`, then rerun `npm run dev` or `npm run build` to refresh them.
The preparation step losslessly recompresses PNG copies only when the pixel data
stays identical and the result is smaller. If a writeup references a GIF, the
build also makes a still for reduced-motion viewing. Source files are untouched
by the build.
The published EXPcalibur explainer receives one mobile-only CSS width constraint
on its milestone select. Both published explainer copies report their content
height to the surrounding page so they fit without a nested page scrollbar;
their original interaction logic remains untouched.
Run `SITE_BASE=/TISC26/ npm run check:built` against `serve:built` to verify all
generated routes and local links.
