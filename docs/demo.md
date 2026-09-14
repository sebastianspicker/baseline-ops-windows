# Browser demo and screenshot tour

Open the [live demo](https://sebastianspicker.github.io/baseline-ops/) to inspect
a profile, prepare an Audit command, and read a sample result. It runs from static HTML, CSS, and JavaScript files. It has no
backend, telemetry, external fonts, or connection to an endpoint.

The three profiles match the reviewed repository examples exactly. The
Defender result uses fictional data and a fixed timestamp, with finding codes
from the Defender health script. Its summary and metadata explain the example;
they were not collected from a device. The demo is a walkthrough, separate from
the Windows Forms launcher and Rust GUI.

## Open it locally

From the repository root, serve only the demo directory:

```bash
python3 -m http.server 8765 --bind 127.0.0.1 --directory docs/demo
```

Open `http://127.0.0.1:8765`. Serve the files over HTTP: browsers that block
local file requests cannot load the profiles when you open `index.html` from
disk.

Select one of the three profiles, change the command's output format, toggle
`-WhatIf`, and copy the command. On the result step, filter findings, open the
JSON, or download the sample. None of these actions runs an endpoint operation.

## Publish on GitHub Pages

Run the [Pages workflow](https://github.com/sebastianspicker/baseline-ops/blob/main/.github/workflows/pages.yml)
manually to publish the files in `docs/demo`. It does not upload the rest of the
repository, endpoint evidence, or local analysis output. The site needs no
build step or runtime dependency.

After merging the reviewed files:

1. In the repository's **Settings → Pages**, choose **GitHub Actions** as the
   publishing source.
2. In **Actions**, open **GitHub Pages demo** and run it on the default branch.
3. Open the deployment URL reported by the workflow. For the upstream repository,
   the expected project URL is `https://sebastianspicker.github.io/baseline-ops/`.
4. Add the deployed URL to the repository's About website field and README.

The workflow checks that profile copies match the examples before uploading.
It only deploys from the repository's default branch. GitHub-hosted project
Pages forks automatically link back to their own repository; custom domains
should update the fallback GitHub links in `docs/demo/index.html`.

See GitHub's [custom Pages workflow documentation](https://docs.github.com/en/pages/getting-started-with-github-pages/using-custom-workflows-with-github-pages)
for publishing-source and environment settings. Check the deployment result
before sharing the public URL.

## Maintain the tour

After changing a showcased profile, regenerate the snapshot from the repository
root and verify it:

```bash
node tools/demo-profiles.mjs
node tools/demo-profiles.mjs --check
```

Browser checks and screenshot capture require Node.js 20 or newer and the
Playwright development package in `tools/demo`. Playwright is not shipped with
the demo or either Windows application:

```bash
npm ci --prefix tools/demo
cd tools/demo
npx playwright install chromium
npm test
npm run screenshots
```

The check script starts a local server and stops it when finished. It checks
profile selection, command options, clipboard success and failure, downloads,
severity filters, empty results, profile-loading errors, keyboard focus, and
mobile layout.

The screenshot command runs these checks before replacing the three desktop
images in [`docs/screenshots/`](screenshots/01-profiles.png). It captures full
pages at a 1440-pixel viewport width. The result view labels the data as
fictional.

The screenshots in the [README](../README.md#screenshot-tour) come from this
browser tour. Windows Forms screenshots and native Windows runtime validation
need a Windows host and must be captured separately.
