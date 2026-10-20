# Work on the documentation

The site uses MkDocs Material with prrr's existing pixel cat/key artwork and the black/white/gold application palette. Markdown remains the content source; SVG walkthroughs are original illustrations of the inspected caller paths.

## Preview

```sh
python3 -m venv target/docs-venv
target/docs-venv/bin/python -m pip install -r requirements-docs.txt
target/docs-venv/bin/python -m mkdocs serve --dev-addr 127.0.0.1:8000
```

Open `http://127.0.0.1:8000`. Fonts, scripts, artwork, animation, and search are served locally; the site does not need an external animation or font service.

## Validate

```sh
target/docs-venv/bin/python -m playwright install chromium
target/docs-venv/bin/python scripts/docs-check.py
cargo build --locked --bin prrr
target/docs-venv/bin/python scripts/docs-examples-check.py
```

The browser checker builds strictly and checks local links/anchors, all 22 animation chapters, state semantics, packet movement and pause, keyboard seeking, speed controls, readable portrait layouts, contrast, reduced motion, local search, transcripts without JavaScript, and print output. Linux may require Playwright's browser system dependencies.

The example checker uses a private temporary HOME and custom data/key directories. It exercises the real CLI's provisioning, import, export, route edits, revocation, and sharing state. It does not start a VPN session or change host routes, and generated credentials are deleted rather than printed.

The generated site and browser evidence live under ignored `target/`. The workflow checks pull requests with read-only permissions and deploys checked output from `main` to [GitHub Pages](https://mewplane.github.io/prrr/).

## Keep page types distinct

| Reader need | Location |
| --- | --- |
| Learn through a successful connection | `tutorials/` |
| Install, provision, or recover | `how-to/` |
| Look up fields, commands, and wire formats | `reference/` |
| Understand mechanisms and boundaries | `explanation/` |

The structure follows [Diátaxis](https://diataxis.fr/) and the tutorial conventions of the [Good Docs Project](https://thegooddocsproject.dev/). Prose and scene artwork are authored for prrr; package tooling retains its own licenses.

## Keep behavior and animation aligned

Implementation links pin revision `191ebaf`. When a caller path changes, update its prose, storyboard labels, field diagrams, and behavioral checks together. Read active code rather than promoting comments or parsed configuration fields into promises. Rust API reference stays with source comments and `cargo doc`.

The animation engine is in `docs/javascripts/mechanics.js`. Preserve the paused default, keyboard-accessible chapter controls, speed selection, stable focus, hidden-document pause, reduced motion, and full transcripts. Reflow scenes by widget width; do not scale a desktop system map until mobile labels become unreadable. Native SVG fields and directional envelopes should teach actual mechanics.

Keep the existing logo intact. The documentation uses `docs/assets/prrr.png`, copied unchanged from `assets/logo_app.png`. Use the app's dark palette and the artwork's gold accent, with visible focus and readable text contrast.

Older root guides remain available in the [repository docs directory](https://github.com/Mewplane/prrr/tree/main/docs) as historical material. Root-anchored exclusions keep stale overclaims and removed functionality out of the published navigation; canonical pages should link to other canonical pages.

## Contribute

See [CONTRIBUTING.md](https://github.com/Mewplane/prrr/blob/main/CONTRIBUTING.md) for the project workflow. Include reader-facing behavior and relevant validation in a documentation PR. Preserve private keys, configuration credentials, and audit files outside published artifacts.
