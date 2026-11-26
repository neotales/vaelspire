# Vaelspire Core Embedded Web UI (`ui/`)

Zero-cyan SvelteKit + Tailwind CSS v4 static web console compiled into `ui/build/` and embedded directly inside the `vaelspire` Rust binary when built with `--features embed-ui`.

## Palette

- **Warm Obsidian:** `#0c0a09`, `#141110`, `#1c1917`, `#292524`
- **Dragon-Ember Crimson:** `#dc2626`, `#ea580c`
- **Molten Brass / Amber-Gold:** `#d97706`, `#f59e0b`, `#fde68a`
- **Emerald Status:** `#10b981`
- **Neotales Parent Accent (badge only):** `#a855f7`

Zero cyan or sky-blue tones are used anywhere in the UI.

## Build & Embed

```bash
cd ui
pnpm install
pnpm build

cd ..
cargo build -p vaelspire --features embed-ui
```

When running `vaelspire serve`, visit `http://127.0.0.1:8080/ui/`. To host the UI separately on a CDN (Enterprise white-label mode), start with `--ui-mode external` or `--ui-mode api-only`.
