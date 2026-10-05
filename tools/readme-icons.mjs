#!/usr/bin/env node
// README icons from the studio's own glyphs (web/studio.js), tinted the way the studio
// tints them in its default theme - Proxmox, dark and light - and rendered to PNG with
// rsvg-convert. GitHub shows the dark one in dark mode (<picture> in README.md).
//
//   node tools/readme-icons.mjs [name ...]     default: every icon README.md uses
//
// Writes .github/assets/icons/<name>-dark.png and -light.png at 2x (44 px) for sharp
// display at 22 px; "mark", the studio's own mark, at 160 px for the title.
//
// The glyph table and the theme come from web/studio.js itself: its icon section and its
// FAMILIES list run in a sandbox, so an icon drawn from a shared constant (the server rack,
// the mark) or re-banded after the table renders exactly as the studio shows it.
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { execFileSync } from "node:child_process";
import vm from "node:vm";

const js = readFileSync("web/studio.js", "utf8");
const readme = readFileSync("README.md", "utf8");

const ctx = {};
vm.createContext(ctx);
const mixFn = js.slice(js.indexOf("\nfunction mix("), js.indexOf("\nfunction luminance("));
vm.runInContext(js.slice(0, js.indexOf("\nfunction tintIcon(")) + mixFn + "\n;this.ICONS = ICON_TEMPLATES; this.seamFor = seamFor;", ctx);
const fam = js.slice(js.indexOf("const FAMILIES = ["), js.indexOf("const THEMES = ("));
vm.runInContext(fam + "\n;this.FAMILIES = FAMILIES;", ctx);
const proxmox = ctx.FAMILIES.find(f => f.id === "proxmox");
const THEMES = { dark: { ...proxmox.dark, mode: "dark" }, light: { ...proxmox.light, mode: "light" } };

// The studio's tintIcon(), for one theme.
function svg(name, t) {
  const def = ctx.ICONS[`${name}.svg`];
  if (!def) throw new Error(`${name}.svg is not in web/studio.js`);
  const hue = def.band === "accent" ? t.accent : t.bands[def.band];
  const seam = def.band === "accent" ? hue : ctx.seamFor(hue, t);
  const body = def.markup.split("@H").join(hue).split("@S").join(seam)
    .replace(/@B:([a-zA-Z]+)/g, (_, b) => t.bands[b] || t[b] || t.accent);
  return { band: def.band, svg: `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18">${body}</svg>` };
}

const names = process.argv.slice(2).length ? process.argv.slice(2)
  : [...new Set([...readme.matchAll(/icons\/([a-z0-9-]+)-dark\.png/g)].map(m => m[1]))];
mkdirSync(".github/assets/icons", { recursive: true });
for (const name of names) {
  const px = name === "mark" ? "160" : "44";
  let band;
  for (const [mode, t] of Object.entries(THEMES)) {
    const g = svg(name, t);
    band = g.band;
    const png = execFileSync("rsvg-convert", ["-w", px, "-h", px, "-f", "png"], { input: g.svg });
    writeFileSync(`.github/assets/icons/${name}-${mode}.png`, png);
  }
  console.log(`${name}: ${band}`);
}
