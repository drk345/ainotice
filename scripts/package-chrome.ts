#!/usr/bin/env npx tsx
/**
 * AG-250: Chrome Submission Packager
 *
 * Packages dist/chrome/ contents into a deterministic ZIP artifact for
 * Chrome Web Store submission.
 *
 * Guards:
 *   - Fails if dist/chrome/manifest.json is missing (build not run)
 *   - Fails if any *.map files are present (source maps must not ship)
 *   - Fails if any *.ts / *.tsx files are present (source files must not ship)
 *
 * Output: release/ainotice-chrome.zip (gitignored by *.zip rule)
 *
 * The ZIP contains the CONTENTS of dist/chrome/ at the root level
 * (manifest.json at zip root, not nested under chrome/).
 *
 * Usage:
 *   npm run package:chrome
 *   npx tsx scripts/package-chrome.ts
 *
 * Prerequisite: npm run build:chrome must have been run first.
 */

import * as fs from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import JSZip from 'jszip';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const ROOT = path.resolve(__dirname, '..');
const CHROME_DIR = path.join(ROOT, 'dist', 'chrome');
const RELEASE_DIR = path.join(ROOT, 'release');
const ZIP_NAME = 'ainotice-chrome.zip';
const ZIP_PATH = path.join(RELEASE_DIR, ZIP_NAME);

function fail(msg: string): never {
  console.error(`\nERROR: ${msg}`);
  process.exit(1);
}

function walkDir(dir: string): string[] {
  const results: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...walkDir(full));
    } else {
      results.push(full);
    }
  }
  return results.sort();
}

async function main(): Promise<void> {
  console.log('\n=== Ai Notice Chrome Submission Packager ===\n');

  // Guard: build output must exist
  if (!fs.existsSync(CHROME_DIR)) {
    fail('dist/chrome/ not found. Run: npm run build:chrome');
  }
  if (!fs.existsSync(path.join(CHROME_DIR, 'manifest.json'))) {
    fail('dist/chrome/manifest.json not found. Run: npm run build:chrome');
  }

  const allFiles = walkDir(CHROME_DIR);

  // Guard: no source maps
  const mapFiles = allFiles.filter(f => f.endsWith('.map'));
  if (mapFiles.length > 0) {
    const names = mapFiles.map(f => path.relative(CHROME_DIR, f));
    fail(`Source map files found in dist/chrome/ — must not ship:\n  ${names.join('\n  ')}\nRun npm run build:chrome (maps are disabled for Chrome).`);
  }

  // Guard: no TypeScript source files
  const sourceFiles = allFiles.filter(f => f.endsWith('.ts') || f.endsWith('.tsx'));
  if (sourceFiles.length > 0) {
    const names = sourceFiles.map(f => path.relative(CHROME_DIR, f));
    fail(`TypeScript source files found in dist/chrome/ — must not ship:\n  ${names.join('\n  ')}`);
  }

  // Read manifest for display
  const manifest = JSON.parse(fs.readFileSync(path.join(CHROME_DIR, 'manifest.json'), 'utf8'));
  console.log(`Extension name:    ${manifest.name}`);
  console.log(`Version:           ${manifest.version}`);
  console.log(`Manifest version:  MV${manifest.manifest_version}`);
  console.log(`Files to package:  ${allFiles.length}`);

  // Build ZIP from contents (not parent folder)
  const zip = new JSZip();
  for (const filePath of allFiles) {
    const relativePath = path.relative(CHROME_DIR, filePath).replace(/\\/g, '/');
    zip.file(relativePath, fs.readFileSync(filePath));
  }

  // AG-PROMPT-311: deterministic packaging. JSZip defaults every entry (and every auto-created
  // folder) to the current wall-clock time, which made the ZIP SHA-256 non-reproducible across runs
  // (broke the release integrity chain). Pin every entry's timestamp to a fixed epoch so identical
  // dist/chrome content always yields an identical ZIP. This changes ONLY ZIP metadata timestamps —
  // file CONTENT is untouched; file ordering is already stable (walkDir() sorts).
  const FIXED_ZIP_DATE = new Date('2000-01-01T00:00:00Z');
  for (const entryName of Object.keys(zip.files)) {
    zip.files[entryName].date = FIXED_ZIP_DATE;
  }

  const buffer = await zip.generateAsync({
    type: 'nodebuffer',
    compression: 'DEFLATE',
    compressionOptions: { level: 9 },
  });

  // Ensure release/ directory exists
  if (!fs.existsSync(RELEASE_DIR)) {
    fs.mkdirSync(RELEASE_DIR, { recursive: true });
  }

  fs.writeFileSync(ZIP_PATH, buffer);

  const zipSize = fs.statSync(ZIP_PATH).size;
  const zipSizeKb = (zipSize / 1024).toFixed(1);

  console.log('\nContents (at ZIP root):');
  for (const filePath of allFiles) {
    const rel = path.relative(CHROME_DIR, filePath).replace(/\\/g, '/');
    const size = fs.statSync(filePath).size;
    console.log(`  ${rel.padEnd(40)} ${size.toLocaleString()} bytes`);
  }

  console.log(`\n✓ Packaged: ${ZIP_PATH}`);
  console.log(`  ZIP size: ${zipSizeKb} KB (${buffer.length.toLocaleString()} bytes)`);
  console.log(`  Files:    ${allFiles.length}`);
  console.log('\nUpload this ZIP to Chrome Web Store > Developer Dashboard.');
  console.log('Do NOT submit the dist/chrome/ folder directly.');
}

main().catch(e => {
  console.error('Packaging failed:', e);
  process.exit(1);
});
