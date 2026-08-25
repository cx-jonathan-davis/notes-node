'use strict';

/**
 * Tests for XSS remediation in the /search route of src/routes/notes.js
 *
 * Verifies that user-supplied query strings are HTML-encoded before being
 * embedded in the rendered response, preventing Reflected Cross-Site Scripting.
 *
 * Uses Node.js built-in `node:test` and `node:assert` (Node >= 18 / project >= 20).
 * No additional test dependencies required.
 */

const { test, describe, before, after } = require('node:test');
const assert = require('node:assert/strict');
const http = require('node:http');
const path = require('node:path');

// ---------------------------------------------------------------------------
// Minimal Express app wired up the same way as src/server.js, but with an
// in-memory DB so tests never touch the on-disk notes.db.
// ---------------------------------------------------------------------------

const express = require('express');
const escapeHtml = require('escape-html');

// Provide a stub db so the route under test can load without needing SQLite.
// We override the module cache before requiring the notes router.
const Module = require('node:module');
const originalLoad = Module._load.bind(Module);

/** Tiny stub that satisfies every db call the notes router makes. */
const dbStub = {
  init: () => {},
  listNotes: () => [],
  getNote: () => null,
  createNote: () => 1,
  searchNotes: (q) => [],
};

// Intercept require('../db') when called from within the routes directory.
Module._load = function (request, parent, isMain) {
  if (request === '../db' && parent && parent.filename &&
      parent.filename.includes(path.join('src', 'routes'))) {
    return dbStub;
  }
  return originalLoad(request, parent, isMain);
};

// Now require the router (the stub intercept is active).
const notesRouter = require('../src/routes/notes');

// Restore Module._load so subsequent requires are unaffected.
Module._load = originalLoad;

// Build a minimal Express app that mirrors server.js configuration.
function buildApp() {
  const app = express();
  app.set('view engine', 'ejs');
  app.set('views', path.join(__dirname, '..', 'views'));
  app.use(express.urlencoded({ extended: false }));
  // Provide a session stub so header.ejs can reference `session`.
  app.use((req, res, next) => {
    res.locals.session = {};
    next();
  });
  app.use(notesRouter);
  return app;
}

// ---------------------------------------------------------------------------
// HTTP helper – make a GET request and collect the full response body.
// ---------------------------------------------------------------------------

function get(server, urlPath) {
  return new Promise((resolve, reject) => {
    const { address, port } = server.address();
    const options = {
      host: address === '::' ? '127.0.0.1' : address,
      port,
      path: urlPath,
      method: 'GET',
    };
    const req = http.request(options, (res) => {
      let body = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => { body += chunk; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe('GET /search – Reflected XSS remediation', () => {
  let server;

  before(() => {
    const app = buildApp();
    server = http.createServer(app);
    return new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  });

  after(() => {
    return new Promise((resolve, reject) =>
      server.close((err) => (err ? reject(err) : resolve()))
    );
  });

  // --- XSS attack vectors must be escaped in the response ---

  test('escapes <script> tag in query parameter', async () => {
    const payload = '<script>alert(1)</script>';
    const encoded = encodeURIComponent(payload);
    const { status, body } = await get(server, `/search?q=${encoded}`);

    assert.equal(status, 200);
    // Raw script tag must NOT appear verbatim in the HTML
    assert.ok(
      !body.includes('<script>alert(1)</script>'),
      'Raw <script> tag must not appear in response'
    );
    // HTML-encoded form must be present instead
    assert.ok(
      body.includes('&lt;script&gt;'),
      'Encoded &lt;script&gt; must appear in response'
    );
  });

  test('escapes double-quote to prevent attribute injection', async () => {
    const payload = '" onmouseover="alert(1)';
    const encoded = encodeURIComponent(payload);
    const { status, body } = await get(server, `/search?q=${encoded}`);

    assert.equal(status, 200);
    // The unescaped double-quote must not break out of an attribute context
    assert.ok(
      !body.includes('" onmouseover="alert(1)'),
      'Unescaped attribute-injection payload must not appear in response'
    );
    assert.ok(
      body.includes('&quot;'),
      'Double-quote must be encoded as &quot; in response'
    );
  });

  test('escapes single-quote to prevent attribute injection', async () => {
    const payload = "' onmouseover='alert(1)";
    const encoded = encodeURIComponent(payload);
    const { status, body } = await get(server, `/search?q=${encoded}`);

    assert.equal(status, 200);
    assert.ok(
      !body.includes("' onmouseover='alert(1)"),
      'Unescaped single-quote injection payload must not appear in response'
    );
    assert.ok(
      body.includes('&#39;') || body.includes('&apos;') || !body.includes("'"),
      'Single-quote should be encoded in the response'
    );
  });

  test('escapes ampersand in query parameter', async () => {
    const payload = 'foo&bar=<script>';
    const encoded = encodeURIComponent(payload);
    const { status, body } = await get(server, `/search?q=${encoded}`);

    assert.equal(status, 200);
    assert.ok(
      !body.includes('&bar=<script>'),
      'Unescaped ampersand/tag combination must not appear in response'
    );
    assert.ok(
      body.includes('&amp;'),
      'Ampersand must be encoded as &amp; in response'
    );
  });

  test('escapes img onerror XSS vector', async () => {
    const payload = '<img src=x onerror=alert(1)>';
    const encoded = encodeURIComponent(payload);
    const { status, body } = await get(server, `/search?q=${encoded}`);

    assert.equal(status, 200);
    assert.ok(
      !body.includes('<img src=x onerror=alert(1)>'),
      'Raw <img> XSS vector must not appear in response'
    );
    assert.ok(
      body.includes('&lt;img'),
      'Opening angle bracket of img tag must be escaped'
    );
  });

  // --- Legitimate search terms must pass through correctly ---

  test('renders normal alphanumeric query without alteration', async () => {
    const payload = 'coffee notes';
    const encoded = encodeURIComponent(payload);
    const { status, body } = await get(server, `/search?q=${encoded}`);

    assert.equal(status, 200);
    assert.ok(
      body.includes('coffee notes'),
      'Plain text query should appear in the rendered page'
    );
  });

  test('renders empty query without error', async () => {
    const { status, body } = await get(server, '/search');

    assert.equal(status, 200);
    // Should show the "type something" hint, not crash
    assert.ok(body.length > 0, 'Response body should not be empty');
  });

  test('handles whitespace-only query gracefully', async () => {
    const { status } = await get(server, '/search?q=+++');
    assert.equal(status, 200);
  });

  // --- Validate that escapeHtml is applied at the input boundary ---

  test('escapeHtml unit check: angle brackets are encoded', () => {
    const escapeHtmlFn = require('escape-html');
    assert.equal(escapeHtmlFn('<script>'), '&lt;script&gt;');
    assert.equal(escapeHtmlFn('</script>'), '&lt;/script&gt;');
  });

  test('escapeHtml unit check: double quotes are encoded', () => {
    const escapeHtmlFn = require('escape-html');
    assert.equal(escapeHtmlFn('"hello"'), '&quot;hello&quot;');
  });

  test('escapeHtml unit check: ampersands are encoded', () => {
    const escapeHtmlFn = require('escape-html');
    assert.equal(escapeHtmlFn('a&b'), 'a&amp;b');
  });

  test('escapeHtml unit check: safe text is preserved', () => {
    const escapeHtmlFn = require('escape-html');
    assert.equal(escapeHtmlFn('hello world'), 'hello world');
    assert.equal(escapeHtmlFn('search term 123'), 'search term 123');
  });
});
