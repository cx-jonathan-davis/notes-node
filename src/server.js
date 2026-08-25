'use strict';

/**
 * A small Notes app: list, view, create, search, log in, download attachments.
 *
 * Kept deliberately plain so the security-relevant lines are easy to find. See the
 * README for the seams where vulnerabilities get introduced in later PRs.
 */

const path = require('node:path');
const crypto = require('node:crypto');
const express = require('express');
const session = require('express-session');

const db = require('./db');

const app = express();
const PORT = Number(process.env.PORT) || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(session({
  // Dev-only fallback. Real deployments set NOTES_SECRET_KEY; a random key here
  // means sessions do not survive a restart, which beats committing a fixed one.
  secret: process.env.NOTES_SECRET_KEY || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production' },
}));

/**
 * Escape the five HTML-significant characters. Used by templates that need to
 * emit pre-rendered markup alongside note text.
 */
function escapeHtml(value) {
  return String(value).replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

// Makes `session` available to every template the same way Flask does.
app.use((req, res, next) => {
  res.locals.session = req.session;
  res.locals.escapeHtml = escapeHtml;
  next();
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.use(require('./routes/notes'));
app.use(require('./routes/auth'));
app.use(require('./routes/attachments'));
app.use(require('./routes/admin'));

db.init();

app.listen(PORT, '127.0.0.1', () => {
  console.log(`notes-node listening on http://127.0.0.1:${PORT}`);
});
