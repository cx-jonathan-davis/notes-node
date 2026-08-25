'use strict';

/**
 * SQLite helpers for the Notes app.
 *
 * Every statement below is a prepared statement with bound parameters. That is
 * deliberate: this app is a clean baseline for Checkmarx scanning, so an injection
 * finding should only ever come from a later change -- never from this file.
 */

const path = require('node:path');
const { scryptSync, randomBytes, timingSafeEqual } = require('node:crypto');
const Database = require('better-sqlite3');

const db = new Database(path.join(__dirname, '..', 'notes.db'));
db.pragma('journal_mode = WAL');

/** Hash a password with scrypt and a per-password random salt. */
function hashPassword(password) {
  const salt = randomBytes(16);
  const derived = scryptSync(password, salt, 64);
  return `scrypt$${salt.toString('hex')}$${derived.toString('hex')}`;
}

/** Verify a password in constant time. */
function verifyPassword(password, stored) {
  const [scheme, saltHex, hashHex] = String(stored).split('$');
  if (scheme !== 'scrypt' || !saltHex || !hashHex) return false;
  const expected = Buffer.from(hashHex, 'hex');
  const actual = scryptSync(password, Buffer.from(saltHex, 'hex'), expected.length);
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS notes (
      id         INTEGER PRIMARY KEY AUTOINCREMENT,
      title      TEXT NOT NULL,
      body       TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS users (
      id            INTEGER PRIMARY KEY AUTOINCREMENT,
      username      TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL
    );
  `);

  const { n } = db.prepare('SELECT COUNT(*) AS n FROM users').get();
  if (n === 0) {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
      .run('demo', hashPassword('demo-password'));
    const insert = db.prepare('INSERT INTO notes (title, body) VALUES (?, ?)');
    insert.run('Welcome', 'This is a sample note. Try the search box above.');
    insert.run('Shopping list', 'Coffee, oat milk, bread.');
    insert.run('Release checklist', 'Run the tests, tag the commit, publish.');
  }
}

/**
 * Columns that may be sorted on. The request only ever supplies a *key* into this
 * table; the value spliced into the SQL is always one of these three literals, so
 * the interpolation below cannot carry attacker input.
 */
const SORT_COLUMNS = { date: 'created_at', title: 'title', id: 'id' };

const listNotes = (sort) => {
  const column = SORT_COLUMNS[sort] || SORT_COLUMNS.id;
  return db.prepare(
    `SELECT id, title, body, created_at FROM notes ORDER BY ${column} DESC`
  ).all();
};

const getNote = (id) =>
  db.prepare('SELECT id, title, body, created_at FROM notes WHERE id = ?').get(id);

const createNote = (title, body) =>
  db.prepare('INSERT INTO notes (title, body) VALUES (?, ?)').run(title, body)
    .lastInsertRowid;

// The search term is passed as a bound parameter (with % wildcards embedded in the
// value itself) so that user input never appears in the SQL template string.
const searchNotes = (query) => {
  const term = `%${query}%`;
  return db.prepare(
    `SELECT id, title, body, created_at FROM notes
     WHERE title LIKE ? OR body LIKE ?
     ORDER BY id DESC`
  ).all(term, term);
};

const findUser = (username) =>
  db.prepare('SELECT id, username, password_hash FROM users WHERE username = ?')
    .get(username);

module.exports = {
  init, listNotes, getNote, createNote, searchNotes, findUser,
  hashPassword, verifyPassword,
};
