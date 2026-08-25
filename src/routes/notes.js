'use strict';

const express = require('express');
const db = require('../db');

const router = express.Router();

router.get('/', (req, res) => {
  res.render('index', { notes: db.listNotes(), query: '' });
});

router.get('/notes/:id', (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send('Bad note id');

  const note = db.getNote(id);
  if (!note) return res.status(404).send('Not found');
  res.render('note', { note, query: '' });
});

router.post('/notes', (req, res) => {
  const title = String(req.body.title || '').trim();
  const body = String(req.body.body || '').trim();
  if (!title) return res.redirect('/');
  res.redirect(`/notes/${db.createNote(title, body)}`);
});

router.get('/search', (req, res) => {
  const query = String(req.query.q || '').trim();
  res.render('search', { query, results: query ? db.searchNotes(query) : [] });
});

module.exports = router;
