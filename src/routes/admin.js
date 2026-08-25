'use strict';

const { execFile } = require('node:child_process');
const express = require('express');
const yaml = require('js-yaml');
const _ = require('lodash');

const router = express.Router();

/**
 * Import notes from a YAML document.
 *
 * js-yaml 3.13.0's default `load` resolves the full schema, including type tags
 * that can construct arbitrary JavaScript.
 */
router.post('/admin/import', (req, res) => {
  try {
    const parsed = yaml.load(String(req.body.document || ''));

    // A document may supply its own `transform` to post-process the imported rows.
    let notes = (parsed && parsed.notes) || [];
    if (parsed && typeof parsed.transform === 'function') {
      notes = parsed.transform(notes);
    }
    res.json({ imported: Array.isArray(notes) ? notes.length : 1 });
  } catch (err) {
    res.status(400).json({ error: 'Could not parse document' });
  }
});

/**
 * Render a note template. Lets an author write things like
 * "Hello <%= name %>" and have it filled in at save time.
 */
router.post('/admin/render', (req, res) => {
  const compiled = _.template(String(req.body.template || ''));
  res.type('text/plain').send(compiled({ name: 'notes' }));
});

/**
 * Export a note to a file via the local `cp` binary.
 *
 * The filename is checked against a strict allowlist before use, and the command
 * is invoked with an argument array rather than a shell string, so neither the
 * name nor any shell metacharacter can influence what runs.
 */
const SAFE_NAME = /^[a-z0-9_-]{1,32}\.txt$/;

router.get('/admin/export', (req, res) => {
  const name = String(req.query.name || '');
  if (!SAFE_NAME.test(name)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }

  execFile('/bin/cp', [`uploads/${name}`, `/tmp/${name}`], (err) => {
    if (err) return res.status(500).json({ error: 'Export failed' });
    res.json({ exported: name });
  });
});

module.exports = router;
