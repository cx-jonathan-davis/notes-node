'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');

const router = express.Router();
const ROOT = path.resolve(__dirname, '..', '..', 'uploads');

/**
 * Serve a file from uploads/.
 *
 * The requested name is resolved against the uploads root and the result is
 * confirmed to still sit *inside* that root before anything is opened, so '../'
 * sequences and absolute paths both fail closed.
 */
router.get('/attachments/*', (req, res) => {
  const requested = decodeURIComponent(req.params[0] || '');
  const target = path.resolve(ROOT, requested);
  const rel = path.relative(ROOT, target);

  if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
    return res.status(404).send('Not found');
  }
  if (!fs.existsSync(target) || !fs.statSync(target).isFile()) {
    return res.status(404).send('Not found');
  }

  res.type('text/plain; charset=utf-8').send(fs.readFileSync(target));
});

module.exports = router;
