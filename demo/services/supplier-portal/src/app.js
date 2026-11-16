'use strict';

const express = require('express');
const _ = require('lodash');
const { PARTS, normalize } = require('./catalog');

const MAX_QUANTITY = 100000;

// Plain-text quote summary that buyers paste into purchase requisitions.
const quoteSummary = _.template(
  'Quote <%- id %>: <%- quantity %> x <%- partNumber %> (<%- name %>) ' +
    'from <%- supplier %> at $<%- unitPrice %> = $<%- total %>, ' +
    'ships in <%- leadTimeDays %> days',
);

function publicPart(part) {
  return {
    ..._.pick(part, ['partNumber', 'name', 'category', 'material', 'spec', 'unitPriceUsd', 'leadTimeDays', 'stock']),
    supplierCode: _.get(part, 'supplier.code'),
    supplierName: _.get(part, 'supplier.name'),
    supplierCage: _.get(part, 'supplier.cage', 'not registered'),
  };
}

function createApp() {
  const app = express();
  const quotes = [];

  app.use(express.json({ limit: '16kb' }));

  app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok', parts: PARTS.length, quotes: quotes.length });
  });

  app.get('/parts', (req, res) => {
    const q = _.toLower(_.trim(_.get(req.query, 'q', '')));
    const category = _.toLower(_.trim(_.get(req.query, 'category', '')));
    let results = PARTS;
    if (q) {
      results = results.filter((p) =>
        [p.partNumber, p.name, p.material, p.spec, _.get(p, 'supplier.name')]
          .some((field) => _.includes(_.toLower(field), q)),
      );
    }
    if (category) {
      results = results.filter((p) => p.category === category);
    }
    res.json({ count: results.length, parts: _.sortBy(results, 'partNumber').map(publicPart) });
  });

  app.get('/parts/:partNumber', (req, res) => {
    const part = _.find(PARTS, { partNumber: normalize(req.params.partNumber) });
    if (!part) {
      return res.status(404).json({ error: 'unknown part number' });
    }
    return res.json(publicPart(part));
  });

  app.post('/quotes', (req, res) => {
    const partNumber = normalize(_.get(req.body, 'partNumber'));
    const quantity = _.get(req.body, 'quantity');
    if (!partNumber) {
      return res.status(400).json({ error: 'partNumber is required' });
    }
    if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_QUANTITY) {
      return res.status(400).json({ error: `quantity must be an integer between 1 and ${MAX_QUANTITY}` });
    }
    const part = _.find(PARTS, { partNumber });
    if (!part) {
      return res.status(404).json({ error: 'unknown part number' });
    }
    const total = _.round(part.unitPriceUsd * quantity, 2);
    const quote = {
      id: `Q-${String(quotes.length + 1).padStart(5, '0')}`,
      partNumber,
      quantity,
      unitPriceUsd: part.unitPriceUsd,
      totalUsd: total,
      leadTimeDays: part.leadTimeDays,
      backordered: quantity > part.stock,
      requestedBy: _.get(req.body, 'buyer.email', 'unknown'),
    };
    quote.summary = quoteSummary({
      id: quote.id,
      quantity,
      partNumber,
      name: part.name,
      supplier: _.get(part, 'supplier.name'),
      unitPrice: part.unitPriceUsd.toFixed(2),
      total: total.toFixed(2),
      leadTimeDays: part.leadTimeDays,
    });
    quotes.push(quote);
    return res.status(201).json(quote);
  });

  // Malformed JSON bodies and other errors come back as JSON, not HTML stack traces.
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = err.status || err.statusCode || 500;
    res.status(status).json({ error: status === 400 ? 'invalid JSON body' : 'internal error' });
  });

  return app;
}

module.exports = { createApp };
