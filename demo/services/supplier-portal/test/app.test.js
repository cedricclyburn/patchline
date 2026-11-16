'use strict';

const { test, before, after } = require('node:test');
const assert = require('node:assert/strict');
const { createApp } = require('../src/app');

let server;
let base;

before(async () => {
  server = createApp().listen(0, '127.0.0.1');
  await new Promise((resolve) => server.once('listening', resolve));
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => new Promise((resolve) => server.close(resolve)));

async function postQuote(body) {
  return fetch(`${base}/quotes`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: typeof body === 'string' ? body : JSON.stringify(body),
  });
}

test('GET /healthz reports ok with catalog size', async () => {
  const res = await fetch(`${base}/healthz`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.status, 'ok');
  assert.equal(body.parts, 5);
});

test('GET /parts?q= searches name, material and supplier case-insensitively', async () => {
  const res = await fetch(`${base}/parts?q=northline`);
  assert.equal(res.status, 200);
  const body = await res.json();
  assert.equal(body.count, 2);
  assert.deepEqual(body.parts.map((p) => p.partNumber), ['AS-2210-AL', 'AS-3307-CF']);

  const byMaterial = await (await fetch(`${base}/parts?q=ti-6al`)).json();
  assert.deepEqual(byMaterial.parts.map((p) => p.partNumber), ['AS-1042-TI']);
});

test('GET /parts filters by category and returns all parts without a query', async () => {
  const all = await (await fetch(`${base}/parts`)).json();
  assert.equal(all.count, 5);
  const hydraulics = await (await fetch(`${base}/parts?category=hydraulics`)).json();
  assert.deepEqual(hydraulics.parts.map((p) => p.partNumber), ['AS-4120-HY']);
});

test('GET /parts/:partNumber returns flattened supplier fields and normalizes case', async () => {
  const res = await fetch(`${base}/parts/as-5001-el`);
  assert.equal(res.status, 200);
  const part = await res.json();
  assert.equal(part.partNumber, 'AS-5001-EL');
  assert.equal(part.supplierName, 'Aurora Interconnect');
  assert.equal(part.supplierCage, '7E8F9');
  assert.equal(part.supplier, undefined);

  const noCage = await (await fetch(`${base}/parts/AS-4120-HY`)).json();
  assert.equal(noCage.supplierCage, 'not registered');
});

test('GET /parts/:partNumber returns 404 for unknown parts', async () => {
  const res = await fetch(`${base}/parts/AS-0000-XX`);
  assert.equal(res.status, 404);
  assert.deepEqual(await res.json(), { error: 'unknown part number' });
});

test('POST /quotes prices the order and renders a summary', async () => {
  const res = await postQuote({ partNumber: 'as-1042-ti', quantity: 200, buyer: { email: 'buyer@example.test' } });
  assert.equal(res.status, 201);
  const quote = await res.json();
  assert.match(quote.id, /^Q-\d{5}$/);
  assert.equal(quote.totalUsd, 970);
  assert.equal(quote.backordered, false);
  assert.equal(quote.requestedBy, 'buyer@example.test');
  assert.equal(
    quote.summary,
    `Quote ${quote.id}: 200 x AS-1042-TI (Titanium hex bolt, 1/4-28 UNF) from Cascade Fastener Co. at $4.85 = $970.00, ships in 21 days`,
  );

  const backorder = await (await postQuote({ partNumber: 'AS-3307-CF', quantity: 10 })).json();
  assert.equal(backorder.backordered, true);
  assert.equal(backorder.requestedBy, 'unknown');
});

test('POST /quotes rejects invalid input with 400/404 JSON errors', async () => {
  assert.equal((await postQuote({ quantity: 1 })).status, 400);
  assert.equal((await postQuote({ partNumber: 'AS-1042-TI', quantity: 0 })).status, 400);
  assert.equal((await postQuote({ partNumber: 'AS-1042-TI', quantity: 1.5 })).status, 400);
  assert.equal((await postQuote({ partNumber: 'AS-9999-ZZ', quantity: 1 })).status, 404);

  const malformed = await postQuote('{"partNumber":');
  assert.equal(malformed.status, 400);
  assert.deepEqual(await malformed.json(), { error: 'invalid JSON body' });
});
