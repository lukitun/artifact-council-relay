import test from 'node:test';
import assert from 'node:assert/strict';
import { colonyVerifier } from '../sdk/colony.mjs';

test('independent Colony gateway uses its own recipient and public verification community', async () => {
  const colonyId = '11111111-2222-3333-4444-555555555555';
  const calls = [];
  let challenge;
  const verifier = colonyVerifier({ apiKey: 'test-only', recipient: 'independent-gateway', colonyId, fetch: async (url) => {
    calls.push(url);
    if (url.endsWith('/auth/token')) return { ok: true, json: async () => ({ access_token: 'fake-jwt' }) };
    if (url.includes('/messages/')) return { ok: true, json: async () => ({ other_user: { id: 'agent-id' }, messages: [] }) };
    assert.ok(url.includes(`colony_id=${colonyId}`));
    return { ok: true, json: async () => ({ items: [{ id: 'p', colony_id: colonyId, created_at: new Date().toISOString(), author: { id: 'reader-id', username: 'reader' }, title: challenge.post_template.title, body: challenge.post_template.body }] }) };
  } });
  challenge = verifier.start('reader');
  assert.equal(challenge.dm_template.to, 'independent-gateway');
  assert.equal(challenge.post_template.colony_id, colonyId);
  assert.deepEqual(await verifier.verify({ client_secret: challenge.client_secret }), { username: 'reader', colonyId: 'reader-id', via: 'post' });
  await assert.rejects(verifier.verify({ client_secret: challenge.client_secret }), /no verification in progress/);
  assert.equal(calls.length, 3);
});

test('default verification recipient stays compatible and invalid routing config fails closed', () => {
  assert.equal(colonyVerifier({}).start('reader').dm_template.to, 'agentpedia');
  assert.throws(() => colonyVerifier({ recipient: 'bad/recipient' }), /invalid Colony verification recipient/);
  assert.throws(() => colonyVerifier({ colonyId: 'injected&search=other' }), /invalid Colony verification colony/);
});
