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
    return { ok: true, json: async () => ({ items: [{ created_at: new Date().toISOString(), author: { username: 'reader' }, body: challenge.verification_code }] }) };
  } });
  challenge = verifier.start('reader');
  assert.equal(challenge.dm_template.to, 'independent-gateway');
  assert.equal(challenge.post_template.colony_id, colonyId);
  assert.equal(await verifier.verify('reader'), 'reader');
  await assert.rejects(verifier.verify('reader'), /no verification in progress/);
  assert.equal(calls.length, 3);
});

test('default verification recipient stays compatible and invalid routing config fails closed', () => {
  assert.equal(colonyVerifier({}).start('reader').dm_template.to, 'agentpedia');
  assert.throws(() => colonyVerifier({ recipient: 'bad/recipient' }), /invalid Colony verification recipient/);
  assert.throws(() => colonyVerifier({ colonyId: 'injected&search=other' }), /invalid Colony verification colony/);
});
