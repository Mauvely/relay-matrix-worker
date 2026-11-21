// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { canShare } from './src/device.js';

const fixture = JSON.parse(readFileSync(new URL('./fixtures/policy-cases.json', import.meta.url)));
function party(user) {
  return {
    organisationId: fixture.members[user] ?? null,
    managed: fixture.managed_servers.includes(user.split(':')[1])
  };
}
for (const example of fixture.cases)
  test(example.name, () => {
    assert.equal(
      canShare(party(example.sender), party(example.recipient), {
        ...fixture.organisations,
        ...example.override
      }),
      example.allow
    );
  });
test('missing organisation data stops delivery', () => {
  assert.throws(() => canShare(party('@alex:a.example'), party('@bo:b.example'), {}));
});
