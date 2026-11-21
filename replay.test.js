import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {initSync,replay} from './room-v10/pkg/relay_room_v10.js';
const load = path => readFileSync(new URL(path, import.meta.url));
initSync({module: load('./room-v10/pkg/relay_room_v10_bg.wasm')});
const {pdus,forks,winner} = JSON.parse(load('./fixtures/synapse-v10.json'));
const keys = load('./fixtures/keys.json').toString();

test('signed Synapse v10 forks converge in either delivery order', () => {
  const apply = order => JSON.parse(replay(JSON.stringify([...pdus,...order]), keys));
  const state = apply(forks);
  assert.deepEqual(state, apply(forks.toReversed()));
  assert.deepEqual(state.find(row => row[0] === 'm.room.topic'), ['m.room.topic','',winner]);
});
test('a changed signed event is refused', () => {
  const event = {...pdus[0],sender:'@other:synapse.matrix.test'};
  assert.throws(() => replay(JSON.stringify([event]), keys));
});

test('a correctly signed power-level change by an ordinary joined member is denied', () => {
  const denied = JSON.parse(readFileSync(new URL('./fixtures/denied-power.json', import.meta.url)));
  assert.throws(() => replay(JSON.stringify([...pdus, denied]), keys), /power|authoris|authoriz|level/i);
});

test('a signed redacted predecessor is valid history and cannot supply replacement content', () => {
  const redacted = {...forks[0], content: {}};
  const result = JSON.parse(replay(JSON.stringify([...pdus,redacted]),keys));
  assert.ok(result.some(([type]) => type === 'm.room.topic'));
  assert.throws(() => replay(JSON.stringify([...pdus,{...redacted,content:{topic:'different'}}]),keys));
  assert.throws(() => replay(JSON.stringify([...pdus,{...redacted,signatures:{}}]),keys));
});
