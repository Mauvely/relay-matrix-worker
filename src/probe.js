// A bounded workload known to be free of account data, exercised on the actual Workers runtime.
import module from '../room-v10/pkg/relay_room_v10_bg.wasm';
import {initSync,replay} from '../room-v10/pkg/relay_room_v10.js';
import trace from '../fixtures/synapse-v10.json';
import keys from '../fixtures/keys.json';
let ready = false;
export function replayProbe() {
  if (!ready) { initSync({module}); ready = true; }
  const apply = forks => replay(JSON.stringify(trace.pdus.concat(forks)), JSON.stringify(keys));
  const state = apply(trace.forks);
  const converged = state === apply(trace.forks.toReversed());
  const topic = JSON.parse(state).find(([kind]) => kind === 'm.room.topic');
  return {room_version:'10', processed:trace.pdus.length + trace.forks.length,
    converged:converged && topic?.[2] === trace.winner};
}
