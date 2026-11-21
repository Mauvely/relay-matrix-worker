import assert from 'node:assert/strict';
import test from 'node:test';
import { packMedia, unpackMedia } from './src/media.js';
test('federation media keeps ciphertext byte-exact with a MIME preamble', async () => {
  const data = Uint8Array.from({ length: 256 }, (_, i) => i),
    boundary = 'test-boundary';
  const mixed = packMedia(data, 'application/octet-stream', boundary);
  for (const prefix of ['', '\r\n']) {
    const response = await new Blob([prefix, mixed]).arrayBuffer();
    assert.deepEqual(
      new Uint8Array(unpackMedia(response, 'multipart/mixed; boundary=' + boundary).body),
      data
    );
  }
});
