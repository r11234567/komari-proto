import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
const vectors = JSON.parse(readFileSync(new URL('../testdata/privileged-settings-v1.json', import.meta.url)));
for (const vector of vectors) {
  test(`privileged-settings-v1 ${vector.sha256}`, () => {
    const mode = Buffer.alloc(4);
    mode.writeUInt32BE(vector.required_privilege_mode);
    const hash = createHash('sha256').update(Buffer.concat([
      Buffer.from('komari.privileged-settings.v1\0'), Buffer.from(vector.booleans), mode,
    ])).digest('hex');
    assert.equal(hash, vector.sha256);
  });
}
