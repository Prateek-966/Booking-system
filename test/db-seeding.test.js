'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { execFileSync } = require('node:child_process');
const Database = require('better-sqlite3');

function fixture(t) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'booking-seeding-'));
  t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
  return {
    start(seedDemo = '1') {
      execFileSync(process.execPath, ['-e', "require('./src/db').close()"], {
        cwd: path.join(__dirname, '..'),
        env: { ...process.env, DATA_DIR: directory, SEED_DEMO: seedDemo },
        stdio: 'pipe',
      });
    },
    open() { return new Database(path.join(directory, 'booking.db')); },
  };
}

test('fresh database seeds once and restart preserves details after all rooms are deleted', (t) => {
  const app = fixture(t);
  app.start();
  let db = app.open();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n, 4);
  assert.equal(db.prepare('SELECT name FROM property').get().name, "Colonel's Paradise Homestay");
  db.prepare(`UPDATE property SET name = ?, tagline = ?, about = ?, location = ?,
    contact_name = ?, contact_email = ?, contact_phone = ? WHERE id = 1`).run(
    'Saved guesthouse', 'Saved tagline', 'Saved description', 'Saved location',
    'Saved owner', 'saved@example.com', '+91 1234567890'
  );
  db.prepare('DELETE FROM rooms').run();
  const saved = db.prepare('SELECT * FROM property').get();
  db.close();

  app.start();
  app.start();
  db = app.open();
  try {
    assert.deepEqual(db.prepare('SELECT * FROM property').get(), saved);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n, 0);
  } finally { db.close(); }
});

for (const version of [1, 2, 4]) {
  test(`unsupported schema ${version} is rejected without changing existing data`, (t) => {
    const app = fixture(t);
    let db = app.open();
    db.exec('CREATE TABLE rooms (name TEXT); INSERT INTO rooms VALUES (\'Saved room\')');
    db.pragma(`user_version = ${version}`);
    const originalSchema = db.prepare('SELECT * FROM sqlite_master').all();
    db.close();
    assert.throws(() => app.start(), /Unsupported database schema version/);
    db = app.open();
    try {
      assert.equal(db.pragma('user_version', { simple: true }), version);
      assert.deepEqual(db.prepare('SELECT * FROM sqlite_master').all(), originalSchema);
      assert.deepEqual(db.prepare('SELECT * FROM rooms').all(), [{ name: 'Saved room' }]);
    } finally { db.close(); }
  });
}

test('enabling demo seeding later does not overwrite an existing unseeded property', (t) => {
  const app = fixture(t);
  app.start('0');
  let db = app.open();
  const saved = db.prepare('SELECT * FROM property').get();
  assert.equal(db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n, 0);
  db.close();
  app.start();
  db = app.open();
  try {
    assert.deepEqual(db.prepare('SELECT * FROM property').get(), saved);
    assert.equal(db.prepare('SELECT COUNT(*) AS n FROM rooms').get().n, 0);
  } finally { db.close(); }
});
