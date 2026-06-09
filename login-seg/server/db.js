const path = require("path");
const sqlite3 = require("sqlite3").verbose();

const DB_PATH = path.join(__dirname, "..", "data", "auth.db");

function openDb() {
  const db = new sqlite3.Database(DB_PATH);

  db.serialize(() => {
    db.run("PRAGMA journal_mode = WAL;");
    db.run(
      `CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL,
        created_at TEXT NOT NULL DEFAULT (datetime('now'))
      );`
    );
  });

  return {
    run(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
          if (err) {
            reject(err);
            return;
          }
          resolve({ lastID: this.lastID, changes: this.changes });
        });
      });
    },
    get(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(row);
        });
      });
    },
    all(sql, params = []) {
      return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
          if (err) {
            reject(err);
            return;
          }
          resolve(rows);
        });
      });
    },
    close() {
      return new Promise((resolve, reject) => {
        db.close((err) => {
          if (err) {
            reject(err);
            return;
          }
          resolve();
        });
      });
    }
  };
}

module.exports = {
  openDb
};
