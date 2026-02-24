/**
 * Mock SqlStorage backed by sql.js (WASM SQLite) for testing Durable Object
 * code that uses Cloudflare's built-in SQLite.
 *
 * Note: The method name `exec` matches Cloudflare's SqlStorage interface —
 * it is parameterized SQL execution, not child_process.
 */

import initSqlJs, { type Database } from 'sql.js';

// Minimal mock of Cloudflare's SqlStorageCursor — just needs to be iterable
interface MockCursor extends Iterable<Record<string, unknown>> {
  toArray(): Record<string, unknown>[];
}

function makeCursor(rows: Record<string, unknown>[]): MockCursor {
  return {
    [Symbol.iterator]() {
      return rows[Symbol.iterator]();
    },
    toArray() {
      return rows;
    },
  };
}

export interface MockSqlStorage {
  exec(query: string, ...bindings: unknown[]): MockCursor;
}

export async function createMockSqlStorage(): Promise<MockSqlStorage> {
  const SQL = await initSqlJs();
  const db = new SQL.Database();

  return {
    exec(query: string, ...bindings: unknown[]): MockCursor {
      const stmt = db.prepare(query);
      if (bindings.length > 0) {
        stmt.bind(bindings as (string | number | null | Uint8Array)[]);
      }

      const isReader = query.trimStart().toUpperCase().startsWith('SELECT');

      if (isReader) {
        const rows: Record<string, unknown>[] = [];
        while (stmt.step()) {
          const obj = stmt.getAsObject();
          rows.push(obj as Record<string, unknown>);
        }
        stmt.free();
        return makeCursor(rows);
      } else {
        stmt.step();
        stmt.free();
        return makeCursor([]);
      }
    },
  };
}
