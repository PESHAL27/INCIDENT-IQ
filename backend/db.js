/**
 * IncidentIQ — SQLite Database Initialization
 */

import Database from 'better-sqlite3'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __dirname = dirname(fileURLToPath(import.meta.url))
const DB_PATH = join(__dirname, 'incidentiq.db')

let _db = null

export function getDb() {
  if (!_db) {
    _db = new Database(DB_PATH)
    _db.pragma('journal_mode = WAL')
    _db.pragma('foreign_keys = ON')
    initSchema(_db)
  }
  return _db
}

function initSchema(db) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS investigations (
      id                TEXT PRIMARY KEY,
      incident_name     TEXT NOT NULL,
      description       TEXT DEFAULT '',
      status            TEXT NOT NULL DEFAULT 'idle',
      severity          TEXT,
      confidence        INTEGER,
      incident_type     TEXT,
      key_indicators    TEXT,
      analysis_result   TEXT,
      parsing_summary   TEXT,
      report            TEXT,
      created_at        TEXT NOT NULL,
      updated_at        TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS evidence_files (
      id                  TEXT PRIMARY KEY,
      investigation_id    TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
      filename            TEXT NOT NULL,
      file_type           TEXT NOT NULL,
      file_size           TEXT,
      upload_timestamp    TEXT NOT NULL,
      content             TEXT,
      char_count          INTEGER DEFAULT 0,
      parsed_events_count INTEGER DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS events (
      id               TEXT PRIMARY KEY,
      event_id         TEXT NOT NULL,
      investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
      evidence_file_id TEXT REFERENCES evidence_files(id) ON DELETE CASCADE,
      timestamp        TEXT,
      source           TEXT,
      event_type       TEXT,
      username         TEXT,
      source_ip        TEXT,
      destination_ip   TEXT,
      port             INTEGER,
      action           TEXT,
      process          TEXT,
      message          TEXT,
      severity         TEXT,
      raw              TEXT,
      created_at       TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reports (
      id               TEXT PRIMARY KEY,
      report_id        TEXT NOT NULL,
      investigation_id TEXT NOT NULL REFERENCES investigations(id) ON DELETE CASCADE,
      report_json      TEXT NOT NULL,
      created_at       TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_evidence_investigation ON evidence_files(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_events_investigation   ON events(investigation_id);
    CREATE INDEX IF NOT EXISTS idx_events_evidence_file  ON events(evidence_file_id);
    CREATE INDEX IF NOT EXISTS idx_events_event_id       ON events(investigation_id, event_id);
    CREATE INDEX IF NOT EXISTS idx_reports_investigation ON reports(investigation_id);
  `)
  console.log('[DB] Schema ready — incidentiq.db')
}

export default getDb
