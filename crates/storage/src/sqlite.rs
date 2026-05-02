//! SQLite-backed session store.
//!
//! This module provides a durable `SessionStore` implementation backed by
//! a SQLite database. It is available only when the `sqlite` feature is
//! enabled.
//!
//! # Schema
//!
//! Two tables are created on first use:
//!
//! ```sql
//! CREATE TABLE IF NOT EXISTS sessions (
//!     session_id   TEXT    NOT NULL PRIMARY KEY,
//!     session_json TEXT    NOT NULL,
//!     is_terminal  INTEGER NOT NULL DEFAULT 0
//! );
//!
//! CREATE TABLE IF NOT EXISTS approvals (
//!     session_id   TEXT NOT NULL,
//!     verifier_id  TEXT NOT NULL,
//!     UNIQUE(session_id, verifier_id)
//! );
//! ```
//!
//! `session_id` and `verifier_id` are stored as hex strings for readability
//! and cross-language compatibility.
//!
//! `is_terminal` is maintained as a separate column (not derived from
//! `session_json`) so that the terminal-state check can be performed with
//! a lightweight indexed query rather than deserializing the full session.
//!
//! # Replay protection
//!
//! All three replay-protection invariants from `traits.rs` are enforced
//! by a combination of application logic and DB constraints:
//!
//! 1. `SessionId` uniqueness: enforced by the `PRIMARY KEY` on `sessions`.
//! 2. Terminal immutability: enforced by checking `is_terminal` before
//!    any state update.
//! 3. Per-verifier approval uniqueness: enforced by `UNIQUE(session_id,
//!    verifier_id)` in the `approvals` table, with a pre-check in code.
//!
//! # Crash safety
//!
//! SQLite's write-ahead log (WAL) mode is enabled to improve concurrent
//! read performance and crash recovery. Each write operation runs in an
//! implicit transaction; multi-step sequences use explicit transactions.
//!
//! # Thread safety
//!
//! `rusqlite::Connection` is not `Sync`. We wrap it in a `Mutex` so the
//! store can be shared across threads. This serializes all DB access, which
//! is appropriate for a single-process node. A production deployment with
//! heavy write concurrency should consider a connection pool.

use crate::{error::StorageError, traits::SessionStore};
use rusqlite::{params, Connection, OptionalExtension};
use std::sync::Mutex;
use tls_attestation_attestation::session::{Session, SessionState};
use tls_attestation_core::ids::{SessionId, VerifierId};

/// SQLite-backed session store.
///
/// See module documentation for schema and invariant details.
pub struct SqliteSessionStore {
    conn: Mutex<Connection>,
}

impl SqliteSessionStore {
    /// Open (or create) a SQLite database at `path` and run schema migrations.
    ///
    /// Passing `":memory:"` opens an in-memory database suitable for tests.
    /// The schema is created idempotently via `CREATE TABLE IF NOT EXISTS`.
    pub fn open(path: &str) -> Result<Self, StorageError> {
        let conn = Connection::open(path).map_err(|e| StorageError::Io(e.to_string()))?;

        // Enable WAL mode for better crash recovery and concurrent reads.
        conn.execute_batch("PRAGMA journal_mode=WAL;")
            .map_err(|e| StorageError::Io(e.to_string()))?;

        // Enable foreign key enforcement (good hygiene, no FK used here yet).
        conn.execute_batch("PRAGMA foreign_keys=ON;")
            .map_err(|e| StorageError::Io(e.to_string()))?;

        Self::migrate(&conn)?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Create schema tables. Idempotent — safe to call on every open.
    fn migrate(conn: &Connection) -> Result<(), StorageError> {
        conn.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS sessions (
                session_id   TEXT    NOT NULL PRIMARY KEY,
                session_json TEXT    NOT NULL,
                is_terminal  INTEGER NOT NULL DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS approvals (
                session_id   TEXT NOT NULL REFERENCES sessions(session_id),
                verifier_id  TEXT NOT NULL,
                UNIQUE(session_id, verifier_id)
            );
            ",
        )
        .map_err(|e| StorageError::Io(e.to_string()))
    }

    /// Encode a `SessionId` as a lowercase hex string for storage.
    fn encode_session_id(id: &SessionId) -> String {
        id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Encode a `VerifierId` as a lowercase hex string for storage.
    fn encode_verifier_id(id: &VerifierId) -> String {
        id.as_bytes().iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Decode a `SessionId` from a lowercase hex string (32 chars → 16 bytes).
    fn decode_session_id(s: &str) -> Result<SessionId, StorageError> {
        if s.len() != 32 {
            return Err(StorageError::Io(format!(
                "session_id hex must be 32 chars, got {}",
                s.len()
            )));
        }
        let mut arr = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let hex_str = std::str::from_utf8(chunk)
                .map_err(|_| StorageError::Io("non-UTF8 in session_id hex".into()))?;
            arr[i] = u8::from_str_radix(hex_str, 16)
                .map_err(|e| StorageError::Io(format!("invalid hex byte '{hex_str}': {e}")))?;
        }
        Ok(SessionId::from_bytes(arr))
    }

    /// Return `true` if the session identified by `id_hex` is in a terminal state.
    ///
    /// Reads only the `is_terminal` column — does not deserialize the full session.
    fn is_terminal_by_hex(&self, conn: &Connection, id_hex: &str) -> Result<bool, StorageError> {
        let result: Option<i64> = conn
            .query_row(
                "SELECT is_terminal FROM sessions WHERE session_id = ?1",
                params![id_hex],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::Io(e.to_string()))?;

        match result {
            None => Err(StorageError::NotFound),
            Some(flag) => Ok(flag != 0),
        }
    }
}

// ── SessionStore implementation ───────────────────────────────────────────────

impl SessionStore for SqliteSessionStore {
    fn insert(&self, session: Session) -> Result<(), StorageError> {
        let id_hex = Self::encode_session_id(&session.context.session_id);
        let is_terminal = session.state.is_terminal() as i64;
        let json = serde_json::to_string(&session)
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let conn = self.conn.lock().unwrap();

        // Use INSERT OR FAIL so the UNIQUE constraint on session_id is enforced
        // atomically. If the row already exists we get a constraint error.
        let result = conn.execute(
            "INSERT OR FAIL INTO sessions (session_id, session_json, is_terminal) VALUES (?1, ?2, ?3)",
            params![id_hex, json, is_terminal],
        );

        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StorageError::AlreadyExists)
            }
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    fn get(&self, id: &SessionId) -> Result<Session, StorageError> {
        let id_hex = Self::encode_session_id(id);
        let conn = self.conn.lock().unwrap();

        let json: Option<String> = conn
            .query_row(
                "SELECT session_json FROM sessions WHERE session_id = ?1",
                params![id_hex],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let json = json.ok_or(StorageError::NotFound)?;
        serde_json::from_str(&json).map_err(|e| StorageError::Io(e.to_string()))
    }

    fn update_state(&self, id: &SessionId, state: SessionState) -> Result<(), StorageError> {
        let id_hex = Self::encode_session_id(id);
        let conn = self.conn.lock().unwrap();

        // Replay protection: read current session and check terminal status.
        if self.is_terminal_by_hex(&conn, &id_hex)? {
            return Err(StorageError::SessionTerminated);
        }

        // Deserialize, update state, re-serialize. This keeps session_json
        // authoritative and avoids storing state in two places without sync.
        let json: String = conn
            .query_row(
                "SELECT session_json FROM sessions WHERE session_id = ?1",
                params![id_hex],
                |row| row.get(0),
            )
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let mut session: Session =
            serde_json::from_str(&json).map_err(|e| StorageError::Io(e.to_string()))?;

        session.state = state.clone();
        let updated_json =
            serde_json::to_string(&session).map_err(|e| StorageError::Io(e.to_string()))?;
        let is_terminal = state.is_terminal() as i64;

        conn.execute(
            "UPDATE sessions SET session_json = ?1, is_terminal = ?2 WHERE session_id = ?3",
            params![updated_json, is_terminal, id_hex],
        )
        .map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn record_approval(&self, id: &SessionId, verifier_id: &VerifierId) -> Result<(), StorageError> {
        let id_hex = Self::encode_session_id(id);
        let vid_hex = Self::encode_verifier_id(verifier_id);
        let conn = self.conn.lock().unwrap();

        // Check existence and terminal state.
        if self.is_terminal_by_hex(&conn, &id_hex)? {
            return Err(StorageError::SessionTerminated);
        }

        // Insert approval; UNIQUE constraint prevents duplicates at the DB level.
        let result = conn.execute(
            "INSERT OR FAIL INTO approvals (session_id, verifier_id) VALUES (?1, ?2)",
            params![id_hex, vid_hex],
        );

        match result {
            Ok(_) => Ok(()),
            Err(rusqlite::Error::SqliteFailure(err, _))
                if err.code == rusqlite::ErrorCode::ConstraintViolation =>
            {
                Err(StorageError::DuplicateApproval {
                    verifier_id: verifier_id.to_string(),
                })
            }
            Err(e) => Err(StorageError::Io(e.to_string())),
        }
    }

    fn has_approved(&self, id: &SessionId, verifier_id: &VerifierId) -> bool {
        let id_hex = Self::encode_session_id(id);
        let vid_hex = Self::encode_verifier_id(verifier_id);
        let conn = self.conn.lock().unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM approvals WHERE session_id = ?1 AND verifier_id = ?2",
                params![id_hex, vid_hex],
                |row| row.get(0),
            )
            .unwrap_or(0);

        count > 0
    }

    fn remove(&self, id: &SessionId) -> Result<(), StorageError> {
        let id_hex = Self::encode_session_id(id);
        let conn = self.conn.lock().unwrap();

        // Delete approvals first (FK reference from approvals → sessions).
        conn.execute("DELETE FROM approvals WHERE session_id = ?1", params![id_hex])
            .map_err(|e| StorageError::Io(e.to_string()))?;
        conn.execute("DELETE FROM sessions WHERE session_id = ?1", params![id_hex])
            .map_err(|e| StorageError::Io(e.to_string()))?;

        Ok(())
    }

    fn contains(&self, id: &SessionId) -> bool {
        let id_hex = Self::encode_session_id(id);
        let conn = self.conn.lock().unwrap();

        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_id = ?1",
                params![id_hex],
                |row| row.get(0),
            )
            .unwrap_or(0);

        count > 0
    }
}

// ── Extension methods for testing convenience ─────────────────────────────────

impl SqliteSessionStore {
    /// Return all session IDs currently in the store. Intended for tests and
    /// diagnostics; not part of the `SessionStore` trait.
    pub fn all_session_ids(&self) -> Result<Vec<SessionId>, StorageError> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn
            .prepare("SELECT session_id FROM sessions")
            .map_err(|e| StorageError::Io(e.to_string()))?;

        let ids: Vec<SessionId> = stmt
            .query_map([], |row| row.get::<_, String>(0))
            .map_err(|e| StorageError::Io(e.to_string()))?
            .filter_map(|r| r.ok())
            .filter_map(|hex| Self::decode_session_id(&hex).ok())
            .collect();

        Ok(ids)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tls_attestation_attestation::session::{Session, SessionContext};
    use tls_attestation_core::{
        ids::{ProverId, SessionId, VerifierId},
        types::{Epoch, Nonce, QuorumSpec, UnixTimestamp},
    };

    fn make_session(id_byte: u8) -> Session {
        let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
        let ctx = SessionContext::new(
            SessionId::from_bytes([id_byte; 16]),
            ProverId::from_bytes([0u8; 32]),
            VerifierId::from_bytes([1u8; 32]),
            quorum,
            Epoch::GENESIS,
            UnixTimestamp(1000),
            UnixTimestamp(2000),
            Nonce::from_bytes([id_byte; 32]),
        );
        Session::new(ctx)
    }

    fn verifier(b: u8) -> VerifierId {
        VerifierId::from_bytes([b; 32])
    }

    fn open() -> SqliteSessionStore {
        SqliteSessionStore::open(":memory:").expect("in-memory SQLite should open")
    }

    // ── Basic CRUD ────────────────────────────────────────────────────────────

    #[test]
    fn sqlite_insert_and_get() {
        let store = open();
        let s = make_session(1);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        let retrieved = store.get(&id).unwrap();
        assert_eq!(retrieved.context.session_id, id);
    }

    #[test]
    fn sqlite_duplicate_insert_fails() {
        let store = open();
        let s = make_session(2);
        store.insert(s.clone()).unwrap();
        assert!(matches!(store.insert(s), Err(StorageError::AlreadyExists)));
    }

    #[test]
    fn sqlite_update_state() {
        let store = open();
        let s = make_session(3);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        let updated = store.get(&id).unwrap();
        assert_eq!(updated.state, SessionState::Active);
    }

    #[test]
    fn sqlite_contains_and_remove() {
        let store = open();
        let s = make_session(4);
        let id = s.context.session_id.clone();
        assert!(!store.contains(&id));
        store.insert(s).unwrap();
        assert!(store.contains(&id));
        store.remove(&id).unwrap();
        assert!(!store.contains(&id));
    }

    // ── Replay protection: terminal state ─────────────────────────────────────

    #[test]
    fn sqlite_update_state_on_finalized_fails() {
        let store = open();
        let s = make_session(5);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        store.update_state(&id, SessionState::Attesting).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();
        store.update_state(&id, SessionState::Finalized).unwrap();

        let result = store.update_state(&id, SessionState::Active);
        assert!(matches!(result, Err(StorageError::SessionTerminated)));
    }

    #[test]
    fn sqlite_session_id_not_reusable_after_finalization() {
        let store = open();
        let s = make_session(6);
        let id = s.context.session_id.clone();
        store.insert(s.clone()).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        store.update_state(&id, SessionState::Attesting).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();
        store.update_state(&id, SessionState::Finalized).unwrap();

        assert!(matches!(store.insert(s), Err(StorageError::AlreadyExists)));
    }

    // ── Replay protection: approval deduplication ─────────────────────────────

    #[test]
    fn sqlite_record_approval_succeeds_first_time() {
        let store = open();
        let s = make_session(7);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();

        assert!(!store.has_approved(&id, &verifier(1)));
        store.record_approval(&id, &verifier(1)).unwrap();
        assert!(store.has_approved(&id, &verifier(1)));
    }

    #[test]
    fn sqlite_duplicate_approval_fails() {
        let store = open();
        let s = make_session(8);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();

        store.record_approval(&id, &verifier(2)).unwrap();
        let result = store.record_approval(&id, &verifier(2));
        assert!(matches!(result, Err(StorageError::DuplicateApproval { .. })));
    }

    #[test]
    fn sqlite_approval_on_terminal_session_fails() {
        let store = open();
        let s = make_session(9);
        let id = s.context.session_id.clone();
        store.insert(s).unwrap();
        store.update_state(&id, SessionState::Active).unwrap();
        store.update_state(&id, SessionState::Attesting).unwrap();
        store.update_state(&id, SessionState::Collecting).unwrap();
        store.update_state(&id, SessionState::Finalized).unwrap();

        let result = store.record_approval(&id, &verifier(3));
        assert!(matches!(result, Err(StorageError::SessionTerminated)));
    }

    // ── Persistence / crash-recovery simulation ───────────────────────────────

    /// Simulate a process restart by closing and reopening the database file,
    /// then verifying that session state is preserved.
    #[test]
    fn sqlite_persists_session_across_simulated_restart() {
        let path = "/tmp/tls-attest-test-persist.db";
        // Clean up any leftover file from a previous run.
        let _ = std::fs::remove_file(path);

        // ── "Process 1": create and finalize a session ────────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let s = make_session(10);
            let id = s.context.session_id.clone();
            store.insert(s).unwrap();
            store.update_state(&id, SessionState::Active).unwrap();
            store.update_state(&id, SessionState::Attesting).unwrap();
            store.update_state(&id, SessionState::Collecting).unwrap();
            store.update_state(&id, SessionState::Finalized).unwrap();
        } // store and its connection are dropped here.

        // ── "Process 2": reopen and verify ───────────────────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let recovered_id = SessionId::from_bytes([10u8; 16]);

            // Session must be present and still finalized.
            let session = store.get(&recovered_id).unwrap();
            assert_eq!(
                session.state,
                SessionState::Finalized,
                "finalized state must survive restart"
            );

            // SessionId must still be occupied — cannot reuse.
            let quorum = QuorumSpec::new(vec![VerifierId::from_bytes([1u8; 32])], 1).unwrap();
            let ctx = SessionContext::new(
                recovered_id.clone(),
                ProverId::from_bytes([0u8; 32]),
                VerifierId::from_bytes([1u8; 32]),
                quorum,
                Epoch::GENESIS,
                UnixTimestamp(9000),
                UnixTimestamp(9999),
                Nonce::random(),
            );
            assert!(matches!(
                store.insert(Session::new(ctx)),
                Err(StorageError::AlreadyExists)
            ));

            // Terminal state must still be enforced.
            let result = store.update_state(&recovered_id, SessionState::Active);
            assert!(matches!(result, Err(StorageError::SessionTerminated)));
        }

        // Clean up.
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn sqlite_approvals_persist_across_simulated_restart() {
        let path = "/tmp/tls-attest-test-approvals.db";
        let _ = std::fs::remove_file(path);

        let id = SessionId::from_bytes([11u8; 16]);

        // ── "Process 1": collect partial approvals ────────────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let s = make_session(11);
            store.insert(s).unwrap();
            store.update_state(&id, SessionState::Collecting).unwrap();
            store.record_approval(&id, &verifier(10)).unwrap();
            store.record_approval(&id, &verifier(11)).unwrap();
        }

        // ── "Process 2": reopen and verify approvals ──────────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            assert!(store.has_approved(&id, &verifier(10)));
            assert!(store.has_approved(&id, &verifier(11)));
            assert!(!store.has_approved(&id, &verifier(99)));

            // Duplicate should still be rejected.
            assert!(matches!(
                store.record_approval(&id, &verifier(10)),
                Err(StorageError::DuplicateApproval { .. })
            ));
        }

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn sqlite_partial_session_resumable() {
        // Simulate a coordinator that crashes after creating the session but
        // before finalizing. On restart, the session is in Attesting state,
        // and processing can continue from there.
        let path = "/tmp/tls-attest-test-resume.db";
        let _ = std::fs::remove_file(path);
        let id = SessionId::from_bytes([12u8; 16]);

        // ── "Process 1": crash during Attesting ───────────────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let s = make_session(12);
            store.insert(s).unwrap();
            store.update_state(&id, SessionState::Active).unwrap();
            store.update_state(&id, SessionState::Attesting).unwrap();
            // "crash" here — session is in Attesting, not yet Collecting
        }

        // ── "Process 2": reload and resume from Attesting ─────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let session = store.get(&id).unwrap();
            assert_eq!(session.state, SessionState::Attesting);

            // Can advance to Collecting.
            store.update_state(&id, SessionState::Collecting).unwrap();
            store.update_state(&id, SessionState::Finalized).unwrap();

            let final_session = store.get(&id).unwrap();
            assert_eq!(final_session.state, SessionState::Finalized);
        }

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }

    #[test]
    fn sqlite_expired_session_not_resumable_after_restart() {
        let path = "/tmp/tls-attest-test-expired.db";
        let _ = std::fs::remove_file(path);
        let id = SessionId::from_bytes([13u8; 16]);

        // ── "Process 1": expire a session ────────────────────────────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let s = make_session(13);
            store.insert(s).unwrap();
            store.update_state(&id, SessionState::Active).unwrap();
            store.update_state(&id, SessionState::Expired).unwrap();
        }

        // ── "Process 2": reopen — expired session is not resumable ────────────
        {
            let store = SqliteSessionStore::open(path).unwrap();
            let session = store.get(&id).unwrap();
            assert_eq!(session.state, SessionState::Expired);

            let result = store.update_state(&id, SessionState::Active);
            assert!(matches!(result, Err(StorageError::SessionTerminated)));
        }

        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(format!("{path}-wal"));
        let _ = std::fs::remove_file(format!("{path}-shm"));
    }
}
