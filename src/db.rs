// ============================================================================
// db.rs — Persistance SQLite des sessions, commandes et credentials
// ============================================================================
//
// Schéma :
//   sessions    — une ligne par connexion SSH (IP, persona, score MITRE…)
//   commands    — chaque commande tapée avec sa réponse et son horodatage
//   credentials — tentatives d'authentification (login / mot de passe)
//   alerts      — sessions dont le score MITRE dépasse le seuil d'alerte
//
// Database est Clone (SqlitePool l'est aussi) → on la passe par valeur partout.
// ============================================================================

use anyhow::Result;
use chrono::Local;
use sqlx::{SqlitePool, sqlite::{SqliteConnectOptions, SqliteJournalMode}};
use std::str::FromStr;
use tracing::{info, warn};

// ----------------------------------------------------------------------------
// Structs de lecture (pour le rapport HTML)
// ----------------------------------------------------------------------------

#[derive(Debug, sqlx::FromRow)]
pub struct SessionData {
    pub id:          String,
    pub ip:          String,
    pub persona:     String,
    pub username:    String,
    pub started_at:  String,
    pub ended_at:    Option<String>,
    pub score_mitre: Option<i64>,
    pub tactiques:   Option<String>,
    pub techniques:  Option<String>,
    pub resume:      Option<String>,
}

#[derive(Debug, sqlx::FromRow)]
pub struct CommandeData {
    pub timestamp: String,
    pub commande:  String,
    pub reponse:   String,
    pub via_ia:    i64,
}

#[derive(Debug, sqlx::FromRow)]
pub struct CredentialFreq {
    pub username: String,
    pub password: String,
    pub nb:       i64,
}

#[derive(Debug, sqlx::FromRow)]
pub struct CommandeFreq {
    pub commande: String,
    pub nb:       i64,
}

// ----------------------------------------------------------------------------
// Structure principale
// ----------------------------------------------------------------------------

#[derive(Clone)]
pub struct Database {
    pool: SqlitePool,
}

impl Database {
    /// Ouvre (ou crée) la base SQLite au chemin indiqué.
    /// Le mode WAL (Write-Ahead Logging) améliore la concurrence : plusieurs
    /// lecteurs simultanés + un seul écrivain sans blocage.
    pub async fn new(chemin: &str) -> Result<Self> {
        let options = SqliteConnectOptions::from_str(&format!("sqlite://{}", chemin))?
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);

        let pool = SqlitePool::connect_with(options).await?;
        info!("💾 Base SQLite ouverte : {}", chemin);
        Ok(Database { pool })
    }

    /// Crée les 4 tables si elles n'existent pas encore.
    /// Idempotent : peut être appelé à chaque démarrage sans risque.
    pub async fn creer_tables(&self) -> Result<()> {
        // ── sessions ────────────────────────────────────────────────────────
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS sessions (
                id          TEXT    PRIMARY KEY,
                ip          TEXT    NOT NULL,
                persona     TEXT    NOT NULL,
                username    TEXT    NOT NULL,
                started_at  TEXT    NOT NULL,
                ended_at    TEXT,
                score_mitre INTEGER,
                tactiques   TEXT,
                techniques  TEXT,
                resume      TEXT
            )",
        )
        .execute(&self.pool)
        .await?;

        // ── commands ─────────────────────────────────────────────────────────
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS commands (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL,
                commande    TEXT    NOT NULL,
                reponse     TEXT    NOT NULL,
                via_ia      INTEGER NOT NULL DEFAULT 0
            )",
        )
        .execute(&self.pool)
        .await?;

        // ── credentials ──────────────────────────────────────────────────────
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS credentials (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL,
                ip          TEXT    NOT NULL,
                username    TEXT    NOT NULL,
                password    TEXT    NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        // ── alerts ───────────────────────────────────────────────────────────
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS alerts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id  TEXT    NOT NULL,
                timestamp   TEXT    NOT NULL,
                score       INTEGER NOT NULL,
                niveau      TEXT    NOT NULL,
                tactiques   TEXT    NOT NULL,
                message     TEXT    NOT NULL
            )",
        )
        .execute(&self.pool)
        .await?;

        info!("🗄️  Tables SQLite prêtes : sessions · commands · credentials · alerts");
        Ok(())
    }

    // ── sessions ─────────────────────────────────────────────────────────────

    /// Crée l'enregistrement de session dès l'ouverture du canal SSH.
    pub async fn inserer_session(
        &self,
        id:      &str,
        ip:      &str,
        persona: &str,
        username: &str,
    ) -> Result<()> {
        let now = Local::now().to_rfc3339();
        sqlx::query(
            "INSERT OR IGNORE INTO sessions (id, ip, persona, username, started_at)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(id)
        .bind(ip)
        .bind(persona)
        .bind(username)
        .bind(&now)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Met à jour la session en fin de connexion avec l'horodatage de fin
    /// et les résultats du scoring MITRE ATT&CK (tous optionnels).
    pub async fn finaliser_session(
        &self,
        id:         &str,
        score:      Option<u8>,
        tactiques:  Option<&str>,
        techniques: Option<&str>,
        resume:     Option<&str>,
    ) -> Result<()> {
        let now = Local::now().to_rfc3339();
        sqlx::query(
            "UPDATE sessions
             SET ended_at=?, score_mitre=?, tactiques=?, techniques=?, resume=?
             WHERE id=?",
        )
        .bind(&now)
        .bind(score.map(|s| s as i32))
        .bind(tactiques)
        .bind(techniques)
        .bind(resume)
        .bind(id)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── credentials ──────────────────────────────────────────────────────────

    /// Enregistre une tentative d'authentification SSH.
    pub async fn inserer_credential(
        &self,
        session_id: &str,
        ip:         &str,
        username:   &str,
        password:   &str,
    ) -> Result<()> {
        let now = Local::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO credentials (session_id, timestamp, ip, username, password)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(&now)
        .bind(ip)
        .bind(username)
        .bind(password)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── commands ─────────────────────────────────────────────────────────────

    /// Enregistre une commande tapée par l'attaquant avec la réponse fournie.
    /// `via_ia` indique si la réponse a été générée par le fallback Claude.
    pub async fn inserer_commande(
        &self,
        session_id: &str,
        commande:   &str,
        reponse:    &str,
        via_ia:     bool,
    ) -> Result<()> {
        let now = Local::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO commands (session_id, timestamp, commande, reponse, via_ia)
             VALUES (?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(&now)
        .bind(commande)
        .bind(reponse)
        .bind(via_ia as i32)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    // ── requêtes rapport ─────────────────────────────────────────────────────

    /// Statistiques globales pour l'en-tête du rapport.
    pub async fn stats_globales(&self) -> Result<(i64, i64, i64, i64, f64)> {
        let nb_sessions: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM sessions")
            .fetch_one(&self.pool).await?;
        let nb_creds: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM credentials")
            .fetch_one(&self.pool).await?;
        let nb_cmds: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM commands")
            .fetch_one(&self.pool).await?;
        let nb_alertes: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM alerts")
            .fetch_one(&self.pool).await?;
        let score_moy: (Option<f64>,) = sqlx::query_as(
            "SELECT AVG(CAST(score_mitre AS REAL)) FROM sessions WHERE score_mitre IS NOT NULL"
        ).fetch_one(&self.pool).await?;
        Ok((nb_sessions.0, nb_creds.0, nb_cmds.0, nb_alertes.0, score_moy.0.unwrap_or(0.0)))
    }

    /// Toutes les sessions triées par date décroissante.
    pub async fn toutes_sessions(&self) -> Result<Vec<SessionData>> {
        let rows = sqlx::query_as::<_, SessionData>(
            "SELECT id, ip, persona, username, started_at, ended_at,
                    score_mitre, tactiques, techniques, resume
             FROM sessions ORDER BY started_at DESC"
        ).fetch_all(&self.pool).await?;
        Ok(rows)
    }

    /// Commandes d'une session donnée, triées par timestamp.
    pub async fn commandes_session(&self, session_id: &str) -> Result<Vec<CommandeData>> {
        let rows = sqlx::query_as::<_, CommandeData>(
            "SELECT timestamp, commande, reponse, via_ia
             FROM commands WHERE session_id = ? ORDER BY timestamp ASC"
        ).bind(session_id).fetch_all(&self.pool).await?;
        Ok(rows)
    }

    /// Top N credentials les plus fréquents.
    pub async fn top_credentials(&self, n: i64) -> Result<Vec<CredentialFreq>> {
        let rows = sqlx::query_as::<_, CredentialFreq>(
            "SELECT username, password, COUNT(*) as nb
             FROM credentials GROUP BY username, password ORDER BY nb DESC LIMIT ?"
        ).bind(n).fetch_all(&self.pool).await?;
        Ok(rows)
    }

    /// Top N commandes les plus fréquentes.
    pub async fn top_commandes(&self, n: i64) -> Result<Vec<CommandeFreq>> {
        let rows = sqlx::query_as::<_, CommandeFreq>(
            "SELECT commande, COUNT(*) as nb
             FROM commands GROUP BY commande ORDER BY nb DESC LIMIT ?"
        ).bind(n).fetch_all(&self.pool).await?;
        Ok(rows)
    }

    // ── alerts ───────────────────────────────────────────────────────────────

    /// Crée une alerte pour les sessions dont le score MITRE dépasse le seuil.
    pub async fn inserer_alerte(
        &self,
        session_id: &str,
        score:      u8,
        niveau:     &str,
        tactiques:  &str,
        message:    &str,
    ) -> Result<()> {
        let now = Local::now().to_rfc3339();
        sqlx::query(
            "INSERT INTO alerts (session_id, timestamp, score, niveau, tactiques, message)
             VALUES (?, ?, ?, ?, ?, ?)",
        )
        .bind(session_id)
        .bind(&now)
        .bind(score as i32)
        .bind(niveau)
        .bind(tactiques)
        .bind(message)
        .execute(&self.pool)
        .await?;
        Ok(())
    }
}
