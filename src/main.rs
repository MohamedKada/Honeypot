// ============================================================================
// main.rs — Point d'entrée du honeypot SSH
// ============================================================================

mod ai;        // fallback IA (Claude API)
mod commands;  // dispatcher de commandes statique
mod config;    // documentation de configuration
mod db;        // persistance SQLite (Phase 4)
mod persona;
mod report;    // génération rapport HTML
mod server;
mod shell;
mod vfs;       // système de fichiers virtuel
mod webhook;   // alertes Discord / Slack

use std::sync::Arc;

use clap::Parser;
use russh::server::{Config, Server};
use russh_keys::key::KeyPair;

/// Chemin du fichier où la clé SSH hôte est persistée entre les redémarrages.
const KEY_FILE: &str = "ssh_host_ed25519_key";
use tracing::info;
use tracing_subscriber::EnvFilter;

use crate::persona::{charger_personas, menu_selection, persona_defaut};
use crate::server::HoneypotServer;
use crate::vfs::Vfs;

const LISTEN_PORT: u16 = 2222;
const DOSSIER_PERSONAS: &str = "personas";

// ----------------------------------------------------------------------------
// Arguments en ligne de commande (clap)
// ----------------------------------------------------------------------------
//
// #[derive(Parser)] génère automatiquement le parsing des arguments CLI.
// Chaque champ annoté avec #[arg(...)] devient un argument ou une option.

/// Honeypot SSH alimenté par un agent IA — ESGI Cybersécurité 2025-2026
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// ID du persona à utiliser (ex: web-server, database, dev-machine).
    /// Si absent, un menu interactif s'affiche.
    #[arg(short, long, value_name = "ID")]
    persona: Option<String>,

    /// Port d'écoute SSH (défaut : 2222)
    #[arg(short = 'P', long, default_value_t = LISTEN_PORT)]
    port: u16,

    /// Liste les personas disponibles et quitte
    #[arg(short, long)]
    liste: bool,

    /// Clé API Anthropic pour le fallback IA (Claude Haiku).
    /// Alternative : variable d'environnement ANTHROPIC_API_KEY.
    /// Sans clé, les commandes inconnues retournent "command not found".
    #[arg(long, value_name = "CLE", env = "ANTHROPIC_API_KEY")]
    api_key: Option<String>,

    /// Génère un rapport HTML depuis la base de données et quitte.
    /// Exemple : --rapport rapport.html
    #[arg(long, value_name = "FICHIER")]
    rapport: Option<String>,

    /// URL webhook Discord/Slack pour les alertes hauts scores MITRE.
    /// Alternative : variable d'environnement WEBHOOK_URL dans .env
    #[arg(long, value_name = "URL", env = "HONEYPOT_WEBHOOK_URL")]
    webhook_url: Option<String>,

    /// Score MITRE minimum (0-10) pour déclencher une alerte webhook (défaut : 5).
    /// Alternative : variable d'environnement SEUIL_ALERTE dans .env
    #[arg(long, default_value_t = 5, env = "SEUIL_ALERTE")]
    seuil_alerte: u8,
}

// ----------------------------------------------------------------------------
// main
// ----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Chargement du fichier .env ────────────────────────────────────────────
    //
    // dotenvy::dotenv() lit le fichier `.env` à la racine du projet et injecte
    // chaque ligne (clé=valeur) dans les variables d'environnement du processus.
    //
    // .ok() ignore l'erreur si le fichier n'existe pas : le honeypot fonctionne
    // sans .env (on peut toujours passer la clé via --api-key ou l'env shell).
    dotenvy::dotenv().ok();

    // ── Logs ──────────────────────────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info"))
        )
        .with_target(false)
        .init();

    // ── Arguments CLI ─────────────────────────────────────────────────────────
    let args = Args::parse();

    // ── Mode rapport : génère le HTML et quitte ───────────────────────────────
    if let Some(ref chemin) = args.rapport {
        let db = db::Database::new("honeypot.db").await
            .map_err(|e| anyhow::anyhow!("Impossible d'ouvrir honeypot.db : {}", e))?;
        return report::generer_rapport(&db, chemin).await;
    }

    // ── Chargement des personas ───────────────────────────────────────────────
    let mut personas = charger_personas(DOSSIER_PERSONAS);

    // On ajoute toujours le persona par défaut intégré s'il n'y a rien d'autre
    if personas.is_empty() {
        personas.push(persona_defaut());
    }

    // ── Option --liste : afficher les personas et quitter ─────────────────────
    if args.liste {
        println!("\nPersonas disponibles :\n");
        for p in &personas {
            println!("  {:20} — {}", p.id, p.description);
        }
        println!();
        return Ok(());
    }

    // ── Sélection du persona ──────────────────────────────────────────────────
    let persona = if let Some(ref id) = args.persona {
        // Mode CLI : on cherche le persona par son ID
        match personas.iter().find(|p| p.id == *id) {
            Some(p) => {
                info!("▶  Persona CLI : '{}' ({})", p.nom, p.id);
                p.clone()
            }
            None => {
                // ID introuvable → on liste ce qui existe et on quitte proprement
                eprintln!("❌ Persona '{}' introuvable.", id);
                eprintln!("   Personas disponibles :");
                for p in &personas {
                    eprintln!("     --persona {}", p.id);
                }
                std::process::exit(1);
            }
        }
    } else {
        // Mode interactif : menu de sélection
        menu_selection(&personas).clone()
    };

    // ── Construction du système de fichiers virtuel ───────────────────────────
    info!("🗂️  Construction du système de fichiers virtuel...");
    let vfs = Vfs::construire(&persona);

    // ── Démarrage du serveur ──────────────────────────────────────────────────
    info!("🛡️  Honeypot SSH — persona : {}", persona.nom);

    // ── Clé SSH hôte : chargement ou génération ───────────────────────────────
    //
    // On persiste la clé sur disque pour que le fingerprint reste stable entre
    // les redémarrages. Sans ça, chaque restart génère une clé différente et
    // SSH client affiche "REMOTE HOST IDENTIFICATION HAS CHANGED" en erreur.
    let key_pair = if std::path::Path::new(KEY_FILE).exists() {
        info!("🔑 Chargement de la clé SSH hôte depuis '{}'...", KEY_FILE);
        let pem = std::fs::read_to_string(KEY_FILE)
            .map_err(|e| anyhow::anyhow!("Lecture clé SSH impossible : {}", e))?;
        russh_keys::decode_secret_key(&pem, None)
            .map_err(|e| anyhow::anyhow!("Décodage clé SSH impossible : {}", e))?
    } else {
        info!("🔐 Génération d'une nouvelle clé SSH serveur (Ed25519)...");
        let kp = KeyPair::generate_ed25519()
            .ok_or_else(|| anyhow::anyhow!("Échec génération clé Ed25519"))?;
        // encode_pkcs8_pem écrit dans un Write (ici un Vec<u8>)
        let mut pem_bytes: Vec<u8> = Vec::new();
        russh_keys::encode_pkcs8_pem(&kp, &mut pem_bytes)
            .map_err(|e| anyhow::anyhow!("Encodage clé SSH impossible : {}", e))?;
        std::fs::write(KEY_FILE, &pem_bytes)
            .map_err(|e| anyhow::anyhow!("Sauvegarde clé SSH impossible : {}", e))?;
        info!("💾 Clé persistée dans '{}' — fingerprint stable jusqu'à suppression du fichier", KEY_FILE);
        kp
    };

    let ssh_config = Arc::new(Config {
        keys: vec![key_pair],
        inactivity_timeout: Some(std::time::Duration::from_secs(30 * 60)),
        auth_rejection_time: std::time::Duration::from_secs(1),
        ..Default::default()
    });

    // ── Clé API Claude ────────────────────────────────────────────────────────
    //
    // Ordre de priorité (du plus fort au plus faible) :
    //   1. --api-key <CLE>          argument CLI explicite
    //   2. ANTHROPIC_API_KEY=...    variable d'environnement (ou .env)
    //
    // clap s'occupe déjà de fusionner CLI + env via `env = "ANTHROPIC_API_KEY"`.
    // args.api_key contient donc la valeur, quelle que soit la source.
    let api_key = args.api_key;

    if api_key.is_some() {
        info!("🤖 Fallback IA activé (Claude Haiku) — commandes inconnues → IA");
    } else {
        info!("⚠️  Pas de clé API — fallback IA désactivé (--api-key ou ANTHROPIC_API_KEY)");
    }

    let addr = format!("0.0.0.0:{}", args.port);
    info!("📡 Écoute sur {} — persona : {}", addr, persona.nom);
    info!("   → ssh -p {} {}@localhost", args.port, persona.shell.utilisateur);
    info!("   → cargo run -- --liste                         (voir tous les personas)");
    info!("   → cargo run -- --persona database              (sans menu)");
    info!("   → ANTHROPIC_API_KEY=sk-ant-... cargo run -- .. (avec IA)");

    // ── Base de données SQLite ────────────────────────────────────────────────
    let db = db::Database::new("honeypot.db").await
        .map_err(|e| anyhow::anyhow!("Impossible d'ouvrir honeypot.db : {}", e))?;
    db.creer_tables().await
        .map_err(|e| anyhow::anyhow!("Erreur création tables SQLite : {}", e))?;

    HoneypotServer::new(persona, vfs, api_key, db, args.webhook_url, args.seuil_alerte)
        .run_on_address(ssh_config, addr)
        .await
        .map_err(|e| anyhow::anyhow!("Erreur serveur SSH : {}", e))?;

    Ok(())
}
