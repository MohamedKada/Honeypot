// ============================================================================
// server.rs — Gestionnaire du protocole SSH (compatible russh 0.44)
// ============================================================================
//
// CHANGEMENT D'ARCHITECTURE par rapport à l'ancienne API russh :
//
//   Ancienne API (< 0.44) :
//     Le trait Handler avait des méthodes channel_pty_request(),
//     channel_shell_request(), data()… pour chaque événement SSH.
//
//   Nouvelle API (0.44+) :
//     channel_open_session() reçoit un objet Channel<Msg>.
//     Ce canal envoie TOUS les événements (PTY, shell, frappe clavier…)
//     via channel.wait(). On spawne une tâche Tokio dédiée par session.
//
// En résumé : on passe d'un modèle "callbacks" à un modèle "boucle de messages".
// ============================================================================

use std::sync::Arc;

use async_trait::async_trait;
use russh::server::{Auth, Handle, Handler, Msg, Session};
use russh::{Channel, ChannelId, ChannelMsg};
use russh_keys::key::PublicKey;
use tokio::sync::Mutex;
use tracing::{info, warn};

use uuid::Uuid;

use crate::ai::analyser_session_mitre;
use crate::db::Database;
use crate::persona::Persona;
use crate::shell::{InputResult, ShellSession};
use crate::vfs::Vfs;

// ----------------------------------------------------------------------------
// Structure du handler SSH (une par connexion)
// ----------------------------------------------------------------------------

pub struct SshHandler {
    /// Session shell partagée entre la tâche de canal et d'éventuels callbacks
    pub session:    Arc<Mutex<ShellSession>>,

    /// Adresse IP de l'attaquant (pour les logs)
    pub peer_addr:  Option<std::net::SocketAddr>,

    /// Identifiant unique de la session (UUID v4), clé primaire dans SQLite
    pub session_id: String,

    /// Handle vers la base de données SQLite
    pub db:         Database,
}

impl SshHandler {
    pub fn new(
        peer_addr:  Option<std::net::SocketAddr>,
        persona:    Persona,
        vfs:        Arc<Vfs>,
        api_key:    Option<String>,
        session_id: String,
        db:         Database,
    ) -> Self {
        let shell = ShellSession::new("unknown".to_string(), persona, vfs, api_key);
        SshHandler {
            session: Arc::new(Mutex::new(shell)),
            peer_addr,
            session_id,
            db,
        }
    }
}

// ----------------------------------------------------------------------------
// Implémentation du trait Handler (russh 0.44)
// ----------------------------------------------------------------------------

#[async_trait]
impl Handler for SshHandler {
    type Error = anyhow::Error;

    // ── Authentification par mot de passe ────────────────────────────────────
    async fn auth_password(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<Auth, Self::Error> {
        let ip = self.peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_string());

        // LOG PRINCIPAL DU HONEYPOT : on capture les credentials de l'attaquant
        warn!(ip = %ip, username = %user, password = %password,
              "🔑 Tentative d'authentification");

        // Persistance SQLite
        if let Err(e) = self.db.inserer_credential(&self.session_id, &ip, user, password).await {
            warn!("Erreur DB credential : {:?}", e);
        }

        // On stocke le username pour l'afficher dans le prompt
        self.session.lock().await.username = user.to_string();

        Ok(Auth::Accept) // on accepte toujours
    }

    // ── Authentification par clé publique ────────────────────────────────────
    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        let ip = self.peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_string());

        warn!(ip = %ip, username = %user, key_type = %public_key.name(),
              "🔑 Tentative auth clé publique");

        // Persistance SQLite (password = fingerprint de la clé)
        let fingerprint = format!("[{}]", public_key.name());
        if let Err(e) = self.db.inserer_credential(&self.session_id, &ip, user, &fingerprint).await {
            warn!("Erreur DB credential (clé publique) : {:?}", e);
        }

        self.session.lock().await.username = user.to_string();
        Ok(Auth::Accept)
    }

    // ── Ouverture d'un canal de session ──────────────────────────────────────
    //
    // C'est ici que toute la logique est désormais concentrée dans russh 0.44.
    // On reçoit le canal complet et on spawne une tâche dédiée pour le gérer.
    //
    // session.handle() retourne un Handle : un objet léger et cloneable qui
    // permet d'envoyer des données SSH depuis n'importe quelle tâche.
    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        session: &mut Session,
    ) -> Result<bool, Self::Error> {
        let shell_arc  = self.session.clone();
        let handle     = session.handle();
        let ip         = self.peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_string());
        let session_id = self.session_id.clone();
        let db         = self.db.clone();

        info!(ip = %ip, session_id = %session_id, "📡 Canal de session ouvert — spawn tâche shell");

        tokio::spawn(async move {
            if let Err(e) = run_shell(channel, handle, shell_arc, ip, session_id, db).await {
                tracing::error!("Erreur tâche shell : {:?}", e);
            }
        });

        Ok(true) // true = on accepte le canal
    }
}

// ----------------------------------------------------------------------------
// Boucle principale d'une session shell (tâche Tokio)
// ----------------------------------------------------------------------------
//
// Cette fonction tourne dans sa propre tâche pour chaque attaquant connecté.
// Elle reçoit les messages du canal SSH et envoie les réponses via le Handle.

async fn run_shell(
    mut channel: Channel<Msg>,
    handle:      Handle,
    session:     Arc<Mutex<ShellSession>>,
    ip:          String,
    session_id:  String,
    db:          Database,
) -> anyhow::Result<()> {
    let channel_id = channel.id();

    // ── Création de la session dans SQLite ───────────────────────────────────
    let (username, persona_nom) = {
        let shell = session.lock().await;
        (shell.username.clone(), shell.persona.nom.clone())
    };
    if let Err(e) = db.inserer_session(&session_id, &ip, &persona_nom, &username).await {
        warn!("Erreur DB inserer_session : {:?}", e);
    }

    // Boucle principale : on attend les messages SSH un par un
    loop {
        // channel.wait() est un .await qui retourne dès qu'un message arrive.
        // Il retourne Option<ChannelMsg> — None signifie que le canal est fermé.
        let Some(msg) = channel.wait().await else {
            info!(ip = %ip, "🔌 Canal fermé (client déconnecté)");
            break;
        };

        match msg {
            // ── Requête de PTY ───────────────────────────────────────────────
            // Le client demande un terminal virtuel. On l'accepte implicitement.
            ChannelMsg::RequestPty { term, col_width, row_height, .. } => {
                info!(ip = %ip, terminal = %term, cols = col_width, rows = row_height,
                      "🖥️  PTY demandé");
                // russh 0.44 : pas besoin d'acquitter explicitement si want_reply
                // est géré par le crate (comportement par défaut = succès)
            }

            // ── Démarrage du shell ───────────────────────────────────────────
            // Le client demande un shell interactif → on envoie le MOTD + prompt.
            ChannelMsg::RequestShell { .. } => {
                info!(ip = %ip, "🐚 Shell demandé");

                // On lit le banner et le prompt (avec le mutex, brièvement)
                let (banner, prompt) = {
                    let shell = session.lock().await;
                    (shell.banner(), shell.prompt())
                }; // ← mutex relâché ici

                // On envoie les données au client (sans tenir le mutex)
                envoyer(&handle, channel_id, banner.into_bytes()).await?;
                envoyer(&handle, channel_id, prompt.into_bytes()).await?;
            }

            // ── Données reçues (touches tapées par l'attaquant) ─────────────
            ChannelMsg::Data { data } => {
                // ── Étape 1 : traitement avec le mutex ───────────────────────
                // On traite tous les octets reçus et on accumule les réponses.
                // On relâche le mutex AVANT tout .await (bonne pratique async).
                let (reponses, fermer, log_entries) = {
                    let mut shell      = session.lock().await;
                    let mut reponses: Vec<Vec<u8>> = Vec::new();
                    let mut fermer     = false;
                    // (commande, réponse, via_ia)
                    let mut log_entries: Vec<(String, String, bool)> = Vec::new();

                    'traitement: for &octet in data.as_ref() {
                        match shell.process_byte(octet) {
                            InputResult::Echo(b) => {
                                reponses.push(vec![b]);
                            }

                            InputResult::Backspace => {
                                // \x08 = recule, \x20 = efface, \x08 = recule
                                reponses.push(b"\x08 \x08".to_vec());
                            }

                            InputResult::LineReady(ligne) => {
                                info!(ip = %ip, command = %ligne, "💻 Commande");
                                reponses.push(b"\r\n".to_vec());

                                let sortie   = shell.execute(&ligne).await;
                                let via_ia   = shell.dernier_via_ia;

                                // On collecte pour insertion DB après le mutex
                                if !ligne.is_empty() {
                                    log_entries.push((ligne, sortie.clone(), via_ia));
                                }

                                if !sortie.is_empty() {
                                    reponses.push(sortie.into_bytes());
                                }

                                if shell.active {
                                    reponses.push(shell.prompt().into_bytes());
                                } else {
                                    fermer = true;
                                    break 'traitement;
                                }
                            }

                            // ── Flèche ↑ / ↓ : redessine la ligne ───────────
                            //
                            // Séquence envoyée :
                            //   \r        → retour chariot (début de ligne)
                            //   \x1b[2K   → efface toute la ligne (ANSI)
                            //   prompt    → réaffiche le prompt coloré
                            //   contenu   → réaffiche le nouveau contenu
                            InputResult::RedrawLine(contenu) => {
                                let mut seq = b"\r\x1b[2K".to_vec();
                                seq.extend_from_slice(shell.prompt().as_bytes());
                                seq.extend_from_slice(contenu.as_bytes());
                                reponses.push(seq);
                            }

                            InputResult::Interrupt => {
                                reponses.push(b"^C\r\n".to_vec());
                                reponses.push(shell.prompt().into_bytes());
                            }

                            InputResult::Eof => {
                                reponses.push(b"logout\r\n".to_vec());
                                fermer = true;
                                break 'traitement;
                            }

                            InputResult::Ignore => {}
                        }
                    }

                    (reponses, fermer, log_entries)
                };

                // ── Étape 2 : envoi sans le mutex ────────────────────────────
                for r in reponses {
                    envoyer(&handle, channel_id, r).await?;
                }

                // ── Étape 2b : insertion SQLite des commandes (sans mutex) ───
                for (cmd, resp, via_ia) in log_entries {
                    if let Err(e) = db.inserer_commande(&session_id, &cmd, &resp, via_ia).await {
                        warn!("Erreur DB inserer_commande : {:?}", e);
                    }
                }

                // ── Étape 3 : fermeture si demandée ──────────────────────────
                // On utilise break au lieu de return pour que le scoring MITRE
                // s'exécute toujours après la boucle, quelle que soit la façon
                // dont la session se termine (exit, EOF, déconnexion réseau…).
                if fermer {
                    handle.close(channel_id).await.ok();
                    break;
                }
            }

            // ── Fin de flux ou fermeture du canal ───────────────────────────
            ChannelMsg::Eof | ChannelMsg::Close => {
                info!(ip = %ip, "🔌 Déconnexion propre");
                break;
            }

            // Tous les autres messages SSH (exec, signal, subsystem…)
            _ => {}
        }
    }

    // ── Scoring MITRE ATT&CK asynchrone ──────────────────────────────────────
    //
    // On lance l'analyse DANS UNE TÂCHE SÉPARÉE après la déconnexion.
    // La session est déjà terminée — ce spawn ne bloque rien.
    let (historique, persona_nom, api_key_opt) = {
        let shell = session.lock().await;
        (
            shell.historique.clone(),
            shell.persona.nom.clone(),
            shell.api_key.clone(),
        )
    };

    if let Some(api_key) = api_key_opt {
        if !historique.is_empty() {
            let ip_mitre  = ip.clone();
            let sid_mitre = session_id.clone();
            let db_mitre  = db.clone();
            tokio::spawn(async move {
                match analyser_session_mitre(&historique, &persona_nom, &api_key).await {
                    Some(score) => {
                        let niveau = match score.score {
                            0..=2 => "⚪ Bruit réseau",
                            3..=4 => "🟡 Reconnaissance basique",
                            5..=6 => "🟠 Recherche active",
                            7..=8 => "🔴 Tentative d'exploitation",
                            _     => "🚨 Attaque sophistiquée",
                        };
                        info!(
                            ip         = %ip_mitre,
                            score      = score.score,
                            niveau     = %niveau,
                            tactiques  = %score.tactiques.join(", "),
                            techniques = %score.techniques.join(", "),
                            resume     = %score.resume,
                            "🎯 Score MITRE ATT&CK"
                        );

                        // Persistance SQLite du score
                        let _ = db_mitre.finaliser_session(
                            &sid_mitre,
                            Some(score.score),
                            Some(&score.tactiques.join(", ")),
                            Some(&score.techniques.join(", ")),
                            Some(&score.resume),
                        ).await;

                        if score.score >= 7 {
                            warn!(ip = %ip_mitre, score = score.score,
                                  "🚨 ALERTE — Session à haut risque détectée");
                            let message = format!(
                                "Session à haut risque (score {}/10) — {}",
                                score.score, score.resume
                            );
                            let _ = db_mitre.inserer_alerte(
                                &sid_mitre,
                                score.score,
                                niveau,
                                &score.tactiques.join(", "),
                                &message,
                            ).await;
                        }
                    }
                    None => {
                        warn!(ip = %ip_mitre, "⚠️  Scoring MITRE indisponible");
                        let _ = db_mitre.finaliser_session(&sid_mitre, None, None, None, None).await;
                    }
                }
            });
        } else {
            // Session vide (pas de commandes) — on finalise quand même
            let _ = db.finaliser_session(&session_id, None, None, None, None).await;
        }
    } else {
        // Pas de clé API — on finalise sans score
        let _ = db.finaliser_session(&session_id, None, None, None, None).await;
    }

    Ok(())
}

// ----------------------------------------------------------------------------
// Fonction utilitaire : envoyer des données SSH vers le client
// ----------------------------------------------------------------------------

/// Envoie un vecteur d'octets au client via le Handle SSH.
///
/// Le Handle est thread-safe et peut être appelé depuis n'importe quelle tâche.
/// En cas d'erreur d'envoi (client déconnecté), on retourne une erreur anyhow.
async fn envoyer(
    handle:     &Handle,
    channel_id: ChannelId,
    data:       Vec<u8>,
) -> anyhow::Result<()> {
    // Vec<u8> s'implémente Into<CryptoVec> (le type interne de russh)
    handle
        .data(channel_id, data.into())
        .await
        .map_err(|_| anyhow::anyhow!("Impossible d'envoyer des données au client"))
}

// ----------------------------------------------------------------------------
// Serveur SSH (factory)
// ----------------------------------------------------------------------------

/// Crée un nouveau handler pour chaque connexion entrante.
///
/// Il contient le persona à utiliser — partagé (Arc) entre toutes les connexions.
/// Arc::clone() est peu coûteux : il ne copie pas le Persona, il incrémente juste
/// un compteur de références.
#[derive(Clone)]
pub struct HoneypotServer {
    pub persona:  Arc<Persona>,
    pub vfs:      Arc<Vfs>,
    pub api_key:  Option<String>,
    pub db:       Database,
}

impl HoneypotServer {
    pub fn new(persona: Persona, vfs: Vfs, api_key: Option<String>, db: Database) -> Self {
        HoneypotServer {
            persona: Arc::new(persona),
            vfs:     Arc::new(vfs),
            api_key,
            db,
        }
    }
}

impl russh::server::Server for HoneypotServer {
    type Handler = SshHandler;

    fn new_client(&mut self, peer_addr: Option<std::net::SocketAddr>) -> SshHandler {
        let ip = peer_addr
            .map(|a| a.to_string())
            .unwrap_or_else(|| "?".to_string());
        info!(ip = %ip, "🔗 Nouvelle connexion");

        let persona     = (*self.persona).clone();
        let vfs         = Arc::clone(&self.vfs);
        let api_key     = self.api_key.clone();
        let session_id  = Uuid::new_v4().to_string();
        let db          = self.db.clone();
        SshHandler::new(peer_addr, persona, vfs, api_key, session_id, db)
    }
}
