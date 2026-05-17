// ============================================================================
// shell.rs — État d'une session shell interactive
// ============================================================================

use std::sync::Arc;
use chrono::{Local, Timelike};
use tracing::warn;

use crate::ai::{fallback_ia, ContexteIA};
use crate::persona::Persona;
use crate::vfs::Vfs;

/// Nombre maximum d'appels IA par session (~€0.14 à ce plafond avec Haiku 4.5).
/// Au-delà, les commandes inconnues retournent "command not found" sans appel API.
const IA_MAX_APPELS: u32 = 100;

/// Codes de couleur ANSI
pub mod ansi {
    pub const RESET: &str = "\x1b[0m";
    pub const BOLD:  &str = "\x1b[1m";
    pub const GREEN: &str = "\x1b[32m";
    pub const CYAN:  &str = "\x1b[36m";
}

// ----------------------------------------------------------------------------
// Mode du shell
// ----------------------------------------------------------------------------

/// Le shell peut être en mode normal ou en train de "lire" un fichier dans vim.
pub enum ShellMode {
    /// Mode normal : prompt bash standard
    Normal,
    /// Mode vim : on affiche un fichier, on attend :q pour sortir
    Vim(String),
    /// Saisie cachée du mot de passe pour sudo/su
    /// Le mode revient à Normal dès que l'utilisateur valide (Enter).
    SudoWait {
        /// Sous-commande à simuler après validation (ex: "bash", "cat /etc/shadow")
        commande: String,
    },
}

// ----------------------------------------------------------------------------
// Machine à états pour les séquences d'échappement ANSI
// ----------------------------------------------------------------------------
//
// Les touches fléchées envoient 3 octets : ESC (0x1b) + '[' + lettre.
// Ex : ↑ = 0x1b 0x5b 0x41  ↓ = 0x1b 0x5b 0x42
//
// On distingue 3 états :
//   Normal     → état de repos
//   Esc        → on a reçu 0x1b, on attend le '[' suivant
//   EscBracket → on a reçu 0x1b + '[', on attend la lettre finale

pub enum EscapeState {
    Normal,
    Esc,
    EscBracket,
}

// ----------------------------------------------------------------------------
// Résultat du traitement d'un caractère
// ----------------------------------------------------------------------------

pub enum InputResult {
    Echo(u8),
    Backspace,
    LineReady(String),
    Interrupt,
    Eof,
    Ignore,
    /// Efface la ligne courante et la réaffiche avec un nouveau contenu.
    /// Utilisé par les flèches haut/bas pour la navigation dans l'historique.
    RedrawLine(String),
    /// Sortie directe produite par le mode SudoWait après validation du mot de passe.
    /// Server.rs envoie \r\n + ce contenu + le nouveau prompt (sans passer par execute()).
    SudoOutput(String),
}

// ----------------------------------------------------------------------------
// Session shell
// ----------------------------------------------------------------------------

pub struct ShellSession {
    pub username:     String,
    pub current_dir:  String,
    pub input_buffer: Vec<u8>,
    pub active:       bool,
    pub persona:      Persona,

    /// Système de fichiers virtuel (partagé en lecture seule avec Arc)
    pub vfs:          Arc<Vfs>,

    /// Mode actuel : Normal ou Vim(chemin)
    pub mode:         ShellMode,

    /// Historique des commandes tapées pendant la session
    pub historique:   Vec<String>,

    /// Clé API Anthropic pour le fallback IA (None = pas d'IA configurée)
    pub api_key:      Option<String>,

    /// Compteur d'appels IA pour la session en cours (plafond = IA_MAX_APPELS)
    pub ia_appels:      u32,

    /// Vrai si la dernière commande a été traitée par le fallback IA.
    /// Utilisé par server.rs pour annoter les logs SQLite.
    pub dernier_via_ia: bool,

    /// Buffer de saisie cachée pour sudo/su — jamais affiché à l'écran.
    /// Vidé et utilisé uniquement pendant le mode SudoWait.
    pub sudo_buffer: Vec<u8>,

    // ── Navigation dans l'historique (flèches ↑↓) ───────────────────────────
    /// État de la machine à états pour les séquences ANSI
    escape_state:   EscapeState,
    /// Index dans l'historique pendant la navigation (None = pas en navigation)
    history_index:  Option<usize>,
    /// Sauvegarde du buffer en cours quand on commence à naviguer dans l'historique
    saved_input:    String,
}

impl ShellSession {
    pub fn new(username: String, persona: Persona, vfs: Arc<Vfs>, api_key: Option<String>) -> Self {
        let home = persona.shell.home.clone();
        ShellSession {
            username,
            current_dir: home,
            input_buffer: Vec::new(),
            active: true,
            persona,
            vfs,
            mode: ShellMode::Normal,
            historique: Vec::new(),
            api_key,
            ia_appels:      0,
            dernier_via_ia: false,
            sudo_buffer:    Vec::new(),
            escape_state:   EscapeState::Normal,
            history_index: None,
            saved_input:   String::new(),
        }
    }

    // ── Prompt ───────────────────────────────────────────────────────────────

    pub fn prompt(&self) -> String {
        match &self.mode {
            // Vim et SudoWait : pas de prompt bash (curseur reste sur la ligne en cours)
            ShellMode::Vim(_) | ShellMode::SudoWait { .. } => String::new(),

            ShellMode::Normal => {
                let home = &self.persona.shell.home;
                let display_dir = if &self.current_dir == home {
                    "~".to_string()
                } else if self.current_dir.starts_with(home.as_str()) {
                    self.current_dir.replacen(home.as_str(), "~", 1)
                } else {
                    self.current_dir.clone()
                };

                // root → '#' en rouge, utilisateur normal → '$' en vert
                let (couleur, symbole) = if self.username == "root" {
                    ("\x1b[31m", "#")   // rouge
                } else {
                    (ansi::GREEN, "$")
                };

                format!(
                    "{}{}{}@{}{}:{}{}{}{}",
                    ansi::BOLD, couleur,
                    self.username,
                    self.persona.systeme.hostname,
                    ansi::RESET,
                    ansi::CYAN,
                    display_dir,
                    ansi::RESET,
                    format!(" {symbole} "),
                )
            }
        }
    }

    // ── Banner (MOTD) ────────────────────────────────────────────────────────

    pub fn banner(&self) -> String {
        let now = Local::now();
        let sys = &self.persona.systeme;
        let ts  = now.timestamp();

        let prefixes = [85u8, 92, 176, 185, 194, 217];
        let prefix   = prefixes[(ts % prefixes.len() as i64) as usize];
        let last_ip  = format!(
            "{}.{}.{}.{}",
            prefix,
            (ts / 7 % 200 + 10) as u8,
            (ts / 60 % 256)     as u8,
            (ts / 3600 % 254 + 1) as u8,
        );

        let login_il_y_a = chrono::Duration::hours(ts % 72 + 1);
        let last_login   = now - login_il_y_a;

        let updates_total    = (ts % 23 + 5)  as u32;
        let updates_securite = (ts % 4  + 1)  as u32;

        let heure           = now.hour();
        let users_connectes = if heure >= 9 && heure <= 18 {
            sys.utilisateurs + (ts % 2) as u32
        } else {
            sys.utilisateurs
        };

        let charge_base: f64 = sys.charge.parse().unwrap_or(0.5);
        let charge_str       = format!("{:.2}", charge_base + (ts % 10) as f64 * 0.03);

        format!(
            "\r\n\
Welcome to {os} (GNU/Linux {kernel} {arch})\r\n\
\r\n\
 * Documentation:  https://help.ubuntu.com\r\n\
 * Management:     https://landscape.canonical.com\r\n\
 * Support:        https://ubuntu.com/advantage\r\n\
\r\n\
Expanded Security Maintenance for Applications is not enabled.\r\n\
\r\n\
{updates} updates can be applied immediately.\r\n\
{sec_updates} of these updates are standard security updates.\r\n\
To see these additional updates run: apt list --upgradeable\r\n\
\r\n\
*** System restart required ***\r\n\
\r\n\
  System load:  {load:<16} Processes:             {procs}\r\n\
  Usage of /:   {disk:<16} Users logged in:       {users}\r\n\
  Memory usage: {mem:<16} IPv4 address for eth0: {ip}\r\n\
  Swap usage:   {swap}\r\n\
\r\n\
Unauthorized access to this system is forbidden and will be\r\n\
prosecuted by law. By accessing this system, you agree that\r\n\
your actions may be monitored and recorded.\r\n\
\r\n\
Last login: {login_date} from {last_ip}\r\n\r\n",
            os           = sys.os_version,
            kernel       = sys.kernel,
            arch         = sys.arch,
            updates      = updates_total,
            sec_updates  = updates_securite,
            load         = charge_str,
            procs        = sys.processus + (ts % 15) as u32,
            disk         = sys.disque,
            users        = users_connectes,
            mem          = sys.memoire,
            ip           = sys.ip,
            swap         = sys.swap,
            login_date   = last_login.format("%a %b %e %H:%M:%S %Y"),
            last_ip      = last_ip,
        )
    }

    // ── Traitement des entrées ────────────────────────────────────────────────

    pub fn process_byte(&mut self, byte: u8) -> InputResult {
        // ── Mode SudoWait : saisie cachée du mot de passe ─────────────────────
        // Court-circuite tout le reste : les caractères ne sont pas affichés.
        if matches!(self.mode, ShellMode::SudoWait { .. }) {
            return self.traiter_octet_sudo(byte);
        }

        // ── Machine à états pour les séquences ANSI ──────────────────────────
        //
        // Les flèches clavier envoient 3 octets successifs :
        //   0x1b → '[' → 'A'/'B'/'C'/'D'
        //
        // On gère les 3 états avant le match général sur les octets normaux.

        match self.escape_state {
            // En attente du '[' après le ESC
            EscapeState::Esc => {
                if byte == b'[' {
                    self.escape_state = EscapeState::EscBracket;
                } else {
                    // Séquence ESC inconnue → on abandonne
                    self.escape_state = EscapeState::Normal;
                }
                return InputResult::Ignore;
            }

            // En attente de la lettre finale après ESC + '['
            EscapeState::EscBracket => {
                self.escape_state = EscapeState::Normal;
                return match byte {
                    b'A' => self.history_up(),    // ↑  flèche haut
                    b'B' => self.history_down(),  // ↓  flèche bas
                    _    => InputResult::Ignore,  // ← → et autres : ignorés
                };
            }

            EscapeState::Normal => {} // traitement normal ci-dessous
        }

        // ── Traitement des octets normaux ─────────────────────────────────────
        match byte {
            // Entrée → on valide la ligne
            b'\r' | b'\n' => {
                self.history_index = None; // reset navigation historique
                let line = String::from_utf8_lossy(&self.input_buffer)
                    .trim()
                    .to_string();
                self.input_buffer.clear();
                InputResult::LineReady(line)
            }

            // Backspace / DEL
            0x7f | 0x08 => {
                if self.input_buffer.is_empty() {
                    InputResult::Ignore
                } else {
                    self.input_buffer.pop();
                    InputResult::Backspace
                }
            }

            // Ctrl+C → interruption
            0x03 => {
                self.input_buffer.clear();
                self.history_index = None;
                InputResult::Interrupt
            }

            // Ctrl+D → EOF (déconnexion)
            0x04 => {
                if self.input_buffer.is_empty() {
                    self.active = false;
                    InputResult::Eof
                } else {
                    InputResult::Ignore
                }
            }

            // ESC → début de séquence ANSI, on change d'état
            0x1b => {
                self.escape_state = EscapeState::Esc;
                InputResult::Ignore
            }

            // Caractères imprimables (espace à tilde)
            32..=126 => {
                self.history_index = None; // toute frappe annule la navigation
                self.input_buffer.push(byte);
                InputResult::Echo(byte)
            }

            _ => InputResult::Ignore,
        }
    }

    // ── Navigation dans l'historique ─────────────────────────────────────────

    /// Flèche ↑ : remonte d'une entrée dans l'historique.
    fn history_up(&mut self) -> InputResult {
        if self.historique.is_empty() {
            return InputResult::Ignore;
        }

        let new_idx = match self.history_index {
            // Premier appui : on sauvegarde l'input courant et on va au plus récent
            None => {
                self.saved_input = String::from_utf8_lossy(&self.input_buffer).to_string();
                self.historique.len() - 1
            }
            // Déjà en navigation : on remonte (sans dépasser le début)
            Some(0)  => 0,
            Some(i)  => i - 1,
        };

        self.history_index = Some(new_idx);
        let contenu = self.historique[new_idx].clone();
        self.input_buffer = contenu.as_bytes().to_vec();
        InputResult::RedrawLine(contenu)
    }

    /// Flèche ↓ : descend d'une entrée dans l'historique.
    /// Quand on atteint le bas, on restaure le texte qu'on était en train de taper.
    fn history_down(&mut self) -> InputResult {
        match self.history_index {
            None => InputResult::Ignore,
            Some(i) if i + 1 >= self.historique.len() => {
                // Fin de l'historique → on restaure l'input sauvegardé
                self.history_index = None;
                let contenu = self.saved_input.clone();
                self.input_buffer = contenu.as_bytes().to_vec();
                InputResult::RedrawLine(contenu)
            }
            Some(i) => {
                let new_idx = i + 1;
                self.history_index = Some(new_idx);
                let contenu = self.historique[new_idx].clone();
                self.input_buffer = contenu.as_bytes().to_vec();
                InputResult::RedrawLine(contenu)
            }
        }
    }

    // ── Saisie cachée (sudo/su) ───────────────────────────────────────────────

    /// Gère un octet reçu pendant la saisie du mot de passe sudo/su.
    /// Aucun caractère n'est affiché à l'écran (saisie invisible).
    fn traiter_octet_sudo(&mut self, byte: u8) -> InputResult {
        match byte {
            // Entrée : on valide le mot de passe
            b'\r' | b'\n' => {
                let mdp = String::from_utf8_lossy(&self.sudo_buffer).to_string();
                self.sudo_buffer.clear();

                // On récupère la commande demandée avant de changer de mode
                let commande = if let ShellMode::SudoWait { commande } = &self.mode {
                    commande.clone()
                } else {
                    String::new()
                };

                // Log du mot de passe comme entrée de session (visible dans le rapport)
                self.historique.push(format!("[sudo:mdp] {}", mdp));

                // Détermine si c'est une ouverture de shell root
                let est_shell_root = matches!(
                    commande.split_whitespace().next().unwrap_or(""),
                    "bash" | "sh" | "-s" | "-i" | "su"
                ) || commande.trim() == "-s"
                  || commande.trim() == "-i"
                  || commande.is_empty();

                // Retour en mode Normal avant de construire la sortie
                self.mode = ShellMode::Normal;

                let sortie = if est_shell_root {
                    // Élévation privilèges : détermine l'utilisateur cible
                    let cible = if commande.starts_with("su ") {
                        commande.split_whitespace().nth(1).unwrap_or("root").to_string()
                    } else {
                        "root".to_string()
                    };
                    self.username    = cible.clone();
                    self.current_dir = if cible == "root" {
                        "/root".to_string()
                    } else {
                        format!("/home/{}", cible)
                    };
                    String::new() // le nouveau prompt s'affichera via server.rs
                } else {
                    // Autre commande sudo : on tente de l'exécuter via le dispatcher
                    if let Some(res) = crate::commands::executer(self, &commande) {
                        res
                    } else {
                        String::new()
                    }
                };

                InputResult::SudoOutput(sortie)
            }

            // Backspace : on efface sans afficher
            0x7f | 0x08 => {
                self.sudo_buffer.pop();
                InputResult::Ignore
            }

            // Ctrl+C : annule le sudo, retour au prompt normal
            0x03 => {
                self.sudo_buffer.clear();
                self.mode = ShellMode::Normal;
                InputResult::Interrupt
            }

            // Caractères imprimables : collecte silencieuse (aucun écho)
            32..=126 => {
                self.sudo_buffer.push(byte);
                InputResult::Ignore
            }

            _ => InputResult::Ignore,
        }
    }

    // ── Exécution ────────────────────────────────────────────────────────────

    /// Route vers le bon dispatcher selon le mode actuel.
    ///
    /// Flux :
    ///   1. Mode Vim → vim_commande (sync)
    ///   2. Mode Normal → dispatcher statique (sync)
    ///      Si la commande n'est pas reconnue (None) ET qu'une clé API est
    ///      configurée → fallback IA (async)
    ///      Sinon → "command not found" générique
    pub async fn execute(&mut self, line: &str) -> String {
        if line.is_empty() {
            return String::new();
        }

        match &self.mode {
            // ── Mode Vim : on délègue à vim_commande (sync) ──────────────────
            ShellMode::Vim(_) => crate::commands::vim_commande(self, line),

            // ── Mode SudoWait : ne devrait jamais recevoir de ligne complète ──
            // (traiter_octet_sudo intercepte l'Enter avant qu'il devienne LineReady)
            ShellMode::SudoWait { .. } => String::new(),

            // ── Mode Normal ───────────────────────────────────────────────────
            ShellMode::Normal => {
                // Étape 1 : dispatcher statique
                if let Some(sortie) = crate::commands::executer(self, line) {
                    self.dernier_via_ia = false;
                    return sortie;
                }

                // Étape 2 : fallback IA si une clé est disponible et plafond non atteint
                if let Some(ref cle) = self.api_key.clone() {
                    if self.ia_appels >= IA_MAX_APPELS {
                        // Plafond atteint → on simule un "command not found" sans appel API
                        warn!(
                            appels = self.ia_appels,
                            plafond = IA_MAX_APPELS,
                            "🚫 Plafond IA atteint — fallback désactivé pour cette session"
                        );
                        let prog = line.split_whitespace().next().unwrap_or(line);
                        return format!("{}: command not found\r\n", prog);
                    }

                    self.ia_appels += 1;
                    self.dernier_via_ia = true;
                    let ctx = ContexteIA {
                        persona_nom: &self.persona.nom,
                        persona_id:  &self.persona.id,
                        os_version:  &self.persona.systeme.os_version,
                        hostname:    &self.persona.systeme.hostname,
                        username:    &self.username,
                        current_dir: &self.current_dir,
                        historique:  &self.historique,
                    };
                    fallback_ia(line, &ctx, cle).await
                } else {
                    // Pas de clé API → comportement classique "command not found"
                    let prog = line.split_whitespace().next().unwrap_or(line);
                    format!("{}: command not found\r\n", prog)
                }
            }
        }
    }
}
