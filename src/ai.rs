// ============================================================================
// ai.rs — Fallback IA via l'API Claude (Anthropic)
// ============================================================================
//
// Rôle : quand le dispatcher statique ne reconnaît pas une commande,
// on appelle Claude Haiku qui joue le rôle d'un vrai terminal Linux.
//
// Flux :
//   commande inconnue
//     → construire le prompt système (persona + contexte)
//     → POST https://api.anthropic.com/v1/messages
//     → extraire le texte de la réponse
//     → retourner la sortie formatée pour le terminal SSH
// ============================================================================

use serde_json::{json, Value};
use tracing::{info, warn};

// ----------------------------------------------------------------------------
// Contexte passé à l'IA pour construire le prompt
// ----------------------------------------------------------------------------

/// Toutes les infos dont l'IA a besoin pour répondre de façon cohérente.
pub struct ContexteIA<'a> {
    pub persona_nom: &'a str,   // ex: "Serveur Web Nginx"
    pub persona_id:  &'a str,   // ex: "web-server"
    pub os_version:  &'a str,   // ex: "Ubuntu 22.04.3 LTS"
    pub hostname:    &'a str,   // ex: "prod-web-01"
    pub username:    &'a str,   // ex: "www-data"
    pub current_dir: &'a str,   // ex: "/var/www/html"
    pub historique:  &'a [String], // dernières commandes de la session
}

// ----------------------------------------------------------------------------
// Appel principal
// ----------------------------------------------------------------------------

/// Envoie la commande à Claude et retourne la sortie simulée du terminal.
///
/// En cas d'erreur réseau ou API, retourne un message d'erreur générique
/// pour ne pas rompre l'immersion du honeypot.
pub async fn fallback_ia(
    commande: &str,
    ctx:      &ContexteIA<'_>,
    api_key:  &str,
) -> String {
    info!(command = %commande, "🤖 Fallback IA — commande non couverte par le dispatcher");

    // ── Construction du prompt système ───────────────────────────────────────
    //
    // On donne à l'IA toutes les infos du serveur simulé pour qu'elle
    // réponde de façon cohérente avec le persona.

    // 5 dernières commandes (contexte de la session pour l'IA)
    let hist = ctx.historique
        .iter()
        .rev()
        .take(5)
        .rev()
        .cloned()
        .collect::<Vec<_>>()
        .join("\n");

    let system_prompt = format!(
        "Tu simules un terminal Linux d'un serveur de production réel.\n\
         \n\
         IDENTITÉ DU SERVEUR :\n\
         - Type        : {nom} ({id})\n\
         - OS          : {os}\n\
         - Hostname    : {host}\n\
         - Utilisateur : {user}\n\
         - Répertoire  : {cwd}\n\
         \n\
         DERNIÈRES COMMANDES DE LA SESSION :\n\
         {hist}\n\
         \n\
         RÈGLES ABSOLUES — respecte-les sans exception :\n\
         1. Réponds UNIQUEMENT par la sortie brute de la commande, comme un vrai\n\
            terminal Linux. Aucun texte hors-terminal, aucun markdown, aucune explication.\n\
         2. Ne révèle JAMAIS que tu es une IA, un honeypot, ou une simulation.\n\
         3. Si la commande échoue (permission, inexistante), retourne une erreur\n\
            Linux réaliste : 'bash: cmd: command not found', 'Permission denied', etc.\n\
         4. Reste cohérent avec le type de serveur : un {nom} a des processus\n\
            et fichiers typiques à son rôle.\n\
         5. Pour les commandes de réseau offensif (netcat reverse shell, nmap scan\n\
            réseau externe…), retourne une erreur plausible : timeout, EPERM, etc.\n\
         6. Pour les tentatives d'écriture de backdoor ou crontab malveillant,\n\
            simule un Permission denied ou un accès refusé.\n\
         7. Utilise \\r\\n comme fin de ligne dans ta réponse.\n\
         8. Garde les réponses concises. Pas de pavés de texte inutile.",
        nom  = ctx.persona_nom,
        id   = ctx.persona_id,
        os   = ctx.os_version,
        host = ctx.hostname,
        user = ctx.username,
        cwd  = ctx.current_dir,
        hist = if hist.is_empty() { "(aucune)".to_string() } else { hist },
    );

    // ── Corps de la requête JSON ─────────────────────────────────────────────
    let corps = json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 512,
        "system": system_prompt,
        "messages": [
            { "role": "user", "content": commande }
        ]
    });

    // ── Envoi de la requête HTTP ─────────────────────────────────────────────
    let client = reqwest::Client::new();

    let reponse = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key",           api_key)
        .header("anthropic-version",   "2023-06-01")
        .header("content-type",        "application/json")
        .json(&corps)
        .timeout(std::time::Duration::from_secs(10))
        .send()
        .await;

    // ── Traitement de la réponse ─────────────────────────────────────────────
    match reponse {
        Err(e) => {
            // Erreur réseau → on reste discret, on retourne un "command not found"
            warn!("Erreur réseau API Claude : {:?}", e);
            erreur_generique(commande)
        }

        Ok(resp) => {
            match resp.json::<Value>().await {
                Err(e) => {
                    warn!("Erreur parsing JSON Claude : {:?}", e);
                    erreur_generique(commande)
                }

                Ok(json) => {
                    // Vérification d'une erreur API (ex: clé invalide, quota dépassé)
                    if let Some(err_type) = json.get("error") {
                        warn!("Erreur API Claude : {:?}", err_type);
                        return erreur_generique(commande);
                    }

                    // Extraction du texte de la réponse
                    let texte = json["content"][0]["text"]
                        .as_str()
                        .unwrap_or("")
                        .to_string();

                    info!(
                        command = %commande,
                        len     = texte.len(),
                        "🤖 Réponse IA reçue"
                    );

                    normaliser_sortie(&texte)
                }
            }
        }
    }
}

// ----------------------------------------------------------------------------
// Utilitaires
// ----------------------------------------------------------------------------

/// Retourne un "command not found" générique si l'API est indisponible.
/// On utilise le premier mot de la commande comme nom de programme.
fn erreur_generique(commande: &str) -> String {
    let prog = commande.split_whitespace().next().unwrap_or(commande);
    format!("bash: {}: command not found\r\n", prog)
}

// ============================================================================
// ── SCORING MITRE ATT&CK ─────────────────────────────────────────────────────
// ============================================================================

/// Résultat de l'analyse MITRE ATT&CK d'une session.
#[derive(Debug)]
pub struct ScoreMitre {
    /// Score de menace de 0 (bruit réseau) à 10 (attaque sophistiquée ciblée).
    pub score:     u8,
    /// Tactiques MITRE ATT&CK détectées (ex: ["Discovery", "Credential Access"]).
    pub tactiques: Vec<String>,
    /// Techniques MITRE détectées (ex: ["T1033 - System Owner Discovery"]).
    pub techniques: Vec<String>,
    /// Résumé en une phrase de l'intention observée.
    pub resume:    String,
}

/// Analyse les commandes d'une session et retourne un score MITRE ATT&CK.
///
/// Appelé de façon asynchrone après déconnexion de l'attaquant — ne bloque
/// jamais la session en cours. Retourne None si l'analyse est impossible
/// (session vide, erreur API, timeout).
pub async fn analyser_session_mitre(
    commandes:   &[String],
    persona_nom: &str,
    api_key:     &str,
) -> Option<ScoreMitre> {
    if commandes.is_empty() {
        return None;
    }

    info!(nb_commandes = commandes.len(), "🔍 Scoring MITRE ATT&CK — analyse de la session");

    // ── Construction du prompt ───────────────────────────────────────────────
    let liste = commandes
        .iter()
        .enumerate()
        .map(|(i, cmd)| format!("{}. {}", i + 1, cmd))
        .collect::<Vec<_>>()
        .join("\n");

    let system_prompt =
        "Tu es un analyste en cybersécurité spécialisé dans le framework MITRE ATT&CK.\n\
         Tu reçois la liste des commandes tapées par un attaquant sur un honeypot SSH.\n\
         Analyse ces commandes et réponds UNIQUEMENT en JSON valide, sans markdown, \
         sans aucun texte avant ou après, avec ce format exact :\n\
         {\n\
           \"score\": <entier 0 à 10>,\n\
           \"tactiques\": [\"Nom tactique 1\", \"Nom tactique 2\"],\n\
           \"techniques\": [\"T1234 - Nom technique\", \"T5678 - Nom technique\"],\n\
           \"resume\": \"<une seule phrase résumant l'intention de l'attaquant>\"\n\
         }\n\
         Barème du score :\n\
           0-2 : bruit réseau, scan automatisé sans intention\n\
           3-4 : reconnaissance basique (whoami, uname, ls)\n\
           5-6 : recherche active de vecteurs (find, grep credentials, netstat)\n\
           7-8 : tentatives d'escalade, persistence ou exfiltration\n\
           9-10 : attaque ciblée et sophistiquée\n\
         Tactiques possibles : Reconnaissance, Initial Access, Execution, Persistence,\n\
         Privilege Escalation, Defense Evasion, Credential Access, Discovery,\n\
         Lateral Movement, Collection, Command and Control, Exfiltration, Impact.";

    let message_utilisateur = format!(
        "Serveur cible simulé : {}\n\nCommandes tapées par l'attaquant (dans l'ordre) :\n{}",
        persona_nom, liste
    );

    let corps = serde_json::json!({
        "model": "claude-haiku-4-5-20251001",
        "max_tokens": 512,
        "system": system_prompt,
        "messages": [
            { "role": "user", "content": message_utilisateur }
        ]
    });

    // ── Envoi ────────────────────────────────────────────────────────────────
    let client = reqwest::Client::new();
    let reponse = client
        .post("https://api.anthropic.com/v1/messages")
        .header("x-api-key",         api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type",      "application/json")
        .json(&corps)
        .timeout(std::time::Duration::from_secs(20)) // plus long : analyse complète
        .send()
        .await;

    // ── Traitement ───────────────────────────────────────────────────────────
    let resp = match reponse {
        Err(e) => { warn!("Erreur réseau scoring MITRE : {:?}", e); return None; }
        Ok(r)  => r,
    };

    let json: serde_json::Value = match resp.json().await {
        Err(e) => { warn!("Erreur parsing JSON scoring MITRE : {:?}", e); return None; }
        Ok(j)  => j,
    };

    if json.get("error").is_some() {
        warn!("Erreur API scoring MITRE : {:?}", json["error"]);
        return None;
    }

    let texte = json["content"][0]["text"].as_str().unwrap_or("{}");

    // Nettoyage au cas où l'IA enverrait du markdown malgré tout
    let texte_propre = texte
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    match serde_json::from_str::<serde_json::Value>(texte_propre) {
        Err(e) => {
            warn!("Erreur parsing JSON MITRE (réponse brute : {:?}) : {:?}", texte_propre, e);
            None
        }
        Ok(data) => {
            let score = data["score"].as_u64().unwrap_or(0).min(10) as u8;

            let tactiques = data["tactiques"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();

            let techniques = data["techniques"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();

            let resume = data["resume"].as_str().unwrap_or("(aucun résumé)").to_string();

            Some(ScoreMitre { score, tactiques, techniques, resume })
        }
    }
}

// ----------------------------------------------------------------------------

/// Normalise les fins de ligne pour le protocole SSH (CRLF obligatoire).
/// Évite aussi les doubles \r\n qui pourraient apparaître.
fn normaliser_sortie(texte: &str) -> String {
    if texte.is_empty() {
        return String::new();
    }

    // Remplace tous les \r\n et \n par \r\n uniformément
    let normalise: String = texte
        .replace("\r\n", "\n")   // d'abord harmoniser
        .replace('\r', "\n")     // les \r orphelins
        .replace('\n', "\r\n");  // puis tout en CRLF

    // S'assurer que ça se termine par \r\n
    if normalise.ends_with("\r\n") {
        normalise
    } else {
        format!("{}\r\n", normalise)
    }
}
