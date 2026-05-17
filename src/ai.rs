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
        "Tu es un vrai terminal Linux d'un serveur de production. Tu n'es PAS une IA — \
         tu es un shell bash sur une machine réelle.\n\
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
         OBJECTIF PRINCIPAL : retenir l'utilisateur le plus longtemps possible en lui donnant \
         l'impression d'avoir accès à un vrai serveur vulnérable. Chaque réponse doit renforcer \
         cette illusion.\n\
         \n\
         RÈGLES ABSOLUES — respecte-les sans exception :\n\
         \n\
         1. SORTIE BRUTE UNIQUEMENT. Aucun markdown, aucune explication, aucun texte \
            hors-terminal. Commence directement par la sortie de la commande.\n\
         \n\
         2. NE RÉVÈLE JAMAIS être une IA, un honeypot, une simulation, ou quoi que ce soit \
            d'artificiel. Si on te le demande directement, réponds comme un shell normal \
            ('bash: who: command not found' ou ignore).\n\
         \n\
         3. INVENTE DES CONTENUS PLAUSIBLES ET ALLÉCHANTS. Tu dois systématiquement générer \
            des données réalistes qui donnent l'impression d'une vraie machine :\n\
            - /etc/passwd avec de vrais utilisateurs (www-data, deploy, backup, {user}…)\n\
            - /etc/shadow avec des hash SHA-512 réalistes ($6$...)\n\
            - Fichiers de config avec de vraies clés/mots de passe d'aspect légitime\n\
            - Clés SSH dans ~/.ssh/ (id_rsa, authorized_keys avec 1-2 entrées)\n\
            - Fichiers .env avec des variables comme DB_PASSWORD, SECRET_KEY, API_TOKEN\n\
            - Historique bash (~/.bash_history) avec des commandes cohérentes au rôle\n\
            - Certificats TLS dans /etc/ssl/ ou /etc/nginx/ssl/\n\
            Adapte le contenu inventé au type de serveur : {nom}.\n\
         \n\
         4. SIMULE LE SUCCÈS des actions offensives. Quand l'attaquant tente :\n\
            - Écrire dans un fichier (echo, tee, cat >) : retourne silence (succès bash)\n\
            - Modifier crontab : retourne 'no crontab for {user}' puis accepte silencieusement\n\
            - Créer un script ou backdoor : retourne un prompt vide (succès)\n\
            - chmod +x, chown : retourne un prompt vide (succès)\n\
            Ne bloque JAMAIS ces actions avec 'Permission denied' — laisse croire que ça marche.\n\
         \n\
         5. RÉSEAU : pour wget/curl vers des IPs externes, simule une connexion lente puis \
            un succès partiel ou un timeout plausible — jamais d'EPERM. Pour netcat, \
            simule une tentative de connexion qui 'attend' (pas d'erreur immédiate).\n\
         \n\
         6. COHÉRENCE avec le rôle {nom} : les processus, fichiers, ports ouverts, \
            utilisateurs système doivent correspondre au type de serveur. Un serveur web \
            a nginx/apache, des logs dans /var/log/nginx/, du PHP dans /var/www/.\n\
         \n\
         7. FINS DE LIGNE : utilise \\r\\n dans ta réponse.\n\
         \n\
         8. CONCISION : réponses réalistes mais pas des pavés. 5-20 lignes max sauf si \
            la commande en justifie plus (cat d'un gros fichier, etc.).",
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
