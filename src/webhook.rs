// ============================================================================
// webhook.rs — Envoi d'alertes HTTP vers Discord, Slack ou endpoint générique
// ============================================================================
//
// Appelé après le scoring MITRE ATT&CK quand le score dépasse le seuil.
// Le format du payload est auto-détecté selon l'URL :
//
//   discord.com/api/webhooks/…  → Discord embed (couleur rouge, champs)
//   hooks.slack.com/…           → Slack block-kit (section + fields)
//   tout autre URL              → JSON générique plat
//
// L'envoi est best-effort : une erreur est loggée mais ne fait jamais planter
// le serveur. Timeout = 10 secondes.
// ============================================================================

use anyhow::Result;
use tracing::{info, warn};

// Seuil au-delà duquel on considère une session comme un niveau CRITIQUE
const SCORE_CRITIQUE: u8 = 9;

// ----------------------------------------------------------------------------
// Point d'entrée public
// ----------------------------------------------------------------------------

/// Envoie une alerte webhook pour une session à haut risque.
///
/// # Arguments
/// * `url`        — URL du webhook (Discord / Slack / générique)
/// * `ip`         — Adresse IP de l'attaquant
/// * `session_id` — UUID de la session SQLite
/// * `persona`    — Nom du persona ciblé
/// * `username`   — Login SSH utilisé
/// * `score`      — Score MITRE (0–10)
/// * `niveau`     — Label textuel du score (ex: "🔴 Tentative d'exploitation")
/// * `tactiques`  — Tactiques MITRE détectées (séparées par ", ")
/// * `techniques` — Techniques MITRE détectées (séparées par ", ")
/// * `resume`     — Résumé IA de la session
pub async fn envoyer_alerte_webhook(
    url:        &str,
    ip:         &str,
    session_id: &str,
    persona:    &str,
    username:   &str,
    score:      u8,
    niveau:     &str,
    tactiques:  &str,
    techniques: &str,
    resume:     &str,
) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()?;

    let body = if url.contains("discord.com/api/webhooks") {
        payload_discord(ip, session_id, persona, username, score, niveau, tactiques, techniques, resume)
    } else if url.contains("hooks.slack.com") {
        payload_slack(ip, session_id, persona, username, score, niveau, tactiques, resume)
    } else {
        payload_generique(ip, session_id, persona, username, score, niveau, tactiques, techniques, resume)
    };

    let resp = client
        .post(url)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await?;

    let status = resp.status();
    if status.is_success() {
        info!(score = score, ip = %ip, "📨 Webhook envoyé ({})", status.as_u16());
    } else {
        let texte = resp.text().await.unwrap_or_default();
        warn!(status = status.as_u16(), body = %texte, "⚠️  Webhook — réponse non-2xx");
    }

    Ok(())
}

// ----------------------------------------------------------------------------
// Payload Discord (embed)
// ----------------------------------------------------------------------------

fn payload_discord(
    ip:         &str,
    session_id: &str,
    persona:    &str,
    username:   &str,
    score:      u8,
    niveau:     &str,
    tactiques:  &str,
    techniques: &str,
    resume:     &str,
) -> String {
    // Couleur de la barre latérale : rouge CRITIQUE, orange ELEVÉ
    let color = if score >= SCORE_CRITIQUE { 15158332u32 } else { 16744272u32 };
    // 15158332 = 0xE74C3C (rouge), 16744272 = 0xFF8000 (orange)

    let titre = format!("🚨 Alerte Honeypot SSH — Score {}/10", score);

    // Le résumé IA tronqué à 1024 chars (limite Discord par champ)
    let resume_affiche = if resume.len() > 1024 {
        format!("{}…", &resume[..1021])
    } else {
        resume.to_string()
    };

    format!(
        r#"{{
  "embeds": [{{
    "title": {titre},
    "color": {color},
    "fields": [
      {{"name": "IP attaquant",  "value": {ip},     "inline": true}},
      {{"name": "Utilisateur",   "value": {user},   "inline": true}},
      {{"name": "Persona cible", "value": {persona},"inline": true}},
      {{"name": "Niveau",        "value": {niveau}, "inline": true}},
      {{"name": "Tactiques",     "value": {tact},   "inline": false}},
      {{"name": "Techniques",    "value": {tech},   "inline": false}},
      {{"name": "📝 Résumé IA",  "value": {resume}, "inline": false}},
      {{"name": "Session ID",    "value": {sid},    "inline": false}}
    ],
    "footer": {{"text": "Honeypot SSH — ESGI Cybersécurité 2025-2026"}}
  }}]
}}"#,
        titre   = json_str(&titre),
        color   = color,
        ip      = json_str(ip),
        user    = json_str(username),
        persona = json_str(persona),
        niveau  = json_str(niveau),
        tact    = json_str(if tactiques.is_empty() { "—" } else { tactiques }),
        tech    = json_str(if techniques.is_empty() { "—" } else { techniques }),
        resume  = json_str(&resume_affiche),
        sid     = json_str(session_id),
    )
}

// ----------------------------------------------------------------------------
// Payload Slack (Block Kit)
// ----------------------------------------------------------------------------

fn payload_slack(
    ip:         &str,
    session_id: &str,
    persona:    &str,
    username:   &str,
    score:      u8,
    niveau:     &str,
    tactiques:  &str,
    resume:     &str,
) -> String {
    let header = format!("🚨 Alerte Honeypot SSH — Score {}/10", score);
    format!(
        r#"{{
  "blocks": [
    {{
      "type": "header",
      "text": {{"type": "plain_text", "text": {header}, "emoji": true}}
    }},
    {{
      "type": "section",
      "fields": [
        {{"type": "mrkdwn", "text": "*IP :*\n{ip}"}},
        {{"type": "mrkdwn", "text": "*Utilisateur :*\n{user}"}},
        {{"type": "mrkdwn", "text": "*Persona :*\n{persona}"}},
        {{"type": "mrkdwn", "text": "*Niveau :*\n{niveau}"}},
        {{"type": "mrkdwn", "text": "*Tactiques :*\n{tact}"}},
        {{"type": "mrkdwn", "text": "*Session :*\n{sid}"}}
      ]
    }},
    {{"type": "divider"}},
    {{
      "type": "section",
      "text": {{"type": "mrkdwn", "text": "*📝 Résumé IA :*\n{resume}"}}
    }}
  ]
}}"#,
        header  = json_str(&header),
        ip      = ip,
        user    = username,
        persona = persona,
        niveau  = niveau,
        tact    = if tactiques.is_empty() { "—" } else { tactiques },
        sid     = session_id,
        resume  = json_str(resume),
    )
}

// ----------------------------------------------------------------------------
// Payload générique (JSON plat)
// ----------------------------------------------------------------------------

fn payload_generique(
    ip:         &str,
    session_id: &str,
    persona:    &str,
    username:   &str,
    score:      u8,
    niveau:     &str,
    tactiques:  &str,
    techniques: &str,
    resume:     &str,
) -> String {
    let ts = chrono::Local::now().to_rfc3339();
    format!(
        r#"{{
  "event":      "honeypot_alert",
  "timestamp":  {ts},
  "session_id": {sid},
  "ip":         {ip},
  "username":   {user},
  "persona":    {persona},
  "score_mitre": {score},
  "niveau":     {niveau},
  "tactiques":  {tact},
  "techniques": {tech},
  "resume":     {resume}
}}"#,
        ts      = json_str(&ts),
        sid     = json_str(session_id),
        ip      = json_str(ip),
        user    = json_str(username),
        persona = json_str(persona),
        score   = score,
        niveau  = json_str(niveau),
        tact    = json_str(if tactiques.is_empty() { "—" } else { tactiques }),
        tech    = json_str(if techniques.is_empty() { "—" } else { techniques }),
        resume  = json_str(resume),
    )
}

// ----------------------------------------------------------------------------
// Utilitaire : encode une &str en valeur JSON string (avec guillemets)
// ----------------------------------------------------------------------------

fn json_str(s: &str) -> String {
    // On échappe les caractères spéciaux JSON manuellement (pas de dépendance)
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"'  => out.push_str(r#"\""#),
            '\\' => out.push_str(r"\\"),
            '\n' => out.push_str(r"\n"),
            '\r' => out.push_str(r"\r"),
            '\t' => out.push_str(r"\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c    => out.push(c),
        }
    }
    out.push('"');
    out
}
