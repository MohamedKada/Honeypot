// ============================================================================
// report.rs — Génération du rapport HTML à partir de la base SQLite
// ============================================================================
//
// Produit un fichier HTML autonome (aucune dépendance externe) :
//   • Statistiques globales (sessions, credentials, commandes, alertes, score moyen)
//   • Tableau des sessions avec badge de score MITRE coloré
//   • Détail cliquable de chaque session : timeline des commandes
//   • Top 10 credentials (tableau)
//   • Top 10 commandes (barres de fréquence)
//
// Utilisation :
//   cargo run -- --rapport rapport.html
// ============================================================================

use anyhow::Result;
use tracing::info;

use crate::db::Database;

// chrono est utilisé via son chemin complet (chrono::DateTime, chrono::Local)

// ----------------------------------------------------------------------------
// Point d'entrée public
// ----------------------------------------------------------------------------

pub async fn generer_rapport(db: &Database, chemin: &str) -> Result<()> {
    info!("📊 Génération du rapport HTML → {}", chemin);

    let (nb_sessions, nb_creds, nb_cmds, nb_alertes, score_moy) = db.stats_globales().await?;
    let sessions = db.toutes_sessions().await?;
    let top_creds = db.top_credentials(10).await?;
    let top_cmds  = db.top_commandes(10).await?;

    // ── Détails de chaque session (commandes) ─────────────────────────────────
    let mut sessions_html = String::new();
    for s in &sessions {
        let cmds = db.commandes_session(&s.id).await?;
        sessions_html.push_str(&render_session_row(s, &cmds));
    }

    let html = render_page(
        nb_sessions, nb_creds, nb_cmds, nb_alertes, score_moy,
        &sessions_html,
        &render_top_creds(&top_creds),
        &render_top_cmds(&top_cmds),
    );

    std::fs::write(chemin, html)?;
    info!("✅ Rapport écrit : {}", chemin);
    Ok(())
}

// ----------------------------------------------------------------------------
// Rendu d'une ligne de session + ses commandes (détail dépliable)
// ----------------------------------------------------------------------------

fn render_session_row(s: &crate::db::SessionData, cmds: &[crate::db::CommandeData]) -> String {
    let score_badge = match s.score_mitre {
        None => r#"<span class="badge badge-none">—</span>"#.to_string(),
        Some(n) => {
            let cls = if n >= 7 { "badge-high" } else if n >= 4 { "badge-med" } else { "badge-low" };
            format!(r#"<span class="badge {}">{}/10</span>"#, cls, n)
        }
    };

    let ended = s.ended_at.as_deref().unwrap_or("en cours");
    let tactiques = s.tactiques.as_deref().unwrap_or("—");
    let resume = s.resume.as_deref().unwrap_or("");

    // Durée de connexion
    let duree = match (&s.started_at, &s.ended_at) {
        (start, Some(end)) => {
            match (
                chrono::DateTime::parse_from_rfc3339(start),
                chrono::DateTime::parse_from_rfc3339(end),
            ) {
                (Ok(t0), Ok(t1)) => {
                    let secs = (t1 - t0).num_seconds().abs();
                    if secs < 60 { format!("{}s", secs) }
                    else { format!("{}m{}s", secs / 60, secs % 60) }
                }
                _ => "—".to_string(),
            }
        }
        _ => "—".to_string(),
    };

    // Timeline des commandes
    let mut timeline = String::new();
    for c in cmds {
        let ia_badge = if c.via_ia != 0 {
            r#" <span class="ia-tag">IA</span>"#
        } else { "" };

        // Échapper HTML dans la réponse (évite de casser le DOM)
        let reponse_safe = html_escape(&c.reponse);
        let cmd_safe     = html_escape(&c.commande);

        timeline.push_str(&format!(
            r#"<div class="cmd-entry">
  <div class="cmd-header">
    <span class="cmd-time">{ts}</span>
    <span class="cmd-text">$ {cmd}{ia}</span>
  </div>
  <pre class="cmd-output">{out}</pre>
</div>"#,
            ts  = &c.timestamp[..19].replace('T', " "),
            cmd = cmd_safe,
            ia  = ia_badge,
            out = reponse_safe,
        ));
    }

    let detail_id = format!("d_{}", s.id.replace('-', ""));
    let nb_cmds   = cmds.len();

    format!(
        r#"<tr class="session-row" onclick="toggle('{did}')">
  <td class="mono">{ip}</td>
  <td>{user}</td>
  <td><span class="persona-tag">{persona}</span></td>
  <td class="mono">{start}</td>
  <td class="mono">{end}</td>
  <td class="mono">{dur}</td>
  <td>{score}</td>
  <td class="tact">{tact}</td>
  <td class="cmd-count">{nb}</td>
</tr>
<tr id="{did}" class="detail-row hidden">
  <td colspan="9">
    {resume_block}
    <div class="timeline">{tl}</div>
  </td>
</tr>
"#,
        did    = detail_id,
        ip     = html_escape(&s.ip),
        user   = html_escape(&s.username),
        persona= html_escape(&s.persona),
        start  = &s.started_at[..19].replace('T', " "),
        end    = if ended == "en cours" { "<span class='live'>⬤ live</span>".to_string() }
                 else { ended[..19.min(ended.len())].replace('T', " ") },
        dur    = duree,
        score  = score_badge,
        tact   = html_escape(tactiques),
        nb     = nb_cmds,
        resume_block = if resume.is_empty() { String::new() }
                       else { format!(r#"<p class="mitre-resume">🤖 {}</p>"#, html_escape(resume)) },
        tl     = if timeline.is_empty() { "<p class='no-cmds'>Aucune commande enregistrée.</p>".to_string() }
                 else { timeline },
    )
}

// ----------------------------------------------------------------------------
// Top credentials
// ----------------------------------------------------------------------------

fn render_top_creds(creds: &[crate::db::CredentialFreq]) -> String {
    if creds.is_empty() {
        return "<p class='empty'>Aucun credential enregistré.</p>".to_string();
    }
    let mut rows = String::new();
    for (i, c) in creds.iter().enumerate() {
        rows.push_str(&format!(
            "<tr><td>#{}</td><td class='mono'>{}</td><td class='mono'>{}</td><td class='nb'>{}</td></tr>\n",
            i + 1,
            html_escape(&c.username),
            html_escape(&c.password),
            c.nb,
        ));
    }
    format!(
        r#"<table class="data-table">
<thead><tr><th>#</th><th>Login</th><th>Mot de passe</th><th>Nb</th></tr></thead>
<tbody>{}</tbody>
</table>"#,
        rows
    )
}

// ----------------------------------------------------------------------------
// Top commandes (barres de fréquence)
// ----------------------------------------------------------------------------

fn render_top_cmds(cmds: &[crate::db::CommandeFreq]) -> String {
    if cmds.is_empty() {
        return "<p class='empty'>Aucune commande enregistrée.</p>".to_string();
    }
    let max = cmds.iter().map(|c| c.nb).max().unwrap_or(1) as f64;
    let mut bars = String::new();
    for c in cmds {
        let pct = (c.nb as f64 / max * 100.0) as u32;
        bars.push_str(&format!(
            r#"<div class="bar-row">
  <span class="bar-label mono">{}</span>
  <div class="bar-track"><div class="bar-fill" style="width:{}%"></div></div>
  <span class="bar-nb">{}</span>
</div>"#,
            html_escape(&c.commande), pct, c.nb
        ));
    }
    bars
}

// ----------------------------------------------------------------------------
// Assemblage final de la page HTML
// ----------------------------------------------------------------------------

fn render_page(
    nb_sessions: i64,
    nb_creds:    i64,
    nb_cmds:     i64,
    nb_alertes:  i64,
    score_moy:   f64,
    sessions_html: &str,
    top_creds_html: &str,
    top_cmds_html:  &str,
) -> String {
    let now = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
    format!(
r#"<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Honeypot SSH — Rapport d'analyse</title>
<style>
/* ── Reset & base ─────────────────────────────────────── */
*, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}
:root {{
  --bg:       #0d1117;
  --surface:  #161b22;
  --border:   #30363d;
  --text:     #c9d1d9;
  --muted:    #8b949e;
  --accent:   #58a6ff;
  --green:    #3fb950;
  --yellow:   #d29922;
  --red:      #f85149;
  --purple:   #bc8cff;
  --radius:   8px;
  --font-mono: 'SFMono-Regular', Consolas, 'Liberation Mono', Menlo, monospace;
}}
body {{
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
  padding: 24px;
}}
a {{ color: var(--accent); text-decoration: none; }}

/* ── Header ──────────────────────────────────────────── */
.header {{
  display: flex;
  align-items: center;
  justify-content: space-between;
  margin-bottom: 32px;
  padding-bottom: 16px;
  border-bottom: 1px solid var(--border);
}}
.header h1 {{
  font-size: 1.4rem;
  font-weight: 700;
  color: #fff;
}}
.header h1 span {{ color: var(--accent); }}
.header .ts {{ color: var(--muted); font-size: .85rem; }}

/* ── Stats cards ─────────────────────────────────────── */
.stats-grid {{
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 16px;
  margin-bottom: 40px;
}}
.stat-card {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  padding: 20px 24px;
}}
.stat-card .label {{ font-size: .75rem; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }}
.stat-card .value {{ font-size: 2rem; font-weight: 700; margin-top: 4px; }}
.stat-card.sessions .value {{ color: var(--accent); }}
.stat-card.creds    .value {{ color: var(--yellow); }}
.stat-card.cmds     .value {{ color: var(--green); }}
.stat-card.alertes  .value {{ color: var(--red); }}
.stat-card.score    .value {{ color: var(--purple); }}

/* ── Section ─────────────────────────────────────────── */
.section {{ margin-bottom: 48px; }}
.section h2 {{
  font-size: 1rem;
  font-weight: 600;
  color: #fff;
  margin-bottom: 16px;
  padding-bottom: 8px;
  border-bottom: 1px solid var(--border);
}}

/* ── Sessions table ──────────────────────────────────── */
.table-wrap {{ overflow-x: auto; }}
table.sessions-table {{
  width: 100%;
  border-collapse: collapse;
  font-size: .875rem;
}}
table.sessions-table th {{
  text-align: left;
  padding: 10px 12px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  font-weight: 600;
  font-size: .75rem;
  text-transform: uppercase;
  letter-spacing: .04em;
  white-space: nowrap;
}}
table.sessions-table td {{
  padding: 10px 12px;
  border-bottom: 1px solid var(--border);
  vertical-align: top;
}}
tr.session-row {{ cursor: pointer; transition: background .15s; }}
tr.session-row:hover {{ background: var(--surface); }}
tr.detail-row td {{ background: #0a0f14; padding: 0; }}
tr.detail-row.hidden {{ display: none; }}
.detail-row > td {{ padding: 16px 20px !important; }}

/* ── Badges ──────────────────────────────────────────── */
.badge {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 12px;
  font-size: .75rem;
  font-weight: 700;
}}
.badge-high  {{ background: rgba(248,81,73,.25); color: var(--red); border: 1px solid var(--red); }}
.badge-med   {{ background: rgba(210,153,34,.2);  color: var(--yellow); border: 1px solid var(--yellow); }}
.badge-low   {{ background: rgba(63,185,80,.2);   color: var(--green);  border: 1px solid var(--green); }}
.badge-none  {{ background: var(--surface); color: var(--muted); border: 1px solid var(--border); }}
.persona-tag {{
  display: inline-block;
  padding: 2px 8px;
  border-radius: 6px;
  font-size: .75rem;
  background: rgba(88,166,255,.15);
  color: var(--accent);
  border: 1px solid rgba(88,166,255,.3);
}}
.ia-tag {{
  display: inline-block;
  padding: 1px 6px;
  border-radius: 4px;
  font-size: .7rem;
  background: rgba(188,140,255,.2);
  color: var(--purple);
  border: 1px solid rgba(188,140,255,.3);
  margin-left: 6px;
  vertical-align: middle;
}}
.live {{ color: var(--green); font-size: .8rem; }}

/* ── Misc table cells ────────────────────────────────── */
.mono  {{ font-family: var(--font-mono); font-size: .8rem; }}
.tact  {{ font-size: .78rem; color: var(--muted); max-width: 220px; }}
.cmd-count {{ color: var(--muted); font-size: .8rem; text-align: center; }}

/* ── Command timeline ────────────────────────────────── */
.timeline {{ display: flex; flex-direction: column; gap: 12px; }}
.cmd-entry {{
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: var(--radius);
  overflow: hidden;
}}
.cmd-header {{
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 8px 12px;
  background: rgba(255,255,255,.03);
  border-bottom: 1px solid var(--border);
}}
.cmd-time {{ color: var(--muted); font-size: .75rem; font-family: var(--font-mono); white-space: nowrap; }}
.cmd-text {{ font-family: var(--font-mono); font-size: .85rem; color: var(--green); word-break: break-all; }}
.cmd-output {{
  padding: 10px 14px;
  font-family: var(--font-mono);
  font-size: .8rem;
  color: var(--text);
  white-space: pre-wrap;
  word-break: break-word;
  max-height: 260px;
  overflow-y: auto;
}}
.mitre-resume {{
  font-size: .85rem;
  color: var(--muted);
  background: rgba(88,166,255,.07);
  border: 1px solid rgba(88,166,255,.2);
  border-radius: var(--radius);
  padding: 10px 14px;
  margin-bottom: 14px;
}}
.no-cmds {{ color: var(--muted); font-size: .85rem; }}

/* ── Data table (creds) ──────────────────────────────── */
table.data-table {{
  width: 100%;
  max-width: 700px;
  border-collapse: collapse;
  font-size: .875rem;
}}
table.data-table th {{
  text-align: left;
  padding: 8px 12px;
  background: var(--surface);
  border-bottom: 1px solid var(--border);
  color: var(--muted);
  font-size: .75rem;
  text-transform: uppercase;
  letter-spacing: .04em;
}}
table.data-table td {{
  padding: 8px 12px;
  border-bottom: 1px solid var(--border);
}}
td.nb {{ text-align: right; font-weight: 700; color: var(--yellow); font-family: var(--font-mono); }}

/* ── Bar chart (top commandes) ───────────────────────── */
.bar-row {{
  display: flex;
  align-items: center;
  gap: 12px;
  margin-bottom: 10px;
}}
.bar-label {{
  min-width: 220px;
  max-width: 220px;
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
  font-size: .82rem;
  color: var(--text);
}}
.bar-track {{
  flex: 1;
  background: var(--surface);
  border-radius: 4px;
  height: 18px;
  overflow: hidden;
  border: 1px solid var(--border);
}}
.bar-fill {{
  height: 100%;
  background: var(--accent);
  border-radius: 4px;
  transition: width .4s;
}}
.bar-nb {{
  min-width: 36px;
  text-align: right;
  font-weight: 700;
  font-family: var(--font-mono);
  font-size: .82rem;
  color: var(--accent);
}}
.empty {{ color: var(--muted); font-size: .875rem; }}
</style>
</head>
<body>

<!-- ── Header ──────────────────────────────────────────────────────── -->
<div class="header">
  <h1>🛡️ Honeypot SSH — <span>Rapport d'analyse</span></h1>
  <span class="ts">Généré le {now}</span>
</div>

<!-- ── Stats globales ──────────────────────────────────────────────── -->
<div class="stats-grid">
  <div class="stat-card sessions">
    <div class="label">Sessions</div>
    <div class="value">{nb_sessions}</div>
  </div>
  <div class="stat-card creds">
    <div class="label">Tentatives auth</div>
    <div class="value">{nb_creds}</div>
  </div>
  <div class="stat-card cmds">
    <div class="label">Commandes</div>
    <div class="value">{nb_cmds}</div>
  </div>
  <div class="stat-card alertes">
    <div class="label">Alertes MITRE</div>
    <div class="value">{nb_alertes}</div>
  </div>
  <div class="stat-card score">
    <div class="label">Score moyen</div>
    <div class="value">{score_moy:.1}</div>
  </div>
</div>

<!-- ── Sessions ────────────────────────────────────────────────────── -->
<div class="section">
  <h2>Sessions SSH <span style="color:var(--muted);font-weight:400">(cliquer pour déplier)</span></h2>
  <div class="table-wrap">
    <table class="sessions-table">
      <thead>
        <tr>
          <th>IP</th>
          <th>Utilisateur</th>
          <th>Persona</th>
          <th>Début</th>
          <th>Fin</th>
          <th>Durée</th>
          <th>Score MITRE</th>
          <th>Tactiques</th>
          <th>Cmds</th>
        </tr>
      </thead>
      <tbody>
        {sessions_html}
      </tbody>
    </table>
  </div>
</div>

<!-- ── Top credentials ─────────────────────────────────────────────── -->
<div class="section">
  <h2>Top 10 credentials tentés</h2>
  {top_creds_html}
</div>

<!-- ── Top commandes ───────────────────────────────────────────────── -->
<div class="section">
  <h2>Top 10 commandes</h2>
  {top_cmds_html}
</div>

<script>
function toggle(id) {{
  const row = document.getElementById(id);
  if (row) row.classList.toggle('hidden');
}}
</script>
</body>
</html>
"#,
        now           = now,
        nb_sessions   = nb_sessions,
        nb_creds      = nb_creds,
        nb_cmds       = nb_cmds,
        nb_alertes    = nb_alertes,
        score_moy     = score_moy,
        sessions_html = sessions_html,
        top_creds_html = top_creds_html,
        top_cmds_html  = top_cmds_html,
    )
}

// ----------------------------------------------------------------------------
// Utilitaire : échappe les caractères HTML spéciaux
// ----------------------------------------------------------------------------

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
     .replace('<', "&lt;")
     .replace('>', "&gt;")
     .replace('"', "&quot;")
}
