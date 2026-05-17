// ============================================================================
// commands.rs — Dispatcher statique de commandes shell
// ============================================================================
//
// Principe : on reçoit une ligne brute ("ls -la /etc"), on la découpe en
// commande + arguments, puis un grand `match` route vers le bon handler.
//
// Chaque handler retourne un String (la sortie à envoyer à l'attaquant).
// La session (ShellSession) est passée en `&mut` pour pouvoir modifier
// le répertoire courant, l'historique, le mode (vim…).
// ============================================================================

use chrono::{Local, Timelike};
use crate::shell::{ShellSession, ShellMode};
use crate::vfs::VfsEntry;

// ── Point d'entrée ──────────────────────────────────────────────────────────

/// Exécute une commande en mode Normal.
///
/// Retourne :
///   Some(sortie) — commande reconnue et traitée (sortie peut être vide)
///   None         — commande inconnue → le caller devra appeler le fallback IA
pub fn executer(session: &mut ShellSession, ligne: &str) -> Option<String> {
    if ligne.is_empty() { return Some(String::new()); }

    // Découpage : premier mot = commande, reste = arguments
    let mut mots: Vec<&str> = ligne.split_whitespace().collect();
    let cmd = mots.remove(0);
    let args = mots;

    // Ajout à l'historique (avant exécution, comme bash)
    session.historique.push(ligne.to_string());

    Some(match cmd {
        // ── Navigation ──────────────────────────────────────────────────────
        "ls"                         => cmd_ls(session, &args),
        "ll"                         => cmd_ls(session, &{let mut a = vec!["-la"]; a.extend(&args); a}),
        "la"                         => cmd_ls(session, &{let mut a = vec!["-a"]; a.extend(&args); a}),
        "cd"                         => cmd_cd(session, &args),
        "pwd"                        => cmd_pwd(session),
        "find"                       => cmd_find(session, &args),

        // ── Lecture de fichiers ──────────────────────────────────────────────
        "cat"                        => cmd_cat(session, &args),
        "head"                       => cmd_head(session, &args),
        "tail"                       => cmd_tail(session, &args),
        "less" | "more"              => cmd_less(session, &args),
        "vim" | "vi" | "nano"        => cmd_vim(session, &args),

        // ── Système ─────────────────────────────────────────────────────────
        "whoami"                     => cmd_whoami(session),
        "id"                         => cmd_id(session),
        "uname"                      => cmd_uname(session, &args),
        "hostname"                   => cmd_hostname(session),
        "uptime"                     => cmd_uptime(session),
        "date"                       => cmd_date(),
        "ps"                         => cmd_ps(session, &args),
        "df"                         => cmd_df(session, &args),
        "free"                       => cmd_free(session, &args),
        "env" | "printenv"           => cmd_env(session),
        "history"                    => cmd_history(session),
        "echo"                       => cmd_echo(&args),
        "clear"                      => "\x1b[2J\x1b[H".to_string(),
        "which"                      => cmd_which(&args),
        "w" | "who"                  => cmd_who(session),

        // ── Réseau ──────────────────────────────────────────────────────────
        "wget"                       => cmd_wget(&args),
        "curl"                       => cmd_curl(&args),
        "netstat"                    => cmd_netstat(session, &args),
        "ss"                         => cmd_ss(session, &args),
        "ifconfig"                   => cmd_ifconfig(session),
        "ip"                         => cmd_ip(session, &args),
        "ping"                       => cmd_ping(&args),

        // ── Opérations fichiers (silencieux, on ne modifie rien réellement) ──
        "touch" | "mkdir" | "rm" | "cp" | "mv" | "chmod" | "chown" => String::new(),

        // ── Auth ─────────────────────────────────────────────────────────────
        "sudo"                       => cmd_sudo(session, &args),
        "su"                         => cmd_su(session, &args),

        // ── Aide ─────────────────────────────────────────────────────────────
        "man"                        => cmd_man(&args),
        "help"                       => "GNU bash, version 5.1.16\nType 'man bash' for more info.\r\n".to_string(),

        // ── Exit ─────────────────────────────────────────────────────────────
        "exit" | "logout"            => { session.active = false; "logout\r\n".to_string() }

        // ── Commande inconnue → fallback IA ──────────────────────────────────
        // On retourne None pour signaler au caller qu'il faut appeler l'IA.
        _ => return None,
    })
}

/// Gère l'input quand on est dans le "mode vim" (lecture d'un fichier).
pub fn vim_commande(session: &mut ShellSession, input: &str) -> String {
    let cmd = input.trim();

    match cmd {
        ":q" | ":q!" | ":wq" | ":wq!" | "ZZ" | "q" | "Q" => {
            // Sortie du mode vim → retour au shell normal
            session.mode = ShellMode::Normal;
            String::new() // le prompt normal sera ré-affiché par le caller
        }
        "" => String::new(),
        autre => {
            format!("E492: Not an editor command: {}\r\n", autre)
        }
    }
}

// ============================================================================
// ── NAVIGATION ──────────────────────────────────────────────────────────────
// ============================================================================

fn cmd_ls(session: &ShellSession, args: &[&str]) -> String {
    // Séparation des flags et du chemin cible
    let long   = args.iter().any(|a| a.starts_with('-') && a.contains('l'));
    let hidden = args.iter().any(|a| a.starts_with('-') && a.contains('a'));
    let cible  = args.iter().find(|a| !a.starts_with('-')).copied()
                    .unwrap_or(".");

    let chemin = session.vfs.resoudre(&session.current_dir, cible);

    match session.vfs.get(&chemin) {
        None => format!("ls: cannot access '{}': No such file or directory\r\n", cible),

        Some(VfsEntry::Fichier(_)) => {
            // ls sur un fichier : affiche juste le nom
            if long { format!("-rw-r--r-- 1 {} {} 1234 May 14 09:23 {}\r\n",
                              session.username, session.username, cible) }
            else    { format!("{}\r\n", cible) }
        }

        Some(VfsEntry::Repertoire) => {
            let mut entrees = session.vfs.lister(&chemin);

            // Sans -a : on cache les fichiers cachés (commençant par ".")
            if !hidden {
                entrees.retain(|(nom, _)| !nom.starts_with('.'));
            }

            if long {
                // Format `ls -la` réaliste
                let total = entrees.len() * 4 + 8;
                let mut sortie = format!("total {}\r\n", total);

                // Entrées "." et ".." toujours présentes avec -a
                if hidden {
                    let parent = if chemin == "/" { "/".to_string() }
                                 else { format!("{}/..", chemin) };
                    let _ = parent; // évite warning
                    sortie.push_str(&format!(
                        "drwxr-xr-x  2 {u} {u} 4096 May 14 09:23 .\r\n\
                         drwxr-xr-x  3 root root 4096 Jan 15 14:32 ..\r\n",
                        u = session.username
                    ));
                }

                for (nom, entree) in &entrees {
                    let (perms, typ) = match entree {
                        VfsEntry::Repertoire => ("drwxr-xr-x", "d"),
                        VfsEntry::Fichier(c) => {
                            if nom.starts_with('.') { ("-rw-------", "-") }
                            else if nom.ends_with(".sh") { ("-rwxr-xr-x", "-") }
                            else { ("-rw-r--r--", "-") }
                        }
                    };
                    let taille = match entree {
                        VfsEntry::Fichier(c) => c.len(),
                        VfsEntry::Repertoire => 4096,
                    };
                    let _ = typ;
                    sortie.push_str(&format!(
                        "{perms}  1 {u} {u} {t:>6} May 14 09:23 {nom}\r\n",
                        perms = perms,
                        u = session.username,
                        t = taille,
                        nom = nom,
                    ));
                }
                sortie
            } else {
                // Format compact : noms séparés par des espaces
                if entrees.is_empty() {
                    return String::new();
                }
                let noms: Vec<String> = entrees.iter()
                    .map(|(nom, e)| match e {
                        VfsEntry::Repertoire => format!("\x1b[1;34m{}\x1b[0m", nom), // bleu = dossier
                        VfsEntry::Fichier(_) if nom.ends_with(".sh") => format!("\x1b[1;32m{}\x1b[0m", nom), // vert = exécutable
                        _ => nom.clone(),
                    })
                    .collect();
                format!("{}\r\n", noms.join("  "))
            }
        }
    }
}

fn cmd_cd(session: &mut ShellSession, args: &[&str]) -> String {
    let cible = match args.first() {
        None | Some(&"~") => session.persona.shell.home.clone(), // cd sans arg → home
        Some(&"-")        => session.current_dir.clone(),        // cd - → rester
        Some(c)           => session.vfs.resoudre(&session.current_dir, c),
    };

    match session.vfs.get(&cible) {
        Some(VfsEntry::Repertoire) => {
            session.current_dir = cible;
            String::new() // cd ne produit aucune sortie en cas de succès
        }
        Some(VfsEntry::Fichier(_)) =>
            format!("bash: cd: {}: Not a directory\r\n", args.first().unwrap_or(&"?")),
        None =>
            format!("bash: cd: {}: No such file or directory\r\n", args.first().unwrap_or(&"?")),
    }
}

fn cmd_pwd(session: &ShellSession) -> String {
    format!("{}\r\n", session.current_dir)
}

fn cmd_find(session: &ShellSession, args: &[&str]) -> String {
    // find [path] [-name pattern] [-type f|d]

    // Filtrer les tokens de redirection shell (2>/dev/null, >/dev/null…)
    // et supprimer les guillemets autour des patterns (-name "*.env" → *.env)
    let args_propres: Vec<&str> = args.iter()
        .filter(|&&a| !a.contains('>') && !a.contains('<'))
        .copied()
        .collect();
    let args = args_propres.as_slice();

    let depart = args.iter().find(|a| !a.starts_with('-'))
                    .map(|a| session.vfs.resoudre(&session.current_dir, a))
                    .unwrap_or_else(|| session.current_dir.clone());

    // Strips guillemets simples et doubles autour du pattern -name
    let filtre_nom  = args.windows(2).find(|w| w[0] == "-name")
                         .map(|w| w[1].trim_matches(|c| c == '"' || c == '\''));
    let filtre_type = args.windows(2).find(|w| w[0] == "-type")
                         .map(|w| w[1].trim_matches(|c| c == '"' || c == '\''));

    let mut resultats = Vec::new();

    // Parcours du VFS réel
    trouver_recursive(session, &depart, filtre_nom, filtre_type, &mut resultats, 0);

    // Injection de fichiers "appâts" selon le persona et le pattern de recherche.
    // Ces chemins n'existent pas dans le VFS mais apparaissent dans find pour
    // donner l'illusion d'une vraie machine avec des données sensibles exposées.
    // On les injecte uniquement si on ne cherche pas exclusivement des dossiers.
    if filtre_type.unwrap_or("") != "d" {
        for chemin in appats_persona(&session.persona.id, filtre_nom, &depart) {
            if !resultats.contains(&chemin) {
                resultats.push(chemin);
            }
        }
    }

    if resultats.is_empty() {
        String::new()
    } else {
        resultats.sort();
        resultats.iter().map(|r| format!("{}\r\n", r)).collect()
    }
}

/// Retourne des chemins de fichiers "appâts" selon le persona et le filtre -name.
/// Ces fichiers donnent l'illusion d'une machine vulnérable avec des credentials exposés.
fn appats_persona(persona_id: &str, filtre_nom: Option<&str>, depart: &str) -> Vec<String> {
    let candidats: &[&str] = match persona_id {
        "web-server" => &[
            "/root/.ssh/id_rsa",
            "/root/.ssh/authorized_keys",
            "/home/ubuntu/.ssh/id_rsa",
            "/etc/ssl/private/server.key",
            "/etc/nginx/ssl/prod.key",
            "/etc/nginx/ssl/prod.crt",
            "/var/www/html/.env",
            "/var/www/html/wp-config.php",
            "/var/www/html/config/database.php",
            "/var/www/html/backup/db_export_2024.sql.gz",
            "/tmp/deploy_rsa",
        ],
        "database" => &[
            "/root/.ssh/id_rsa",
            "/root/.ssh/authorized_keys",
            "/home/postgres/.pgpass",
            "/var/lib/postgresql/.pgpass",
            "/etc/postgresql/15/main/pg_hba.conf",
            "/var/backups/postgres_full_20240315.sql",
            "/var/backups/prod_dump_latest.sql",
            "/opt/scripts/backup_db.sh",
            "/home/admin/.pgpass",
            "/tmp/restore_prod.sql",
        ],
        _ => &[
            // dev-machine
            "/home/developer/.ssh/id_rsa",
            "/home/developer/.ssh/authorized_keys",
            "/root/.ssh/id_rsa",
            "/home/developer/.env",
            "/opt/app/.env",
            "/opt/app/config/secrets.yml",
            "/home/developer/.docker/config.json",
            "/opt/scripts/deploy.sh",
            "/home/developer/projects/api/.env",
            "/etc/ssl/private/dev-server.key",
        ],
    };

    let prefixe = depart.trim_end_matches('/');

    candidats
        .iter()
        .filter(|&&chemin| {
            // Le fichier doit être sous le répertoire de départ
            (prefixe == "" || prefixe == "/" || chemin.starts_with(&format!("{}/", prefixe)) || chemin.starts_with(prefixe))
            // Et son nom doit correspondre au filtre -name si présent
            && match filtre_nom {
                None => true,
                Some(pattern) => {
                    let nom = chemin.rsplit('/').next().unwrap_or(chemin);
                    glob_simple(pattern, nom)
                }
            }
        })
        .map(|&s| s.to_string())
        .collect()
}

fn trouver_recursive(
    session: &ShellSession,
    chemin: &str,
    filtre_nom: Option<&str>,
    filtre_type: Option<&str>,
    resultats: &mut Vec<String>,
    profondeur: usize,
) {
    if profondeur > 8 { return; } // évite les boucles infinies

    let entrees = session.vfs.lister(chemin);
    for (nom, entree) in entrees {
        let chemin_complet = if chemin == "/" {
            format!("/{}", nom)
        } else {
            format!("{}/{}", chemin, nom)
        };

        // Filtre par type
        let correspond_type = match (filtre_type, entree) {
            (Some("f"), VfsEntry::Fichier(_)) => true,
            (Some("d"), VfsEntry::Repertoire)  => true,
            (None, _)                           => true,
            _                                   => false,
        };

        // Filtre par nom (glob simple : juste le wildcard *)
        let correspond_nom = match filtre_nom {
            None => true,
            Some(pattern) => glob_simple(pattern, &nom),
        };

        if correspond_type && correspond_nom {
            resultats.push(chemin_complet.clone());
        }

        // Récursion dans les sous-dossiers
        if matches!(entree, VfsEntry::Repertoire) {
            trouver_recursive(session, &chemin_complet, filtre_nom, filtre_type, resultats, profondeur + 1);
        }
    }
}

/// Glob ultra-simplifié : supporte uniquement `*` (n'importe quoi)
fn glob_simple(pattern: &str, nom: &str) -> bool {
    if pattern == "*" { return true; }
    if let Some(suffixe) = pattern.strip_prefix('*') {
        return nom.ends_with(suffixe);
    }
    if let Some(prefixe) = pattern.strip_suffix('*') {
        return nom.starts_with(prefixe);
    }
    pattern == nom
}

// ============================================================================
// ── LECTURE DE FICHIERS ──────────────────────────────────────────────────────
// ============================================================================

fn lire_fichier<'a>(session: &'a ShellSession, arg: &str) -> Result<&'a str, String> {
    let chemin = session.vfs.resoudre(&session.current_dir, arg);
    match session.vfs.get(&chemin) {
        Some(VfsEntry::Fichier(c)) => Ok(c),
        Some(VfsEntry::Repertoire) => Err(format!("{}: Is a directory\r\n", arg)),
        None => Err(format!("{}: No such file or directory\r\n", arg)),
    }
}

fn cmd_cat(session: &ShellSession, args: &[&str]) -> String {
    if args.is_empty() { return String::new(); }

    let mut sortie = String::new();
    for arg in args {
        match lire_fichier(session, arg) {
            Ok(contenu) => sortie.push_str(&unix_vers_crlf(contenu)),
            Err(e)      => sortie.push_str(&format!("cat: {}", e)),
        }
    }
    sortie
}

fn cmd_head(session: &ShellSession, args: &[&str]) -> String {
    let n = args.windows(2).find(|w| w[0] == "-n")
               .and_then(|w| w[1].parse::<usize>().ok())
               .unwrap_or(10);
    let fichier = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");

    match lire_fichier(session, fichier) {
        Ok(c) => {
            let lignes: Vec<&str> = c.lines().take(n).collect();
            unix_vers_crlf(&lignes.join("\n"))
        }
        Err(e) => format!("head: {}", e),
    }
}

fn cmd_tail(session: &ShellSession, args: &[&str]) -> String {
    let n = args.windows(2).find(|w| w[0] == "-n")
               .and_then(|w| w[1].parse::<usize>().ok())
               .unwrap_or(10);
    let fichier = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");

    match lire_fichier(session, fichier) {
        Ok(c) => {
            let toutes: Vec<&str> = c.lines().collect();
            let debut = toutes.len().saturating_sub(n);
            unix_vers_crlf(&toutes[debut..].join("\n"))
        }
        Err(e) => format!("tail: {}", e),
    }
}

fn cmd_less(session: &ShellSession, args: &[&str]) -> String {
    let fichier = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");
    match lire_fichier(session, fichier) {
        Ok(c) => {
            let mut sortie = unix_vers_crlf(c);
            sortie.push_str(&format!("\r\n\x1b[7m(END)\x1b[0m\r\n"));
            sortie
        }
        Err(e) => format!("less: {}", e),
    }
}

fn cmd_vim(session: &mut ShellSession, args: &[&str]) -> String {
    let fichier = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");

    if fichier.is_empty() {
        // vim sans argument : ouvre un buffer vide
        session.mode = ShellMode::Vim(String::new());
        return "\r\n\
                ~\r\n~\r\n~\r\n~\r\n~\r\n~\r\n~\r\n~\r\n~\r\n~\r\n\
                \x1b[7m\"[New File]\"                                        0L, 0C\x1b[0m\r\n"
               .to_string();
    }

    let chemin = session.vfs.resoudre(&session.current_dir, fichier);

    match session.vfs.get(&chemin) {
        Some(VfsEntry::Fichier(contenu)) => {
            let nb_lignes = contenu.lines().count();
            let nb_octets = contenu.len();
            let mut sortie = unix_vers_crlf(contenu);

            // Lignes vides de vim (~)
            sortie.push_str("\r\n~\r\n~\r\n~\r\n");

            // Barre de statut vim en bas (inversion vidéo)
            sortie.push_str(&format!(
                "\x1b[7m\"{}\" {}L, {}B\x1b[0m\r\n",
                chemin, nb_lignes, nb_octets
            ));

            // On passe en mode vim
            session.mode = ShellMode::Vim(chemin);
            sortie
        }
        Some(VfsEntry::Repertoire) =>
            format!("\"{}\" is a directory\r\n", fichier),
        None => {
            // vim sur un fichier inexistant → "New File" (comportement normal de vim)
            session.mode = ShellMode::Vim(chemin.clone());
            format!("\r\n~\r\n~\r\n~\r\n\x1b[7m\"{}\" [New File]\x1b[0m\r\n", chemin)
        }
    }
}

// ============================================================================
// ── SYSTÈME ──────────────────────────────────────────────────────────────────
// ============================================================================

fn cmd_whoami(session: &ShellSession) -> String {
    format!("{}\r\n", session.username)
}

fn cmd_id(session: &ShellSession) -> String {
    // uid/gid différents selon si c'est root ou un utilisateur normal
    let (uid, gid) = if session.username == "root" { (0u32, 0u32) } else { (1000, 1000) };
    format!(
        "uid={}({}) gid={}({}) groups={}({}),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev)\r\n",
        uid, session.username, gid, session.username, gid, session.username
    )
}

fn cmd_uname(session: &ShellSession, args: &[&str]) -> String {
    let sys = &session.persona.systeme;
    if args.contains(&"-a") || args.contains(&"--all") {
        format!(
            "Linux {} {} #{} SMP PREEMPT_DYNAMIC Fri Jan 12 07:07:48 UTC 2024 {} GNU/Linux\r\n",
            sys.hostname, sys.kernel, 91, sys.arch
        )
    } else if args.contains(&"-r") {
        format!("{}\r\n", sys.kernel)
    } else if args.contains(&"-n") {
        format!("{}\r\n", sys.hostname)
    } else {
        "Linux\r\n".to_string()
    }
}

fn cmd_hostname(session: &ShellSession) -> String {
    format!("{}\r\n", session.persona.systeme.hostname)
}

fn cmd_uptime(session: &ShellSession) -> String {
    let now = Local::now();
    let ts  = now.timestamp();
    let jours = (ts % (86400 * 30) / 86400 + 1) as u64;
    let heures = (ts % 86400 / 3600) as u64;
    let minutes = (ts % 3600 / 60) as u64;
    let sys = &session.persona.systeme;
    format!(
        " {:02}:{:02}:{:02} up {} days, {:02}:{:02},  {} user,  load average: {}, {:.2}, {:.2}\r\n",
        heures, minutes, ts % 60,
        jours, heures, minutes,
        sys.utilisateurs,
        sys.charge,
        sys.charge.parse::<f32>().unwrap_or(0.5) * 0.9,
        sys.charge.parse::<f32>().unwrap_or(0.5) * 0.7,
    )
}

fn cmd_date() -> String {
    format!("{}\r\n", Local::now().format("%a %b %e %H:%M:%S %Z %Y"))
}

fn cmd_ps(session: &ShellSession, args: &[&str]) -> String {
    let aux = args.contains(&"aux") || args.contains(&"-aux")
           || args.contains(&"ax")  || args.contains(&"-ef");

    let user = &session.username;
    let sys  = &session.persona.systeme;
    let now  = Local::now();
    let heure_boot = format!("{:02}:{:02}",
        (now.hour() + 22) % 24, (now.minute() + 45) % 60);

    // Processus de base communs à tous
    let mut lignes = vec![
        format!("USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\r\n"),
        format!("root         1  0.0  0.1 168940 11244 ?        Ss   {}   0:01 /sbin/init\r\n", heure_boot),
        format!("root       234  0.0  0.0      0     0 ?        S    {}   0:00 [kworker/0:2H]\r\n", heure_boot),
        format!("root       891  0.0  0.1  15424  9876 ?        Ss   {}   0:00 /usr/sbin/sshd -D\r\n", heure_boot),
        format!("root      1203  0.0  0.0   5572  1988 ?        Ss   {}   0:00 /usr/sbin/cron -f\r\n", heure_boot),
        format!("{u}       2341  0.0  0.1  10252  7834 ?        S    {}   0:00 sshd: {u}@pts/0\r\n", heure_boot, u=user),
        format!("{u}       2342  0.0  0.1   8136  5212 pts/0    Ss   {}   0:00 -bash\r\n", heure_boot, u=user),
        format!("{u}       2891  0.0  0.0   8912  3284 pts/0    R+   {}   0:00 ps aux\r\n", heure_boot, u=user),
    ];

    // Processus spécifiques au persona
    match session.persona.id.as_str() {
        "web-server" => {
            lignes.insert(4, format!("www-data   892  0.0  0.5  55088 20412 ?        S    {}   0:00 nginx: master process\r\n", heure_boot));
            lignes.insert(5, format!("www-data   893  0.1  0.8  55088 32144 ?        S    {}   0:03 nginx: worker process\r\n", heure_boot));
            lignes.insert(6, format!("www-data   894  0.0  0.9  55088 36244 ?        S    {}   0:01 nginx: worker process\r\n", heure_boot));
            lignes.insert(7, format!("www-data  1102  0.1  1.2 342144 48234 ?        S    {}   0:05 php-fpm: master process\r\n", heure_boot));
            lignes.insert(8, format!("mysql     1203  0.4  4.2 983444 169234 ?       Ssl  {}   1:23 /usr/sbin/mysqld\r\n", heure_boot));
        }
        "database" => {
            lignes.insert(4, format!("postgres   892  0.2  5.1 312456 204812 ?       Ss   {}   2:14 /usr/lib/postgresql/15/bin/postgres\r\n", heure_boot));
            lignes.insert(5, format!("postgres   893  0.0  0.3  312456 13244 ?       Ss   {}   0:00 postgres: checkpointer\r\n", heure_boot));
            lignes.insert(6, format!("postgres   894  0.0  0.2  312456 10123 ?       Ss   {}   0:00 postgres: background writer\r\n", heure_boot));
            lignes.insert(7, format!("postgres   895  0.0  0.5  323456 21234 ?       Ss   {}   0:01 postgres: walwriter\r\n", heure_boot));
        }
        "dev-machine" => {
            lignes.insert(4, format!("{u}   1102  0.5  3.4 892344 136234 ?       Sl   {}   5:43 /usr/bin/dockerd\r\n", heure_boot, u=user));
            lignes.insert(5, format!("{u}   1340  0.1  1.2 234456 49234 ?        Sl   {}   0:45 node /home/{u}/projects/webapp/server.js\r\n", heure_boot, u=user));
        }
        _ => {}
    }

    if aux {
        lignes.concat()
    } else {
        // ps sans args : juste les process du terminal actuel
        format!("  PID TTY          TIME CMD\r\n\
                 2342 pts/0    00:00:00 bash\r\n\
                 2891 pts/0    00:00:00 ps\r\n")
    }
}

fn cmd_df(session: &ShellSession, args: &[&str]) -> String {
    let human = args.contains(&"-h") || args.contains(&"--human-readable");
    let sys = &session.persona.systeme;
    let (taille, dispo) = if human { ("50G", "19G") } else { ("51200000", "19456000") };
    format!(
        "Filesystem      Size  Used Avail Use% Mounted on\r\n\
         /dev/sda1       {t}  {u}  {d}  {pct} /\r\n\
         tmpfs           {ram}  0    {ram}   0% /dev/shm\r\n\
         /dev/sda15      105M  6.1M   99M   6% /boot/efi\r\n",
        t = taille, u = "30G", d = dispo,
        pct = sys.disque.split('%').next().unwrap_or("34"),
        ram = if human { "1.9G" } else { "2000000" },
    )
}

fn cmd_free(session: &ShellSession, args: &[&str]) -> String {
    let human = args.contains(&"-h") || args.contains(&"-m");
    let sys = &session.persona.systeme;
    let pct: f64 = sys.memoire.trim_end_matches('%').parse().unwrap_or(22.0) / 100.0;
    let total = 4096u64;
    let used  = (total as f64 * pct) as u64;
    let free  = total - used;

    if human {
        format!(
            "               total        used        free      shared  buff/cache   available\r\n\
             Mem:           {t}Mi       {u}Mi       {f}Mi        12Mi      {b}Mi      {a}Mi\r\n\
             Swap:          2048Mi          0Mi       2048Mi\r\n",
            t = total, u = used, f = free / 2,
            b = free / 3, a = free / 2,
        )
    } else {
        format!(
            "               total        used        free      shared  buff/cache   available\r\n\
             Mem:         {t}      {u}      {f}       12288     {b}     {a}\r\n\
             Swap:        2097152          0    2097152\r\n",
            t = total*1024, u = used*1024, f = (free/2)*1024,
            b = (free/3)*1024, a = (free/2)*1024,
        )
    }
}

fn cmd_env(session: &ShellSession) -> String {
    let home = &session.persona.shell.home;
    format!(
        "SHELL=/bin/bash\r\n\
         HOME={home}\r\n\
         USER={user}\r\n\
         LOGNAME={user}\r\n\
         PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\r\n\
         LANG=en_US.UTF-8\r\n\
         TERM=xterm-256color\r\n\
         HISTSIZE=1000\r\n\
         HISTFILE={home}/.bash_history\r\n\
         PWD={pwd}\r\n",
        home = home, user = session.username, pwd = session.current_dir,
    )
}

fn cmd_history(session: &ShellSession) -> String {
    // On affiche l'historique bash du VFS + les commandes de la session en cours
    let hist_vfs = {
        let chemin = format!("{}/.bash_history", session.persona.shell.home);
        match session.vfs.get(&chemin) {
            Some(VfsEntry::Fichier(c)) => c.lines()
                .map(|l| l.to_string())
                .collect::<Vec<_>>(),
            _ => Vec::new(),
        }
    };

    let mut toutes: Vec<String> = hist_vfs;
    toutes.extend(session.historique.clone());

    toutes.iter().enumerate()
        .map(|(i, cmd)| format!("  {:>4}  {}\r\n", i + 1, cmd))
        .collect()
}

fn cmd_echo(args: &[&str]) -> String {
    let texte = args.join(" ");
    // Interprétation basique de \n et \t
    let texte = texte.replace("\\n", "\r\n").replace("\\t", "\t");
    format!("{}\r\n", texte)
}

fn cmd_which(args: &[&str]) -> String {
    let commandes_connues = [
        "ls", "cat", "pwd", "cd", "echo", "grep", "find", "curl", "wget",
        "python3", "python", "node", "npm", "git", "docker", "vim", "nano",
        "ssh", "scp", "rsync", "tar", "gzip", "sudo", "su", "bash", "sh",
        "ps", "top", "df", "free", "netstat", "ss", "ifconfig", "ip",
        "ping", "traceroute", "nmap", "nc", "netcat", "chmod", "chown",
    ];

    if let Some(cmd) = args.first() {
        if commandes_connues.contains(cmd) {
            if ["python3", "node", "npm", "git", "docker"].contains(cmd) {
                format!("/usr/local/bin/{}\r\n", cmd)
            } else {
                format!("/usr/bin/{}\r\n", cmd)
            }
        } else {
            format!("{} not found\r\n", cmd)
        }
    } else {
        String::new()
    }
}

fn cmd_who(session: &ShellSession) -> String {
    let now = Local::now();
    format!(
        "{u}   pts/0    {} ({})\r\n",
        now.format("%Y-%m-%d %H:%M"),
        session.persona.systeme.ip,
        u = session.username,
    )
}

// ============================================================================
// ── RÉSEAU ───────────────────────────────────────────────────────────────────
// ============================================================================

fn cmd_wget(args: &[&str]) -> String {
    let url = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");
    if url.is_empty() {
        return "wget: missing URL\r\nUsage: wget [OPTION]... [URL]...\r\n".to_string();
    }
    format!(
        "--{date}--  {url}\n\
         Resolving {host}... connexion refusée\n\
         wget: unable to resolve host address '{host}'\r\n",
        date = Local::now().format("%Y-%m-%d %H:%M:%S"),
        url  = url,
        host = url.split('/').nth(2).unwrap_or(url),
    )
}

fn cmd_curl(args: &[&str]) -> String {
    let url = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("");
    if url.is_empty() {
        return "curl: try 'curl --help' for more information\r\n".to_string();
    }
    format!(
        "curl: (6) Could not resolve host: {}\r\n",
        url.split('/').nth(2).unwrap_or(url)
    )
}

fn cmd_netstat(session: &ShellSession, args: &[&str]) -> String {
    let sys = &session.persona.systeme;
    let mut lignes = format!(
        "Active Internet connections (servers and established)\r\n\
         Proto Recv-Q Send-Q Local Address           Foreign Address         State\r\n\
         tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\r\n\
         tcp        0    236 {}:22                47.29.201.179:52387     ESTABLISHED\r\n",
        sys.ip
    );

    match session.persona.id.as_str() {
        "web-server" => {
            lignes.push_str(
                "tcp        0      0 0.0.0.0:80              0.0.0.0:*               LISTEN\r\n\
                 tcp        0      0 0.0.0.0:443             0.0.0.0:*               LISTEN\r\n\
                 tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN\r\n"
            );
        }
        "database" => {
            lignes.push_str("tcp        0      0 127.0.0.1:5432          0.0.0.0:*               LISTEN\r\n");
        }
        "dev-machine" => {
            lignes.push_str(
                "tcp        0      0 0.0.0.0:8080            0.0.0.0:*               LISTEN\r\n\
                 tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\r\n"
            );
        }
        _ => {}
    }
    lignes
}

fn cmd_ss(session: &ShellSession, args: &[&str]) -> String {
    // ss utilise un format légèrement différent de netstat
    let mut sortie = format!(
        "Netid  State   Recv-Q  Send-Q  Local Address:Port  Peer Address:Port\r\n\
         tcp    LISTEN  0       128     0.0.0.0:22           0.0.0.0:*\r\n"
    );
    match session.persona.id.as_str() {
        "web-server" => sortie.push_str(
            "tcp    LISTEN  0       511     0.0.0.0:80           0.0.0.0:*\r\n\
             tcp    LISTEN  0       511     0.0.0.0:443          0.0.0.0:*\r\n\
             tcp    LISTEN  0       128     127.0.0.1:3306       0.0.0.0:*\r\n"
        ),
        "database" => sortie.push_str(
            "tcp    LISTEN  0       128     127.0.0.1:5432       0.0.0.0:*\r\n"
        ),
        "dev-machine" => sortie.push_str(
            "tcp    LISTEN  0       128     0.0.0.0:8080         0.0.0.0:*\r\n\
             tcp    LISTEN  0       511     127.0.0.1:6379       0.0.0.0:*\r\n"
        ),
        _ => {}
    }
    sortie
}

fn cmd_ifconfig(session: &ShellSession) -> String {
    let sys = &session.persona.systeme;
    format!(
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\r\n\
         \t    inet {ip}  netmask 255.255.255.0  broadcast {bcast}\r\n\
         \t    inet6 fe80::216:3eff:fe12:ab34  prefixlen 64  scopeid 0x20<link>\r\n\
         \t    ether 00:16:3e:12:ab:34  txqueuelen 1000  (Ethernet)\r\n\
         \t    RX packets 234521  bytes 312445123 (312.4 MB)\r\n\
         \t    TX packets 198234  bytes 23445312 (23.4 MB)\r\n\n\
         lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\r\n\
         \t    inet 127.0.0.1  netmask 255.0.0.0\r\n\
         \t    loop  txqueuelen 1000  (Local Loopback)\r\n",
        ip    = sys.ip,
        bcast = sys.ip.rsplitn(2, '.').nth(1)
                    .map(|p| format!("{}.255", p))
                    .unwrap_or_else(|| "10.0.0.255".to_string()),
    )
}

fn cmd_ip(session: &ShellSession, args: &[&str]) -> String {
    let sous_cmd = args.first().copied().unwrap_or("addr");
    match sous_cmd {
        "addr" | "a" | "address" => cmd_ifconfig(session),
        "route" | "r" => {
            format!(
                "default via 10.0.0.1 dev eth0 proto dhcp src {} metric 100\r\n\
                 10.0.0.0/24 dev eth0 proto kernel scope link src {}\r\n",
                session.persona.systeme.ip, session.persona.systeme.ip
            )
        }
        _ => format!("Object \"{}\" is unknown, try \"ip help\".\r\n", sous_cmd),
    }
}

fn cmd_ping(args: &[&str]) -> String {
    let host = args.iter().find(|a| !a.starts_with('-')).copied().unwrap_or("localhost");
    format!(
        "PING {h} ({h}): 56 data bytes\r\n\
         ping: connect: Network is unreachable\r\n",
        h = host
    )
}

// ============================================================================
// ── AUTH ─────────────────────────────────────────────────────────────────────
// ============================================================================

fn cmd_sudo(session: &mut ShellSession, args: &[&str]) -> String {
    // Déjà root → pas besoin de mot de passe
    if session.username == "root" {
        let commande = args.join(" ");
        if commande.is_empty() {
            return "sudo: no command specified\r\n".to_string();
        }
        return if let Some(sortie) = executer(session, &commande) {
            sortie
        } else {
            String::new()
        };
    }

    // Construit la sous-commande (sans les flags sudo)
    let commande = if args.contains(&"-s") || args.contains(&"-i") {
        "bash".to_string()
    } else {
        args.iter()
            .filter(|&&a| !a.starts_with('-'))
            .copied()
            .collect::<Vec<_>>()
            .join(" ")
    };

    if commande.is_empty() && !args.contains(&"-s") && !args.contains(&"-i") {
        return format!(
            "usage: sudo command\r\n\
             Try 'sudo -h' for help.\r\n"
        );
    }

    // Bascule en mode SudoWait — le prompt s'affiche, l'input suivant est caché
    session.mode = ShellMode::SudoWait { commande };

    // Pas de \r\n : le curseur reste sur la même ligne pour la saisie
    format!("[sudo] password for {}: ", session.username)
}

fn cmd_su(session: &mut ShellSession, args: &[&str]) -> String {
    let cible = args.iter()
        .find(|&&a| !a.starts_with('-'))
        .copied()
        .unwrap_or("root");

    // On stocke la cible dans la commande pour que traiter_octet_sudo
    // sache vers quel utilisateur switcher
    session.mode = ShellMode::SudoWait {
        commande: format!("su {}", cible),
    };

    "Password: ".to_string()
}

// ============================================================================
// ── AIDE ─────────────────────────────────────────────────────────────────────
// ============================================================================

fn cmd_man(args: &[&str]) -> String {
    let cmd = args.first().copied().unwrap_or("");
    if cmd.is_empty() {
        return "What manual page do you want?\r\n".to_string();
    }
    format!(
        "No manual entry for {}\r\n\
         See 'man 7 undocumented' for help when manual pages are not available.\r\n",
        cmd
    )
}

// ============================================================================
// ── Utilitaires ──────────────────────────────────────────────────────────────
// ============================================================================

/// Convertit les sauts de ligne Unix (\n) en CRLF (\r\n) pour le terminal SSH.
fn unix_vers_crlf(s: &str) -> String {
    // On s'assure de ne pas doubler les \r\n existants
    s.lines().map(|l| format!("{}\r\n", l)).collect()
}
