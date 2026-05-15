// ============================================================================
// persona.rs — Système de personas du honeypot
// ============================================================================
//
// Un "persona" est un profil de serveur que le honeypot va imiter.
// Il définit tout ce qui rend le leurre crédible :
//   - Le nom d'hôte, l'OS, la version du kernel
//   - Les ressources système affichées (charge, mémoire, disque…)
//   - Le message de bienvenue (MOTD)
//   - L'utilisateur et le home directory par défaut
//
// Les personas sont chargées depuis des fichiers .toml dans le dossier
// `personas/`. Si aucun fichier n'est trouvé, on utilise le persona intégré.
//
// CONCEPT CLÉ — #[derive(Deserialize)] :
//   Cette annotation "magique" vient de serde. Elle génère automatiquement
//   le code pour lire du TOML/JSON et le convertir en struct Rust.
//   Sans derive, il faudrait écrire des dizaines de lignes manuellement.
// ============================================================================

use std::fs;
use std::path::Path;

use serde::Deserialize;
use tracing::{info, warn};

// ----------------------------------------------------------------------------
// Structures de données (miroir des fichiers TOML)
// ----------------------------------------------------------------------------
//
// Chaque struct correspond à une section du fichier TOML.
// Les noms de champs doivent correspondre aux clés TOML.

/// Configuration du système simulé (section [systeme] dans le TOML)
#[derive(Debug, Clone, Deserialize)]
pub struct SystemeConfig {
    /// Nom d'hôte affiché dans le prompt : "ubuntu@web-prod-01:~$"
    pub hostname: String,

    /// Version de l'OS affichée dans le MOTD : "Ubuntu 22.04.3 LTS"
    pub os_version: String,

    /// Version du kernel Linux simulé
    pub kernel: String,

    /// Architecture matérielle : "x86_64"
    pub arch: String,

    /// Adresse IP affichée dans les infos système
    pub ip: String,

    /// Charge système (load average) : "0.08"
    pub charge: String,

    /// Nombre de processus simulés
    pub processus: u32,

    /// Nombre d'utilisateurs "connectés" affiché dans le MOTD
    pub utilisateurs: u32,

    /// Utilisation du disque : "34.2% of 19.52GB"
    pub disque: String,

    /// Utilisation de la mémoire : "22%"
    pub memoire: String,

    /// Utilisation du swap : "0%"
    pub swap: String,
}

/// Configuration du shell simulé (section [shell] dans le TOML)
#[derive(Debug, Clone, Deserialize)]
pub struct ShellConfig {
    /// Nom d'utilisateur par défaut pour le prompt
    pub utilisateur: String,

    /// Répertoire home de cet utilisateur
    pub home: String,

    /// Lignes supplémentaires ajoutées au MOTD (services actifs, alertes…)
    /// Option<String> = peut être absent du fichier TOML sans erreur
    pub motd_extra: Option<String>,
}

/// Persona complet — correspond à un fichier .toml entier
#[derive(Debug, Clone, Deserialize)]
pub struct Persona {
    /// Identifiant unique utilisé dans --persona <id> : "web-server"
    pub id: String,

    /// Nom lisible affiché dans le menu interactif : "Serveur Web (Nginx)"
    pub nom: String,

    /// Description courte affichée dans le menu
    pub description: String,

    /// Configuration du système (section [systeme])
    pub systeme: SystemeConfig,

    /// Configuration du shell (section [shell])
    pub shell: ShellConfig,
}

// ----------------------------------------------------------------------------
// Chargement des personas
// ----------------------------------------------------------------------------

/// Charge tous les fichiers .toml du dossier `personas/`.
///
/// Retourne un Vec avec tous les personas valides trouvés.
/// Les fichiers invalides sont ignorés avec un warning dans les logs.
pub fn charger_personas(dossier: &str) -> Vec<Persona> {
    let chemin = Path::new(dossier);

    // Si le dossier n'existe pas, on retourne une liste vide.
    // Le caller ajoutera le persona par défaut.
    if !chemin.exists() {
        warn!("Dossier '{}' introuvable — utilisation du persona par défaut", dossier);
        return Vec::new();
    }

    let mut personas = Vec::new();

    // fs::read_dir liste le contenu d'un dossier
    let entrees = match fs::read_dir(chemin) {
        Ok(e)  => e,
        Err(e) => {
            warn!("Impossible de lire '{}' : {}", dossier, e);
            return Vec::new();
        }
    };

    for entree in entrees {
        let entree = match entree {
            Ok(e)  => e,
            Err(_) => continue, // on saute les entrées illisibles
        };

        let path = entree.path();

        // On ne traite que les fichiers .toml
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }

        // Lecture du fichier
        let contenu = match fs::read_to_string(&path) {
            Ok(c)  => c,
            Err(e) => {
                warn!("Impossible de lire {:?} : {}", path, e);
                continue;
            }
        };

        // Parsing TOML → struct Persona
        // toml::from_str retourne un Result<Persona, toml::de::Error>
        match toml::from_str::<Persona>(&contenu) {
            Ok(persona) => {
                info!("✅ Persona chargé : '{}' ({})", persona.nom, persona.id);
                personas.push(persona);
            }
            Err(e) => {
                warn!("❌ Fichier {:?} invalide : {}", path, e);
            }
        }
    }

    personas
}

/// Retourne le persona par défaut intégré dans le binaire.
///
/// Avantage : le honeypot fonctionne même sans le dossier `personas/`.
/// Ce persona simule un serveur web Ubuntu classique.
pub fn persona_defaut() -> Persona {
    // toml::from_str ne peut pas échouer sur une constante valide,
    // donc on utilise unwrap() ici en toute sécurité.
    toml::from_str(PERSONA_DEFAUT_TOML).expect("Persona défaut invalide — bug interne")
}

/// Contenu TOML du persona par défaut, embarqué dans le binaire.
/// Les guillemets triples """...""" sont des chaînes multi-lignes en TOML.
const PERSONA_DEFAUT_TOML: &str = r#"
id          = "web-server"
nom         = "Serveur Web (Nginx)"
description = "Ubuntu 22.04 avec Nginx, PHP-FPM et MySQL"

[systeme]
hostname    = "web-prod-01"
os_version  = "Ubuntu 22.04.3 LTS"
kernel      = "5.15.0-91-generic"
arch        = "x86_64"
ip          = "10.0.0.42"
charge      = "0.08"
processus   = 112
utilisateurs = 1
disque      = "34.2% of 19.52GB"
memoire     = "22%"
swap        = "0%"

[shell]
utilisateur = "ubuntu"
home        = "/home/ubuntu"
motd_extra  = """
 * Nginx 1.24.0 running on port 80/443
 * PHP-FPM 8.2 active
 * MySQL 8.0 active
"""
"#;

// ----------------------------------------------------------------------------
// Menu interactif de sélection
// ----------------------------------------------------------------------------

/// Affiche un menu dans le terminal et retourne le persona choisi.
///
/// Cette fonction est synchrone (pas async) car elle lit stdin de façon
/// bloquante — ce qui est acceptable avant le démarrage du serveur.
pub fn menu_selection(personas: &[Persona]) -> &Persona {
    println!("\n╔══════════════════════════════════════════╗");
    println!("║     🛡️  Honeypot SSH — Sélection Persona  ║");
    println!("╚══════════════════════════════════════════╝\n");

    for (i, p) in personas.iter().enumerate() {
        println!("  [{}] {}", i + 1, p.nom);
        println!("      └─ {}", p.description);
        println!();
    }

    // Boucle jusqu'à ce que l'utilisateur entre un numéro valide
    loop {
        print!("Choisissez un persona [1-{}] : ", personas.len());

        // std::io::Write::flush force l'affichage du print! sans \n
        use std::io::Write;
        std::io::stdout().flush().unwrap();

        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();

        // .trim() supprime le \n final, .parse() convertit en usize
        match input.trim().parse::<usize>() {
            Ok(n) if n >= 1 && n <= personas.len() => {
                let choix = &personas[n - 1];
                println!("\n▶  Persona sélectionné : {}\n", choix.nom);
                return choix;
            }
            _ => {
                println!("❌ Entrée invalide, réessayez.");
            }
        }
    }
}
