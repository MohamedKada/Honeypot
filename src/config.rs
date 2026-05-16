// ============================================================================
<<<<<<< HEAD
// config.rs — Configuration locale du honeypot
// ============================================================================
//
// ⚠️  POUR LE CORRECTEUR : remplacez la clé ci-dessous par votre propre
//    clé API Anthropic (https://console.anthropic.com) si vous souhaitez
//    tester le fallback IA. Sans clé valide, les commandes inconnues
//    retournent simplement "command not found".
//
// La clé peut aussi être fournie via la variable d'environnement :
//   ANTHROPIC_API_KEY=sk-ant-... cargo run -- --persona web-server
// ============================================================================

/// Clé API Anthropic — fallback IA (Claude Haiku 4.5)
/// Laissez vide ("") pour désactiver le fallback IA.
pub const ANTHROPIC_API_KEY: &str = "REMPLACER_PAR_VOTRE_CLE";
=======
// config.rs — Configuration du honeypot
// ============================================================================
//
// Les secrets (clé API Anthropic…) sont chargés depuis le fichier `.env`
// situé à la racine du projet. Ce fichier est dans .gitignore et ne doit
// jamais être commité.
//
// Pour démarrer :
//   1. Copiez `.env.example` vers `.env`
//   2. Remplissez votre clé Anthropic dans `.env`
//   3. Lancez : cargo run -- --persona web-server
//
// La clé peut aussi être passée directement :
//   ANTHROPIC_API_KEY=sk-ant-... cargo run -- --persona web-server
//   cargo run -- --api-key sk-ant-... --persona web-server
//
// Sans clé valide, le fallback IA est désactivé et les commandes inconnues
// retournent simplement "command not found".
// ============================================================================
>>>>>>> 2384e2ccef211339b2ad54cb4cd8408c9d0ca502
