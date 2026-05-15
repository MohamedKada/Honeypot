// ============================================================================
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
