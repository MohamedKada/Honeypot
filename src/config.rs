// ============================================================================
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
