# OWS — Checklist sécurité avant déploiement

Ce repo contient des valeurs **par défaut héritées d'OWS upstream**, conçues pour le dev local. **Aucune** de ces valeurs ne doit subsister en environnement déployé (cloud, VPS, K8s, machine à IP publique).

## 1. Secrets à rotater (avant tout déploiement)

| Service | Fichier source | Variable / clé | Valeur par défaut à NE PAS conserver |
|---|---|---|---|
| PostgreSQL | `src/.env` | `DATABASE_PASSWORD` | `yourStrong(!)Password` |
| SQL Server (alt) | `src/OWS*/appsettings.json` → `OWSStorageConfig.OWSDBConnectionString` | `Password=` | `yourStrong(!)Password` |
| RabbitMQ | `src/.env` + `appsettings.json` → `RabbitMQOptions` | `RabbitMQUserName` / `RabbitMQPassword` | `dev` / `test` |
| Elasticsearch | `src/.env` | `ELASTIC_PASSWORD`, `LOGSTASH_INTERNAL_PASSWORD`, `KIBANA_SYSTEM_PASSWORD` | `changeme` |
| OWS Instance Launcher | `src/OWSInstanceLauncher/appsettings.json` | `OWSInstanceLauncherOptions.OWSAPIKey` | `F9B16963-DC44-4E9C-9635-257FA18D4D41` |
| OWS Instance Launcher | idem | `OWSInstanceLauncherOptions.LauncherGuid` | `11111111-2222-3333-4444-555555555555` |
| OWS Management | `src/OWSManagement/appsettings.json` | `OWSManagementOptions.OWSAPIKey` | vide (à remplir avec un GUID fort) |
| EpicOnlineServices | `src/OWSPublicAPI/appsettings.json` | `ExternalLoginProviderConfig.EpicOnlineServices.ClientSecret` | vide (à remplir si EOS utilisé) |

## 2. Mécanisme d'override recommandé

Pour chaque service ASP.NET, **ne pas modifier `appsettings.json`** (il reste tracked comme template). Créer à côté :

- `appsettings.Production.json` — non versionné (gitignored ci-dessous)
- ou variables d'environnement (préféré pour Docker/K8s) :
  - `OWSStorageConfig__OWSDBConnectionString="..."`
  - `RabbitMQOptions__RabbitMQPassword="..."`
  - `OWSInstanceLauncherOptions__OWSAPIKey="..."`
  - etc. (la syntaxe `__` est le séparateur ASP.NET pour sections imbriquées)

Lancer le service avec `ASPNETCORE_ENVIRONMENT=Production` pour activer l'override `appsettings.Production.json` et désactiver `UseDeveloperExceptionPage()`.

## 3. Fichiers non versionnés (déjà gitignored)

- `src/.env` (le vrai fichier à secrets locaux)
- `src/OWSInstanceLauncher/appsettings.json` (contient des chemins machine `H:\…`)
- Tous les `appsettings.{Development,Local,Production,Staging}.json`
- Tous les `appsettings.*.secret.json`

## 4. Durcissement supplémentaire à faire avant exposition publique

- **CORS** : ~~`src/OWSPublicAPI/Startup.cs:71-73`~~ ✅ traité (commit `b86b269`) — whitelist explicite des headers (`X-CustomerGUID`, `Content-Type`, `Accept`, `Authorization`) et méthodes (`GET`, `POST`, `OPTIONS`). `AllowedCorsOrigins` toujours à restreindre aux domaines réels de prod côté `appsettings.Production.json`.
- **CustomerGUID auth** : `src/OWSShared/Middleware/StoreCustomerGUIDMiddleware.cs` — ajouter un HMAC signé partagé entre client et serveur, ou exiger un JWT au-dessus du simple header GUID. Rate-limiting basique déjà en place (`RateLimitingMiddleware`, 60 req/min/IP), à raffiner par endpoint sensible (login/register).
- **TLS** : forcer HTTPS sur tous les endpoints publics, désactiver HTTP simple. `ASPNETCORE_URLS` côté `configmap.yaml` est en `http://+:80` — terminer le TLS au niveau d'un ingress (déjà présent : `k8s/ingress.yaml`, à durcir avec `cert-manager` + redirection HTTP→HTTPS forcée).
- **K8s** : `k8s/secret.yaml` — ne pas appliquer tel quel ; passer par un Secret externe (sealed-secrets, External Secrets Operator avec Vault/Azure Key Vault) avant `kubectl apply`.
- **`ASPNETCORE_ENVIRONMENT` overrides** : les fichiers `src/docker-compose.override.windows.yml` et `.osx.yml` settent `ASPNETCORE_ENVIRONMENT=Development` (légitime en dev local — docker-compose les charge automatiquement). **Ne jamais déployer un de ces overrides sur un serveur exposé** : `UseDeveloperExceptionPage()` y exposerait des stack traces complètes. La prod K8s utilise `configmap.yaml` (Production) et le `docker-compose.yml` de base n'override pas la valeur, donc le défaut runtime ASP.NET (Production) s'applique. ✓ audité.
- **Logs serveur** : audit complet effectué — aucun leak de password / SessionGUID / connection-string dans les `Log.*` Serilog. Cependant **7 `Console.WriteLine($"... Error: {ex}")`** dans `src/OWSData/Repositories/Implementations/MSSQL/UsersRepository.cs` (CreateCharacter, Logout, RegisterUser, UpdateUser, etc.) + 1 dans `StoreCustomerGUIDMiddleware.cs:37` dumpent l'exception complète (stack trace, class names internes) en stdout, **bypassant le pipeline Serilog structuré**. Pas de credential leak (Dapper protège les valeurs paramétrées), mais à migrer vers `Log.Error(ex, "...")` pour bénéficier des filtres Serilog et du formatage JSON Elasticsearch en prod. Faible criticité, cleanup recommandé.
- **`Serilog.MinimumLevel`** : tous les `appsettings.json` utilisent `Default: "Debug"` — verbeux mais OK car écrasé en prod par `appsettings.Production.json` (à créer le jour du déploiement, voir §5 ci-dessous).

## 5. À faire le jour J du premier déploiement

1. Générer tous les nouveaux secrets (passwords forts, GUIDs frais) — utiliser `openssl rand -base64 32` ou équivalent.
2. Les injecter via variables d'env ou Secret manager — **jamais** dans un fichier versionné.
3. Vérifier `ASPNETCORE_ENVIRONMENT=Production` sur chaque service en prod.
4. Audit des logs pour s'assurer qu'aucun secret ne fuit dans Serilog (`OWSAPIKey` partiellement loggué côté client UE — voir `HybeliorWorld_5.4/Source/.../HWLoginWidget.cpp:92`).
