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
- **CustomerGUID auth** : ✅ HMAC-SHA256 implémenté dans `StoreCustomerGUIDMiddleware`. Le client UE5 (helper `OWSHmacSigning::ApplySignature` dans `OWSPlugin`) calcule `HMAC-SHA256(secret, timestamp + "\n" + METHOD + "\n" + path + "\n" + sha256(body))` et l'attache via `X-Customer-Timestamp` + `X-Customer-Signature`. Le serveur recalcule en `FixedTimeEquals` et vérifie la fenêtre anti-replay ±5 min (configurable `OWSHmac:ClockSkewSeconds`). **Le `path` du canonical inclut `PathBase + Path`** (pas juste `Path`) pour matcher ce que voit le client derrière un reverse-proxy avec sub-path (ex: nginx `location /owspublic/` proxy_pass) — sans ça toute requête 401 en prod. Le body est hashé en streaming avec **cap configurable `OWSHmac:MaxBodyBytes` (default 2 MB, plancher 1 KB)** ; au-delà, rejet 401 générique avant allocation pour bloquer les POST géants (DoS OOM). **Rollout en 2 phases pour éviter de casser le login** : (1) déployer backend `OWSHmac:Enabled=true, RequireSignature=false` (accepte signé + non-signé avec warning log throttlé à 1 par IP par minute pour ne pas saturer le disque), patcher tous les clients, vérifier que les warnings tombent à 0 ; (2) flipper `RequireSignature=true` → les requêtes non-signées renvoient 401. Le secret partagé est lu depuis `appsettings.json` clé `OWSHmac:Secret` (override prod via env var `OWSHMAC__SECRET`), et côté client depuis GConfig `[/Script/OWSPlugin.OWSPlayerControllerComponent] OWSHmacSecret=...` (à mettre dans `Config/DefaultGame_Secrets.ini` gitignored). **Si `Enabled=true` mais `Secret` vide, le middleware throw `InvalidOperationException` au démarrage** (fail-CLOSED loud — l'opérateur doit soit fournir un secret, soit explicitement `Enabled=false`). Le `X-CustomerGUID` n'est écrit dans le scope IHeaderCustomerGUID **qu'après que tous les checks passent**, sinon les requêtes rejetées attribueraient le tenant attaqué dans les logs Serilog. 14 tests xUnit (60/60 OWS total) couvrent : signature valide, signature invalide, timestamp trop vieux / futur / extrême (long.MinValue/MaxValue/-1), opt-in unsigned accepté, strict unsigned rejeté, throw on empty secret, body au-dessus du cap, PathBase canonical reverse-proxy, no GUID leak sur rejection. ~~Rate-limiting basique~~ ✅ `RateLimitingMiddleware` désormais branché à la fois sur OWSPublicAPI **et** sur OWSManagement (commit avec le wire admin), avec quotas par endpoint sensible : `/api/Users/LoginAndCreateSession` = 5 req/min, `/api/Users/RegisterUser` = 3 req/min, défaut 60 req/min (commit `277871d`).
- **Input validation backend** : ✅ `DefaultPublicAPIInputValidation` (ValidateEmail / ValidatePassword / ValidateFirstName / ValidateLastName) maintenant appelé dans `RegisterUserRequest.Handle()` avant tout DB write (commit `37ed399`). Avant ce fix, le client pouvait pousser email malformé, password 1 char, XSS dans FirstName directement en DB.
- **Password hashing** : ✅ migré de `crypt(_Password, gen_salt('md5'))` (MD5-crypt, crackable au GPU) vers `crypt(_Password, gen_salt('bf', 12))` (bcrypt cost 12, ~250ms/hash) dans `setup.sql:AddUser` (commit `051adf6`). `crypt()` auto-détecte le format côté login donc rétro-compatible avec hash legacy s'il y en a.
- **OWSManagement** : admin API protégée par `StoreCustomerGUIDMiddleware` + désormais `RateLimitingMiddleware`. **Doit rester derrière VPN/réseau privé** — Swagger UI et endpoints d'écriture (CreateUser, etc.) sont exposés au monde si bind public. Idéalement : ne pas inclure OWSManagement dans l'ingress public, ou ajouter une auth réseau supplémentaire (basic auth devant Nginx, IP allow-list, etc.).
- **TLS** : forcer HTTPS sur tous les endpoints publics, désactiver HTTP simple. `ASPNETCORE_URLS` côté `configmap.yaml` est en `http://+:80` — terminer le TLS au niveau d'un ingress (déjà présent : `k8s/ingress.yaml`, à durcir avec `cert-manager` + redirection HTTP→HTTPS forcée).
- **K8s** : `k8s/secret.yaml` — ne pas appliquer tel quel ; passer par un Secret externe (sealed-secrets, External Secrets Operator avec Vault/Azure Key Vault) avant `kubectl apply`.
- **`ASPNETCORE_ENVIRONMENT` overrides** : les fichiers `src/docker-compose.override.windows.yml` et `.osx.yml` settent `ASPNETCORE_ENVIRONMENT=Development` (légitime en dev local — docker-compose les charge automatiquement). **Ne jamais déployer un de ces overrides sur un serveur exposé** : `UseDeveloperExceptionPage()` y exposerait des stack traces complètes. La prod K8s utilise `configmap.yaml` (Production) et le `docker-compose.yml` de base n'override pas la valeur, donc le défaut runtime ASP.NET (Production) s'applique. ✓ audité.
- **Logs serveur** : audit complet effectué — aucun leak de password / SessionGUID / connection-string dans les `Log.*` Serilog. Cependant **7 `Console.WriteLine($"... Error: {ex}")`** dans `src/OWSData/Repositories/Implementations/MSSQL/UsersRepository.cs` (CreateCharacter, Logout, RegisterUser, UpdateUser, etc.) + 1 dans `StoreCustomerGUIDMiddleware.cs:37` dumpent l'exception complète (stack trace, class names internes) en stdout, **bypassant le pipeline Serilog structuré**. Pas de credential leak (Dapper protège les valeurs paramétrées), mais à migrer vers `Log.Error(ex, "...")` pour bénéficier des filtres Serilog et du formatage JSON Elasticsearch en prod. Faible criticité, cleanup recommandé.
- **`Serilog.MinimumLevel`** : tous les `appsettings.json` utilisent `Default: "Debug"` — verbeux mais OK car écrasé en prod par `appsettings.Production.json` (à créer le jour du déploiement, voir §5 ci-dessous).

## 4bis. Changelog de la session sécurité 2026-05-23

Vue chronologique de tout ce qui a été durci ce soir (côté OWS). Les commits "WIP" ne sont pas des fixes de sécurité, ils encapsulent juste le travail local préexistant que la session a dû commit séparément pour garder les commits sécu lisibles.

| Hash | Type | Surface durcie |
|---|---|---|
| `d8b81ed` | sécu | Untrack `.env` + `OWSInstanceLauncher/appsettings.json` ; SECURITY.md initial ; `.gitignore` étendu |
| `1d58ddd` | WIP | Redis singleton + JSON casing PascalCase + Serilog request logging + rate-limit wiring |
| `b86b269` | sécu | OWSPublicAPI CORS : `WithHeaders/WithMethods` explicites au lieu de `AllowAnyHeader/AllowAnyMethod` |
| `ece666a` | docs | Bilan CORS + audit `ASPNETCORE_ENVIRONMENT` (OK : prod K8s = Production, overrides dev local légitimes) |
| `277871d` | sécu | Per-endpoint rate-limit : login 5/min, register 3/min, défaut 60/min, 7 tests xUnit |
| `983aa74` | docs | Audit logs Serilog → aucun leak credential ; Console.WriteLine listés pour cleanup |
| `520d672` | WIP | UsersRepository MSSQL refactor (per-method `using var conn`, generic errors, transaction param) |
| `77c7dc2` | sécu | `Console.WriteLine` → `Serilog.Log.Error` sur UsersRepository MSSQL + middleware GUID |
| `37ed399` | sécu | `IPublicAPIInputValidation` câblé dans `RegisterUserRequest` (Email/Password/FirstName/LastName) |
| `051adf6` | sécu | **MD5-crypt → bcrypt cost 12** dans `AddUser` SP (setup.sql) |
| `7bf0044` | sécu | RateLimitingMiddleware sur OWSManagement + entrée SECURITY.md sur l'isolation réseau admin |
| `15cb4c3` | WIP | Launcher OtherCustomFlags + LiveCoding kill |
| `52566f3` | sécu | mapName regex `^[A-Za-z][A-Za-z0-9_]{0,63}$` dans le launcher → bloque CLI arg injection |
| `2710265` | sécu | `LoginAndCreateSession` : `ValidateEmail` pré-filtre + message d'erreur générique anti-enumeration |
| `5b9ba84` | sécu | RateLimitingMiddleware câblé sur les 3 services OWS restants (CharacterPersistence/GlobalData/InstanceManagement) |
| `d0f9bba` | sécu | `UpdateAllPlayerPositions` durci (TryParse + IsFinite + bornes 10 000 km) ; `UpdateCharacterStats` ne renvoie plus `ex.Message` |
| `e21d863` | sécu | 20+ `ErrorMessage = ex.Message` côté Postgres + MySQL repositories → message générique (info disclosure colmaté) |
| _next_    | sécu | **HMAC-SHA256 sur `X-CustomerGUID`** : `StoreCustomerGUIDMiddleware` étendu (`OWSHmac` section appsettings, mode opt-in `RequireSignature=false` par défaut, fenêtre anti-replay 5 min, `FixedTimeEquals`). 7 nouveaux tests xUnit. Helper client UE5 `OWSHmacSigning::ApplySignature` (OpenSSL HMAC, lit `OWSHmacSecret` GConfig). Tous les call sites HTTP X-CustomerGUID patchés : `OWSAPISubsystem` (POST+GET), `OWSGameMode` (POST), `SHWSlateMenu` (Register/Login/GetAllCharacters), `HWLoginWidget` (Login legacy). |

Côté client UE5.4 (privé, branche `refactor/source-reorganization`) :
- `fa15544` security: WithValidation Server_SetFlySpeed + Server_TravelToDeadKingdom + BuildJsonBody pour le login Slate
- `9159453` security: SessionGUID + CustomerKey masqués dans 6 logs client
- `b1a2d38` security: WithValidation x3 supplémentaires (CreateDeformation/ChangeAppearance/ChangeOverlapStatus)
- `5a071f7` security: template secrets enrichi (instructions de génération `openssl rand -hex 16` + politique rotation)

Côté site Hybelior (public, branche `main`) :
- `0cf69e574` security: CSP + HSTS + X-Frame-Options + Referrer-Policy + Permissions-Policy ; mot de passe éditeur en header `X-Editor-Password` uniquement (plus de query string)

## 5. À faire le jour J du premier déploiement

1. Générer tous les nouveaux secrets (passwords forts, GUIDs frais) — utiliser `openssl rand -base64 32` ou équivalent.
2. Les injecter via variables d'env ou Secret manager — **jamais** dans un fichier versionné.
3. Vérifier `ASPNETCORE_ENVIRONMENT=Production` sur chaque service en prod.
4. Audit des logs pour s'assurer qu'aucun secret ne fuit dans Serilog (`OWSAPIKey` partiellement loggué côté client UE — voir `HybeliorWorld_5.4/Source/.../HWLoginWidget.cpp:92`).
5. **HMAC rollout** :
   - Générer un secret partagé : `openssl rand -hex 32` (64 chars hex).
   - Le stocker côté OWS dans `appsettings.Production.json` clé `OWSHmac:Secret` (ou env var `OWSHMAC__SECRET`).
   - Le stocker côté client UE5 dans `Config/DefaultGame_Secrets.ini` (gitignored) sous `[/Script/OWSPlugin.OWSPlayerControllerComponent] OWSHmacSecret=...`.
   - **Sanity check pré-déploiement** : `dotnet test` sur OWS.sln → doit reporter **60/60 réussis** (les tests HMAC échouent immédiatement si la configuration appsettings ou la registration SimpleInjector cassent). Si moins de tests passent : ne pas déployer, ouvrir un commit fix.
   - **Phase 1** : déployer backend avec `OWSHmac:Enabled=true, RequireSignature=false`. Patcher les clients (déjà fait côté UE5 — 6 sites HTTP signés : `OWSAPISubsystem` GET+POST, `OWSGameMode`, `SHWSlateMenu` Register/Login/GetAllCharacters, `HWLoginWidget`, **`OWSPlayerControllerComponent` (helper central in-world, 19+ callers)**). Surveiller les warnings Serilog `"HMAC opt-in: unsigned request from <IP>"` (throttlés à 1/IP/min, n'inonderont pas le disque même sous traffic prod). Tant que ces warnings remontent, des clients tournent encore en mode legacy.
   - **Phase 2** : une fois les warnings Phase 1 à zéro, flipper `OWSHmac:RequireSignature=true`. Les requêtes non-signées retournent désormais 401.
   - **Cap body HMAC** : `OWSHmac:MaxBodyBytes` default 2 MB suffit pour tous les writes OWS légitimes (le plus gros = `AddOrUpdateCustomCharacterData` capé à 64 KB). Si une feature future a besoin de POST plus volumineux, augmenter cette valeur — sinon laisser tel quel pour bloquer les POST géants (DoS).
   - **Misconfig fail-closed** : `OWSHmac:Enabled=true` + `OWSHmac:Secret` vide = le service refuse de démarrer (InvalidOperationException). Soit fournir le secret, soit `Enabled=false`.
   - Rotation : remplacer `OWSHmac:Secret` simultanément client + serveur lors d'une fenêtre de maintenance (pas de support multi-key actuellement — TODO si besoin).
