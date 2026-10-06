# kde-auth — révocation de jeton et fin de session OIDC

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** feature (après correctifs « cassé »). Aujourd’hui : `POST /logout` ne couvre que le cookie session issuer. Il existe une primitive repo pour révoquer un refresh, mais **pas** de `POST /revoke` public ni d’`end_session_endpoint`.

## Produit

Les clients (surtout natifs) doivent pouvoir :

1. **Révoquer** un refresh (et idéalement ignorer / laisser expirer l’access) quand l’utilisateur se déconnecte de l’app — RFC 7009 simplifié.
2. **Terminer la session** issuer (cookie) de façon interopérable — OIDC RP-Initiated Logout minimal, si on expose une session navigateur partagée.

L’issuer reste light : pas d’introspection obligatoire, pas de denylist access dans la v1.

## Processus — revoke

1. Le client appelle `POST /revoke` avec le jeton (refresh) et s’authentifie selon son type (secret post ou public + PKCE non requis pour revoke ; public : `client_id` + token).
2. Si le jeton est un refresh connu du client : marquage révoqué ; réponse 200 même si déjà inconnu (anti-énumération, pratique RFC 7009).
3. Access token présenté à `/revoke` : accepté sans effet durable en v1 (200) **ou** refusé clairement — **défaut proposé : 200 no-op** pour rester simple.

## Processus — end session

1. Le RP redirige le navigateur vers `GET /end-session` (nom exact au plan) avec la session cookie issuer (et optionnellement `client_id`), et optionnellement `post_logout_redirect_uri` + `state`. Pas d’`id_token_hint` tant qu’on n’émet pas d’`id_token` (voir [spec-oidc-discovery-honesty.md](spec-oidc-discovery-honesty.md)).
2. L’issuer révoque la session cookie.
3. Si `post_logout_redirect_uri` est dans une allowlist du client : redirect ; sinon page « déconnecté » issuer.

## Règles

- `/logout` actuel (POST, cookie) peut rester pour les pages issuer ; end-session couvre le cas RP.
- Revoke ne nécessite pas la session cookie.
- Un refresh révoqué ne peut plus être échangé.
- `post_logout_redirect_uri` : exact match sur une URI enregistrée du client (réutiliser redirect_uris **ou** liste dédiée — **défaut proposé : sous-ensemble des redirect_uris** en v1).

## API (issuer)

| Méthode | Chemin (proposé) | Effet |
|---------|------------------|--------|
| `POST` | `/revoke` | RFC 7009 : révoque refresh |
| `GET` | `/end-session` (ou `/logout` enrichi) | fin session + redirect optionnel |
| Discovery | + `revocation_endpoint`, + `end_session_endpoint` | une fois implémenté |

## Clients

- Apps natives : appeler `/revoke` au logout local avant d’effacer le stockage.
- Apps web first-party : end-session ou `/logout` selon le flux.

## Hors scope (cette version)

- Introspection (`/introspect`).
- Révocation d’access via denylist.
- Back-channel logout.
- Grace period multi-secret.

## Critères d’acceptation

- Refresh révoqué via `/revoke` → `invalid_grant` au token endpoint.
- Revoke d’un jeton inconnu → 200 (pas d’oracle).
- End-session : cookie session invalidé ; redirect uniquement vers URI autorisée.
- Discovery ne mentionne ces endpoints **qu’après** implémentation (lien avec [spec-oidc-discovery-honesty.md](spec-oidc-discovery-honesty.md)).
