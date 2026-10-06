# kde-auth — suspendre un compte coupe sessions et refresh

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** cassé. L’admin peut passer un user en `suspended`, mais les sessions cookie et refresh tokens déjà émis restent utilisables jusqu’à TTL / prochaine vérif partielle. Un access JWT déjà émis expire seul (~15 min) — acceptable. Sessions et refresh ne le sont pas.

## Produit

Passer un compte en **suspended** doit immédiatement empêcher :

- la poursuite d’une session issuer (cookie) ;
- le renouvellement via refresh ;
- un nouvel authorize / login réussi.

Le compte reste en base (pas de delete). Le repasser en `active` ne « ressuscite » pas les anciens refresh/sessions : l’utilisateur doit se reconnecter.

## Processus

1. Admin (session admin) change le statut user → `suspended` (UI / action existante).
2. L’issuer persiste le statut.
3. Dans la **même** opération : révoque toutes les sessions + tous les refresh du user (même primitive que revoke admin / change-password après correctif).
4. Tentatives suivantes : login / authorize / refresh refusés selon les règles `CanAuthenticate` / `CanAuthorize` déjà en place.

## Règles

- Symétrie avec « revoke sessions » admin : suspend = revoke + statut.
- Remise à `active` : pas de réactivation automatique des jetons révoqués.
- Access JWT non expirés : hors scope denylist (comme pour change-password).
- Ne s’applique pas aux admins se suspendant eux-mêmes si déjà interdit ; sinon même revoke.

## API (issuer)

Pas de nouvelle route publique. Renforcement de l’action admin existante de changement de statut.

| Action | Attendu |
|--------|---------|
| Set status → `suspended` | statut + revoke sessions + revoke refresh |
| Set status → `active` | statut seulement (pas de restauration de jetons) |

## Clients

Les apps voient `invalid_grant` / échec de session et renvoient au login — déjà le cas attendu après revoke admin.

## Hors scope (cette version)

- Denylist access token.
- Notification email « votre compte a été suspendu ».
- Soft-lock temporaire (rate-limit) distinct du statut `suspended`.

## Critères d’acceptation

- Après suspend : refresh du user → `invalid_grant` ; cookie session invalide.
- Login avec mot de passe correct sur compte suspended : refus (comportement actuel `CanAuthenticate` conservé ou renforcé, pas d’ouverture de session).
- Remise `active` : login possible ; anciens refresh toujours morts.
- Test unitaire / intégration sur le chemin SetStatus → suspended.
