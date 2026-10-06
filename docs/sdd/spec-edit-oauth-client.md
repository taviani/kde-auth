# kde-auth — édition d’un client OAuth

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

**Priorité :** feature (après correctifs « cassé »). Aujourd’hui l’admin peut **créer** un client et changer `access_mode`. Impossible d’éditer nom, redirect URIs, `android_package`, de faire tourner le secret, ou de supprimer un client.

## Produit

L’administrateur de l’issuer gère le cycle de vie d’un client OAuth first-party sans passer par la base à la main :

- modifier les métadonnées sûres (nom, redirect URIs, package Android pour intent links) ;
- changer `access_mode` (déjà possible) ;
- faire **tourner le secret** d’un client confidentiel (nouveau secret affiché une fois) ;
- **supprimer** un client hors production critique (avec garde-fous).

Les apps (Portclos, Instacrane, etc.) ne s’auto-provisionnent pas : l’issuer reste la source de vérité des clients.

## Processus

1. Admin authentifié ouvre `/admin/clients`.
2. Il édite un client existant (formulaire) ou demande une rotation de secret / une suppression.
3. L’issuer valide (URIs, méthode d’auth, package) et persiste.
4. En cas de rotation de secret : l’ancien hash est remplacé ; le secret en clair n’est montré qu’une fois (comme à la création).
5. En cas de suppression : le client disparaît ; codes / refresh liés deviennent inutilisables au prochain usage (ou cascade DB).

## Règles

- Public (`token_endpoint_auth_method=none`) : pas de secret ; pas de rotation secret.
- Confidential : secret hashé argon2 ; rotation invalide l’ancien secret immédiatement.
- Redirect URIs : liste exact-match (comme aujourd’hui) ; au moins une URI.
- `android_package` : optionnel ; utilisé seulement pour la page de handoff native.
- On ne change pas `client_id` après création (identifiant stable).
- On ne change pas `token_endpoint_auth_method` public ↔ confidential dans la v1 **sauf** si le plan le permet explicitement (défaut proposé : **interdit** en v1 pour éviter les semi-états).
- Suppression : refusée si c’est le dernier client, ou confirmation explicite ; pas de soft-delete dans la v1.

## API / Admin (issuer)

Surface admin HTML (et éventuellement POST form) — pas d’API publique machine dans la v1.

| Action | Effet |
|--------|--------|
| Update metadata | name, redirect_uris[], android_package, access_mode |
| Rotate secret | nouveau secret (confidential only), affichage one-shot |
| Delete client | suppression + invalidation effective des grants |

## Clients

Après rotation de secret, les backends confidentiels doivent mettre à jour leur config. Les apps publiques (PKCE) ne sont pas impactées par la rotation.

## Hors scope (cette version)

- Self-service création de client par un non-admin.
- Plusieurs secrets en chevauchement (grace period).
- Scopes autorisés par client / audience fine.
- UI hors `/admin`.
- Changement de `client_id`.

## Critères d’acceptation

- Admin peut corriger une redirect URI sans recréer le client.
- Rotation secret : ancien secret refusé au `/token` ; nouveau accepté.
- Client public : pas de bouton / action rotate secret.
- Delete : authorize avec cet `client_id` → invalid_client (ou équivalent).
- `access_mode` invite_only ↔ public reste possible (comportement actuel conservé).
