# kde-auth — emails secondaires / récupération

Source de vérité. On n’implémente une tranche qu’une fois cette spec validée, et seulement cette tranche.

## Produit

Un compte a aujourd’hui **un** email, vérifié à l’inscription. Cette feature ajoute un **second email** (aussi appelé email de récupération). Une fois ce second email **vérifié**, le titulaire peut **supprimer** l’un des deux. Enchaîner « ajouter + vérifier + supprimer l’ancien » revient à **changer l’email du compte** sans jamais rester sans adresse vérifiée.

Les clients OAuth (Portclos, Instacrane, etc.) exposent ces actions dans leurs écrans compte. L’issuer reste la seule source de vérité : pas de changement d’email local côté app.

## Processus

1. Le titulaire est authentifié (session issuer ou Bearer JWT, selon les routes retenues).
2. Il demande l’ajout d’un second email. L’issuer refuse si un second email (vérifié ou en attente) existe déjà, si l’adresse est déjà prise par un autre compte, ou si elle est déjà l’email courant.
3. L’issuer envoie un **mail de validation** à cette nouvelle adresse uniquement.
4. Tant que le lien n’est pas consommé (ou tant qu’il n’a pas expiré), le second email est **en attente** : non utilisable pour se connecter, non exposé comme email principal OIDC.
5. Après validation réussie, le compte a **deux emails vérifiés**.
6. Supprimer un email n’est possible que s’il en reste **au moins un vérifié**. On ne peut pas supprimer le dernier.
7. Après suppression, l’email restant devient (ou reste) l’email principal du compte : login, `email` / `email_verified` dans les jetons et `/userinfo`, reset mot de passe.

Sans ticket / sans session : pas d’ajout. Inscription initiale inchangée (toujours un email + vérification).

## Règles

- Au plus **deux** emails par compte (un principal + un secondaire / récupération).
- Un email **non vérifié** en attente compte dans cette limite : pas de troisième tentative en parallèle.
- Chaque adresse est **unique** dans tout l’issuer (comme aujourd’hui pour `users.email`).
- Login et mot de passe oublié acceptent **n’importe quel email vérifié** du compte.
- Un email en attente n’ouvre pas le login.
- Annuler l’ajout en attente (avant validation) libère la place pour un autre second email.
- Changer d’email = ajouter + vérifier + supprimer l’ancien ; pas de route magique « remplacer ».
- Rate-limit et captcha sur les actions qui envoient un mail (alignés sur forgot-password / register).

## Données

Évolution du modèle actuel (une colonne `users.email`) vers plusieurs adresses rattachées au même `user_id` :

- chaque ligne : adresse, statut (en attente / vérifié), rôle (principal / secondaire), horodatages ;
- exactement un principal parmi les emails **vérifiés** ;
- le claim OIDC `email` est toujours celui du principal vérifié.

(Les détails de migration SQL sont hors de cette page produit ; ils suivront la tranche d’implémentation.)

## API (issuer)

Toutes les routes compte ci-dessous exigent une session valide (cookie issuer et/ou Bearer, même modèle que `POST /account/password`).

| Méthode | Chemin (proposé) | Effet |
|--------|------------------|--------|
| `GET` | `/account/emails` | Liste les emails du compte (principal / secondaire, vérifié ou en attente) |
| `POST` | `/account/emails` | Demande d’ajout du second email → envoi du mail de validation |
| `POST` | `/account/emails/cancel` | Annule un ajout encore en attente |
| `DELETE` | `/account/emails` | Supprime un email vérifié si un autre vérifié reste |
| `GET` | `/verify-email?token=` | Inchangé pour l’inscription ; aussi consomme la validation d’un second email |

Réponses d’erreur utiles aux clients : adresse prise, limite atteinte, dernier email, token invalide, non authentifié.

`/userinfo` et les JWT continuent d’exposer uniquement l’email **principal** vérifié.

## Clients

Les apps n’écrivent pas l’email en base locale comme source de vérité. Après succès issuer, elles rafraîchissent le profil (`userinfo` / session).

Écrans typiques plus tard : liste des emails, formulaire « ajouter un email de récupération », message « vérifiez votre boîte », action « supprimer » si deux emails vérifiés.

## Hors scope (cette version)

- Plus de deux emails.
- Fusion de comptes.
- Changement d’email sans vérification.
- Admin qui force un email sans flux de validation.
- UI admin kde-auth pour gérer les emails (sauf si une tranche ultérieure le demande).

## Critères d’acceptation

- Sans ticket / sans auth : impossible d’ajouter un email.
- Ajout → mail reçu → lien valide → second email vérifié.
- Lien expiré ou rejoué : refus.
- Avec un seul email vérifié : suppression refusée.
- Avec deux vérifiés : suppression de l’un laisse le compte utilisable avec l’autre (login + OIDC).
- `REGISTRATION_OPEN` et invite-only ne changent pas ce flux compte (utilisateur déjà inscrit).
