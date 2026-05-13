# keycloak-user-panel

Pannello self-service ASP Messina per la gestione dei metodi di **autenticazione a due fattori** (FIDO2, codice via email, codice via SMS) di un utente Keycloak.

Conforme alle direttive ASP-WS apps management: container Docker, porta `3000`, BASE_PATH da env.

## Stack

- **Node.js 20+** / Express
- **openid-client** per il flow OIDC verso Keycloak
- **Tailwind CSS** + **Lucide Icons** via CDN (no build pipeline)

## Sicurezza

L'app **non ha alcun accesso amministrativo a Keycloak**. Tutte le operazioni sui metodi 2FA usano l'**Account REST API** di Keycloak con l'access token dell'utente loggato:

| Operazione | Endpoint Keycloak |
|---|---|
| Profilo utente | `GET /realms/{r}/account/` |
| Lista credentials | `GET /realms/{r}/account/credentials` |
| Rimuovi credential | `DELETE /realms/{r}/account/credentials/{id}` |
| Modifica label credential | `PUT /realms/{r}/account/credentials/{id}/label` |
| Aggiungi nuovo metodo | redirect OIDC con `?kc_action=<required-action-id>` |

Le **aggiunte** di metodi 2FA usano il pattern Keycloak *Application Initiated Action*: l'app reindirizza al flow di login con il parametro `kc_action`, l'utente conferma/completa la setup (passa eventualmente per la propria 2FA esistente), e torna al pannello.

I `kc_action` previsti sono:
- `CONFIGURE_TOTP` — registrazione TOTP (App Authenticator)
- `webauthn-register` — registrazione FIDO2 / passkey
- `asp-configure-email-otp` — registrazione codice via email (required action custom ASP)
- *(SMS sarà aggiunto quando la required action lato Keycloak sarà implementata)*

## Configurazione del client Keycloak

Da Admin Console → realm `asp` → *Clients* → **Create client**.

**Tab General**
- Client type: `OpenID Connect`
- Client ID: `keycloak-user-panel`
- Name: `Pannello utente — gestione 2FA`

**Tab Capability config**
- Client authentication: **ON** (confidential)
- Authorization: **OFF**
- Standard flow: **ON**
- Implicit flow: OFF
- Direct access grants: OFF
- Service accounts roles: **OFF** *(non serve, l'app NON usa il service account)*
- Authentication flow: OAuth 2.0 Device Authorization Grant: OFF; OIDC CIBA Grant: OFF

**Tab Login settings**
- Root URL: `https://ws1.asp.messina.it/apps/keycloak-user-panel`
- Home URL: `https://ws1.asp.messina.it/apps/keycloak-user-panel/`
- Valid redirect URIs: `https://ws1.asp.messina.it/apps/keycloak-user-panel/auth/callback`
- Valid post logout redirect URIs: `https://ws1.asp.messina.it/apps/keycloak-user-panel/`
- Web origins: `https://ws1.asp.messina.it`

**Tab Advanced** → *Authentication flow overrides* (opzionale): nessuno, eredita dal realm.

Dopo Save, dal tab **Credentials** copia il *Client secret* — andrà in `KEYCLOAK_CLIENT_SECRET`.

### Tramite kcadm (alternativa)

```bash
docker exec keycloak /opt/keycloak/bin/kcadm.sh create clients -r asp \
  -s clientId=keycloak-user-panel \
  -s 'name=Pannello utente - gestione 2FA' \
  -s protocol=openid-connect \
  -s publicClient=false \
  -s standardFlowEnabled=true \
  -s directAccessGrantsEnabled=false \
  -s serviceAccountsEnabled=false \
  -s 'rootUrl=https://ws1.asp.messina.it/apps/keycloak-user-panel' \
  -s 'baseUrl=https://ws1.asp.messina.it/apps/keycloak-user-panel/' \
  -s 'redirectUris=["https://ws1.asp.messina.it/apps/keycloak-user-panel/auth/callback"]' \
  -s 'webOrigins=["https://ws1.asp.messina.it"]'

# Stampa il client secret generato
CID=$(docker exec keycloak /opt/keycloak/bin/kcadm.sh get clients -r asp \
        -q clientId=keycloak-user-panel --fields id --format csv --noquotes | tail -1)
docker exec keycloak /opt/keycloak/bin/kcadm.sh get clients/$CID/client-secret -r asp
```

## Variabili d'ambiente

Vedi [`.env.example`](.env.example).

In **produzione** (ASP-WS apps management), `BASE_PATH` viene iniettato automaticamente. Le altre variabili si configurano nell'interfaccia apps.

## Sviluppo locale

```bash
cp .env.example .env
# Compila KEYCLOAK_CLIENT_SECRET, SESSION_SECRET (random 64 char), DEV_MODE=true,
# APP_PUBLIC_URL=http://localhost:3000

npm install
npm start
```

Apri http://localhost:3000 e fai login.

> Per testare in locale dovrai aggiungere `http://localhost:3000/auth/callback` ai Valid redirect URIs del client Keycloak (puoi tenere entrambi prod + dev).

## Build & Docker

```bash
docker build -t keycloak-user-panel .
docker run --rm -p 3000:3000 \
    -e BASE_PATH=/apps/keycloak-user-panel \
    -e SESSION_SECRET=xxxxx \
    -e KEYCLOAK_CLIENT_ID=keycloak-user-panel \
    -e KEYCLOAK_CLIENT_SECRET=xxxxx \
    -e APP_PUBLIC_URL=https://ws1.asp.messina.it/apps/keycloak-user-panel \
    keycloak-user-panel
```

## Deploy su ASP-WS

1. Pusha il codice sul repo GitHub privato configurato
2. Su ws1, accedi alla console apps management
3. Aggiungi nuova app da URL git, branch `main`
4. App ID: `keycloak-user-panel`
5. Configura le variabili d'ambiente
6. Avvia

## Endpoint app

| Path | Descrizione |
|---|---|
| `/` | Dashboard utente |
| `/auth/login` | Inizia OIDC login |
| `/auth/callback` | Callback OIDC |
| `/auth/logout` | Logout (RP-initiated) |
| `/api/me` | Profilo utente + credentials |
| `DELETE /api/2fa/credentials/:id` | Rimuove un credential |
| `PUT /api/2fa/credentials/:id/label` | Rinomina label |
| `GET /api/2fa/add/:method` | Redirect a Keycloak per setup (`webauthn`, `totp`, `email`) |
| `PUT /api/2fa/sms` | Salva numero telefono (channel sms, in attesa di implementazione invio) |

## Licenza

Uso interno ASP Messina.
