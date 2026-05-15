/**
 * keycloak-user-panel
 * ------------------------------------------------------------------
 * Self-service per la gestione dei metodi di autenticazione a due
 * fattori (FIDO2, email-otp, sms-otp) di un utente Keycloak.
 *
 * Conforme alle direttive ASP-WS: ascolta sulla porta 3000, legge
 * BASE_PATH dall'env (iniettato dal sistema apps).
 *
 * SICUREZZA:
 *   L'app NON ha alcun accesso admin a Keycloak. Tutte le operazioni
 *   sono fatte tramite l'Account REST API di Keycloak usando l'access
 *   token dell'utente loggato. Niente service-account, niente
 *   client-credentials, nessun ruolo realm-management.
 *
 *   - GET   /realms/{r}/account/                  -> profilo utente
 *   - GET   /realms/{r}/account/credentials       -> lista credentials
 *   - DELETE/realms/{r}/account/credentials/{id}  -> rimuovi credential
 *
 *   Per aggiungere un nuovo metodo 2FA (FIDO2, email-otp, sms-otp)
 *   facciamo redirect al flow OIDC con il parametro speciale
 *   ?kc_action=<required-action-id>: Keycloak chiede all'utente di
 *   completare la registrazione (Application Initiated Action).
 *
 * Variabili d'ambiente: vedi .env.example
 */
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const path = require('path');
const { Issuer, generators } = require('openid-client');
const fetch = require('node-fetch');

const PORT = parseInt(process.env.PORT || '3000', 10);
const BASE_PATH = process.env.BASE_PATH || '';
const APP_PUBLIC_URL = (process.env.APP_PUBLIC_URL || 'http://localhost:3000').replace(/\/$/, '');
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-me-in-production-use-a-long-random-string';
const KEYCLOAK_ISSUER = process.env.KEYCLOAK_ISSUER || 'https://login.asp.messina.it/realms/asp';
const KEYCLOAK_REALM = process.env.KEYCLOAK_REALM || 'asp';
const CLIENT_ID = process.env.KEYCLOAK_CLIENT_ID || 'keycloak-user-panel';
const CLIENT_SECRET = process.env.KEYCLOAK_CLIENT_SECRET || '';
const DEV_MODE = String(process.env.DEV_MODE || 'false').toLowerCase() === 'true';

const ACCOUNT_BASE = `${KEYCLOAK_ISSUER}/account`;
// Endpoint REST custom esposto dal nostro SPI Java in Keycloak. Usato per
// elencare TUTTI i credentials dell'utente, inclusi i tipi custom (asp-otp-channel)
// che l'Account API standard non include nella sua risposta.
const ASP_API_BASE = `${KEYCLOAK_ISSUER}/asp-2fa`;

const CREDENTIAL_TYPE_OTP_CHANNEL = 'asp-otp-channel';
const CHANNEL_EMAIL = 'email';
const CHANNEL_SMS = 'sms';

const REQUIRED_ACTION_EMAIL_OTP = 'asp-configure-email-otp';
const REQUIRED_ACTION_WEBAUTHN = 'webauthn-register';
const REQUIRED_ACTION_TOTP = 'CONFIGURE_TOTP';

console.log('=== keycloak-user-panel starting ===');
console.log('  PORT:           ', PORT);
console.log('  BASE_PATH:      ', BASE_PATH || '(none)');
console.log('  APP_PUBLIC_URL: ', APP_PUBLIC_URL);
console.log('  KEYCLOAK_ISSUER:', KEYCLOAK_ISSUER);
console.log('  CLIENT_ID:      ', CLIENT_ID);
console.log('  DEV_MODE:       ', DEV_MODE);

const app = express();
// Trust il reverse proxy ASP-WS: ci passa attraverso e termina HTTPS lui.
// Express deve fidarsi di X-Forwarded-Proto / X-Forwarded-For per determinare
// req.secure e settare il cookie di sessione correttamente.
app.set('trust proxy', true);

// Log diagnostico: stampiamo per ogni richiesta lo schema "visto" dietro proxy
app.use((req, _res, next) => {
    if (process.env.DEBUG_REQ) {
        console.log(`[req] ${req.method} ${req.originalUrl} secure=${req.secure} xfp=${req.get('x-forwarded-proto')}`);
    }
    next();
});

app.use(express.json({ limit: '64kb' }));
app.use(express.urlencoded({ extended: true, limit: '64kb' }));
app.use(cookieParser());
app.use(session({
    secret: SESSION_SECRET,
    name: 'asp_panel_sid',
    resave: false,
    saveUninitialized: false,
    proxy: true,
    cookie: {
        httpOnly: true,
        sameSite: 'lax',
        // 'auto' = secure solo se req.secure (X-Forwarded-Proto=https) e' true.
        // In DEV_MODE forziamo false per consentire localhost http.
        secure: DEV_MODE ? false : 'auto',
        maxAge: 12 * 60 * 60 * 1000,
    },
}));

// ------------------------------------------------------------------
// OIDC client (lazy init: la discovery va fatta una volta sola)
// ------------------------------------------------------------------
let oidcClient = null;
async function getOidcClient() {
    if (oidcClient) return oidcClient;
    const issuer = await Issuer.discover(KEYCLOAK_ISSUER);
    oidcClient = new issuer.Client({
        client_id: CLIENT_ID,
        client_secret: CLIENT_SECRET,
        redirect_uris: [`${APP_PUBLIC_URL}/auth/callback`],
        post_logout_redirect_uris: [`${APP_PUBLIC_URL}/`],
        response_types: ['code'],
        token_endpoint_auth_method: CLIENT_SECRET ? 'client_secret_post' : 'none',
    });
    return oidcClient;
}

// ------------------------------------------------------------------
// Account API call (con access token dell'utente)
// ------------------------------------------------------------------
async function userApi(req, baseUrl, pathPart, opts = {}) {
    const at = req.session && req.session.tokens && req.session.tokens.access_token;
    if (!at) {
        const err = new Error('no_user_access_token');
        err.status = 401;
        throw err;
    }
    const url = `${baseUrl}${pathPart}`;
    const res = await fetch(url, {
        ...opts,
        headers: {
            'Authorization': `Bearer ${at}`,
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            ...(opts.headers || {}),
        },
    });
    if (res.status === 401 || res.status === 403) {
        const err = new Error('account_api_unauthorized');
        err.status = res.status;
        throw err;
    }
    if (!res.ok) {
        const txt = await res.text().catch(() => '');
        const err = new Error(`Account API ${opts.method || 'GET'} ${pathPart} -> ${res.status}: ${txt}`);
        err.status = res.status;
        throw err;
    }
    if (res.status === 204) return null;
    const text = await res.text();
    if (!text) return null;
    try { return JSON.parse(text); } catch { return text; }
}

// Account API standard (per profile + delete credential)
const userAccountApi = (req, pathPart, opts) => userApi(req, ACCOUNT_BASE, pathPart, opts);
// Nostro endpoint custom (lista credentials completa, incluso asp-otp-channel)
const userAspApi = (req, pathPart, opts) => userApi(req, ASP_API_BASE, pathPart, opts);

// ------------------------------------------------------------------
// Auth middleware
// ------------------------------------------------------------------
function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        // Per gli endpoint API mai redirect (causerebbe redirect cross-origin
        // bloccato da CORS quando il browser fa fetch): rispondi 401 JSON e
        // lascia al client gestire la redirezione al login.
        const isApi = req.path.startsWith('/api/') || req.xhr ||
                      req.get('accept') === 'application/json';
        if (isApi || req.method !== 'GET') {
            return res.status(401).json({ error: 'not_authenticated' });
        }
        // Per le pagine HTML: redirect normale al login
        return res.redirect(`${BASE_PATH}/auth/login`);
    }
    next();
}

// ------------------------------------------------------------------
// Routes - auth
// ------------------------------------------------------------------
function startOidc(req, res, extraParams = {}) {
    return (async () => {
        const client = await getOidcClient();
        const code_verifier = generators.codeVerifier();
        const code_challenge = generators.codeChallenge(code_verifier);
        const state = generators.state();
        const nonce = generators.nonce();
        req.session.pkce = { code_verifier, state, nonce };

        const authUrl = client.authorizationUrl({
            scope: 'openid profile email',
            state, nonce,
            code_challenge,
            code_challenge_method: 'S256',
            ...extraParams,
        });
        console.log('[startOidc] redirect →', authUrl);
        res.redirect(authUrl);
    })();
}

app.get('/auth/login', (req, res, next) => {
    startOidc(req, res).catch(next);
});

app.get('/auth/callback', async (req, res, next) => {
    try {
        const client = await getOidcClient();
        const pkce = req.session.pkce || {};
        // Diagnostica: se la sessione PKCE e' vuota qui, il cookie di sessione
        // non e' arrivato (di solito problema secure/sameSite dietro proxy).
        if (!pkce.code_verifier) {
            console.error('[auth/callback] req.session.pkce is empty - session cookie not persisted across redirect. ' +
                          `cookie name=asp_panel_sid. xfp=${req.get('x-forwarded-proto')} secure=${req.secure}`);
        }
        const params = client.callbackParams(req);
        const tokenSet = await client.callback(
            `${APP_PUBLIC_URL}/auth/callback`,
            params,
            { code_verifier: pkce.code_verifier, state: pkce.state, nonce: pkce.nonce },
        );
        const claims = tokenSet.claims();
        // Decodifica payload dell'access_token (JWT) per i claim non in id_token
        let accessClaims = null;
        try {
            const payloadB64 = tokenSet.access_token.split('.')[1];
            const padded = payloadB64 + '==='.slice((payloadB64.length + 3) % 4);
            accessClaims = JSON.parse(Buffer.from(padded, 'base64').toString('utf8'));
        } catch (e) { /* ignore */ }
        req.session.user = {
            sub: claims.sub,
            username: claims.preferred_username,
            email: claims.email,
            name: claims.name,
            given_name: claims.given_name,
            family_name: claims.family_name,
            amr: claims.amr || [],
        };
        // Salva tutti i claim (id_token + access_token) per esporli al pannello.
        req.session.idTokenClaims = claims;
        req.session.accessTokenClaims = accessClaims;
        req.session.tokens = {
            access_token: tokenSet.access_token,
            id_token: tokenSet.id_token,
            refresh_token: tokenSet.refresh_token,
            expires_at: tokenSet.expires_at,
            scope: tokenSet.scope,
            token_type: tokenSet.token_type,
        };
        delete req.session.pkce;
        // Se la sessione aveva un "returnTo" (es. dopo kc_action), riprendi
        const returnTo = req.session.returnTo;
        delete req.session.returnTo;
        res.redirect(returnTo || `${BASE_PATH}/`);
    } catch (e) { next(e); }
});

app.get('/auth/logout', async (req, res, next) => {
    try {
        const client = await getOidcClient();
        const id_token = req.session.tokens && req.session.tokens.id_token;
        req.session.destroy(() => {
            const logoutUrl = client.endSessionUrl({
                id_token_hint: id_token,
                post_logout_redirect_uri: `${APP_PUBLIC_URL}/`,
            });
            res.redirect(logoutUrl);
        });
    } catch (e) { next(e); }
});

// ------------------------------------------------------------------
// API - versione app (utile per verificare deploy/cache invalidation)
// ------------------------------------------------------------------
const APP_VERSION = require('./package.json').version;
const APP_BUILD_TIME = new Date().toISOString();
app.get('/api/version', (req, res) => {
    res.json({ version: APP_VERSION, buildTime: APP_BUILD_TIME, name: 'keycloak-user-panel' });
});

// ------------------------------------------------------------------
// API - info utente + gestione 2FA (via Account API dell'utente)
// ------------------------------------------------------------------
app.get('/api/me', requireAuth, async (req, res, next) => {
    try {
        const profile = await userAccountApi(req, '/');
        // Lista credentials direttamente dal nostro endpoint Keycloak custom
        // (include i tipi custom come asp-otp-channel che Account API esclude).
        // Formato gia' piatto + normalizzato server-side (channel/address).
        const aspCreds = await userAspApi(req, '/credentials');
        // Aggiungiamo virtualmente la "password" come credential perche' il
        // nostro endpoint mostra solo i stored credentials e per utenti LDAP
        // read-only il password e' federato (non stored).
        const credentials = Array.isArray(aspCreds) ? aspCreds.slice() : [];
        credentials.unshift({
            id: null,
            type: 'password',
            label: null,
            createdDate: null,
            removable: false,
        });
        const tokens = req.session.tokens || {};
        res.json({
            profile,
            amr: req.session.user.amr,
            credentials,
            session: {
                scope: tokens.scope || null,
                tokenType: tokens.token_type || null,
                expiresAt: tokens.expires_at || null,
                idTokenClaims: redactSensitive(req.session.idTokenClaims || {}),
                accessTokenClaims: redactSensitive(req.session.accessTokenClaims || {}),
            },
        });
    } catch (e) { next(e); }
});

/** Maschera (non rimuove, ma offusca) campi sensibili nei claim mostrati al client. */
function redactSensitive(obj) {
    if (!obj || typeof obj !== 'object') return obj;
    const out = Array.isArray(obj) ? [] : {};
    const HIDE = new Set(['at_hash', 'c_hash', 'nonce']);
    for (const [k, v] of Object.entries(obj)) {
        if (HIDE.has(k)) continue;
        out[k] = v;
    }
    return out;
}

/**
 * Account API ritorna credentials come "tipi". Trasformiamo in lista piatta
 * di credentials individuali per la UI, includendo la decodifica per
 * asp-otp-channel.
 */
function normalizeCredentials(types) {
    const out = [];
    for (const tg of types) {
        const list = Array.isArray(tg.userCredentialMetadatas) ? tg.userCredentialMetadatas : [];
        for (const ucm of list) {
            const c = ucm.credential || {};
            const item = {
                id: c.id,
                type: c.type || tg.type,
                label: c.userLabel || null,
                createdDate: c.createdDate || null,
            };
            if (item.type === CREDENTIAL_TYPE_OTP_CHANNEL && c.secretData) {
                try {
                    const data = JSON.parse(c.secretData);
                    item.channel = data.channel || null;
                    item.address = data.address || null;
                } catch { /* ignore */ }
            }
            out.push(item);
        }
        // Fallback per versioni Account API che restituiscono credentials in 'credentials'
        const flat = Array.isArray(tg.credentials) ? tg.credentials : [];
        for (const c of flat) {
            const item = {
                id: c.id,
                type: c.type || tg.type,
                label: c.userLabel || null,
                createdDate: c.createdDate || null,
            };
            if (item.type === CREDENTIAL_TYPE_OTP_CHANNEL && c.secretData) {
                try {
                    const data = JSON.parse(c.secretData);
                    item.channel = data.channel || null;
                    item.address = data.address || null;
                } catch { /* ignore */ }
            }
            out.push(item);
        }
    }
    return out;
}

// Rimuove un credential dell'utente (FIDO2, OTP, asp-otp-channel).
//
// SECURITY (anti-takeover): pre-check sui metodi 2FA dell'utente. Se la
// rimozione lascerebbe l'utente con ZERO metodi 2FA, RIFIUTIAMO l'operazione
// con HTTP 409. L'utente deve PRIMA aggiungere un nuovo metodo e solo dopo
// potra' rimuovere il vecchio. In questo modo non si crea mai una finestra
// in cui l'account e' protetto solo da password (che un attaccante con
// credenziali sottratte potrebbe sfruttare per registrare il proprio 2FA).
app.delete('/api/2fa/credentials/:credId', requireAuth, async (req, res, next) => {
    try {
        const credIdToDelete = req.params.credId;

        // 1) Pre-check: conta i metodi 2FA attuali
        let methods = [];
        try {
            const credsResp = await userApi(req, ASP_API_BASE, '/credentials', {});
            const creds = Array.isArray(credsResp) ? credsResp : (credsResp.credentials || []);
            methods = creds.filter(c => {
                const t = (c.type || '').toLowerCase();
                if (t === 'webauthn' || t === 'webauthn-passwordless') return true;
                if (t === 'otp') return true;
                if (t === CREDENTIAL_TYPE_OTP_CHANNEL) {
                    const label = (c.userLabel || '').toLowerCase();
                    return label.includes('email') || label.includes('mail');
                }
                return false;
            });
        } catch (_) { /* se fallisce il pre-check, prosegui con la rimozione */ }

        // 2) Verifica se il credential da rimuovere e' un metodo 2FA E sarebbe l'ultimo
        const isTarget2fa = methods.some(m => m.id === credIdToDelete);
        if (isTarget2fa && methods.length <= 1) {
            return res.status(409).json({
                ok: false,
                error: 'last_2fa_method',
                message: 'Devi avere almeno un metodo di sicurezza (2FA) attivo. Aggiungi un nuovo metodo prima di rimuovere questo.',
            });
        }

        // 3) Procedi con la rimozione
        await userAccountApi(req, `/credentials/${encodeURIComponent(credIdToDelete)}`, {
            method: 'DELETE',
        });

        const remaining2fa = isTarget2fa ? methods.length - 1 : methods.length;
        res.json({ ok: true, remaining2fa });
    } catch (e) { next(e); }
});

function buildLogoutUrl(req) {
    const idToken = req.session.tokens?.id_token;
    const params = new URLSearchParams({
        client_id: CLIENT_ID,
        post_logout_redirect_uri: APP_PUBLIC_URL + BASE_PATH + '/',
    });
    if (idToken) params.set('id_token_hint', idToken);
    return `${KEYCLOAK_ISSUER}/protocol/openid-connect/logout?${params.toString()}`;
}

// Endpoint per RINOMINARE la label di un credential (Account API supporta PUT label)
app.put('/api/2fa/credentials/:credId/label', requireAuth, async (req, res, next) => {
    try {
        const label = String(req.body.label || '').slice(0, 80);
        await userAccountApi(req, `/credentials/${encodeURIComponent(req.params.credId)}/label`, {
            method: 'PUT',
            headers: { 'Content-Type': 'text/plain' },
            body: label,
        });
        res.json({ ok: true });
    } catch (e) { next(e); }
});

// Pulsante UNICO "Aggiungi nuovo metodo 2FA". Redirect a Keycloak con
// kc_action=asp-pick-2fa-method (mini-flow custom che mostra la pagina di
// scelta e gestisce inline il setup di tutti i metodi).
app.get('/api/2fa/add', requireAuth, async (req, res, next) => {
    console.log('[/api/2fa/add] user=', req.session.tokens?.access_token ? '(autenticato)' : '(NO TOKEN)', 'redirect a kc_action=asp-pick-2fa-method');
    req.session.returnTo = `${BASE_PATH}/`;
    try {
        await startOidc(req, res, {
            kc_action: 'asp-pick-2fa-method',
            prompt: 'login',
        });
    } catch (e) { next(e); }
});

app.get('/api/2fa/add/:method', requireAuth, async (req, res, next) => {
    console.log('[/api/2fa/add/:method] method=', req.params.method, 'redirect a kc_action=asp-pick-2fa-method');
    req.session.returnTo = `${BASE_PATH}/`;
    try {
        await startOidc(req, res, {
            kc_action: 'asp-pick-2fa-method',
            prompt: 'login',
        });
    } catch (e) { next(e); }
});

// ------------------------------------------------------------------
// Static + SPA fallback
// ------------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public'), { index: false }));

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handler
app.use((err, req, res, next) => {
    console.error('[ERR]', err && err.stack ? err.stack : err);
    if (res.headersSent) return next(err);
    const status = err.status || 500;
    if (req.accepts('html') && !req.path.startsWith('/api/')) {
        res.status(status).sendFile(path.join(__dirname, 'public', 'error.html'));
    } else {
        res.status(status).json({ error: 'internal_error', message: err.message });
    }
});

app.listen(PORT, () => {
    console.log(`==> listening on http://0.0.0.0:${PORT}`);
});
