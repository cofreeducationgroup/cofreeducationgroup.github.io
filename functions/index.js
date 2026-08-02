"use strict";

/**
 * ============================================================================
 *  COFRÉ Education Group · Módulo "LinkedIn Center"
 *  Cloud Functions (2ª gen) · Node 20
 *
 *  Seguridad:
 *   - El intercambio OAuth code->token ocurre SOLO aquí (backend).
 *   - El CLIENT_SECRET y la clave de cifrado viven como Firebase Secrets.
 *   - Los tokens se guardan CIFRADOS (AES-256-GCM) y nunca se devuelven al cliente.
 *   - Cada función privada valida Firebase Auth (request.auth.uid).
 *   - Las reglas de Firestore impiden que el cliente lea tokens.
 * ============================================================================
 */

const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall, onRequest } = require("firebase-functions/v2/https");
const { onSchedule } = require("firebase-functions/v2/scheduler");
const { defineSecret } = require("firebase-functions/params");
const { beforeUserSignedIn, HttpsError: IdentityError } = require("firebase-functions/v2/identity");
const { initializeApp } = require("firebase-admin/app");
const { getFirestore, FieldValue, Timestamp } = require("firebase-admin/firestore");

const {
  ERR,
  fail,
  requireAuth,
  encrypt,
  decrypt,
  randomToken,
  isExpired,
} = require("./util");
const li = require("./linkedin");
const { generateContentIdeas } = require("./ai");
const { identifyBookFromCover } = require("./books");

initializeApp();
const db = getFirestore();

setGlobalOptions({ region: "us-central1", maxInstances: 10 });

// --- Secretos (configurar con `firebase functions:secrets:set ...`) ---
const LINKEDIN_CLIENT_SECRET = defineSecret("LINKEDIN_CLIENT_SECRET");
const TOKEN_ENCRYPTION_KEY = defineSecret("TOKEN_ENCRYPTION_KEY");
// OPENAI_API_KEY es OPCIONAL: si no está, las ideas se generan localmente.
// Para activarlo, configúralo en functions/.env o como secret y se leerá por process.env.

// ---------------------------------------------------------------------------
//  Helpers de datos
// ---------------------------------------------------------------------------
const connectionRef = (uid) => db.doc(`users/${uid}/linkedin/connection`);

/** Carga la conexión activa y devuelve el access token descifrado. */
async function getActiveToken(uid) {
  const snap = await connectionRef(uid).get();
  if (!snap.exists) throw fail(ERR.NOT_CONNECTED);
  const c = snap.data();
  if (c.status === "disconnected") throw fail(ERR.NOT_CONNECTED);
  if (c.status === "expired" || isExpired(c.expiresAt)) {
    await connectionRef(uid).set({ status: "expired", updatedAt: FieldValue.serverTimestamp() }, { merge: true });
    throw fail(ERR.TOKEN_EXPIRED);
  }
  if (!c.accessTokenEncrypted) throw fail(ERR.NOT_CONNECTED);
  const accessToken = decrypt(c.accessTokenEncrypted);
  return { accessToken, memberId: c.linkedinMemberId, scopes: c.scopes || [], connection: c };
}

/** Construye el URN de autor validando permisos para organizaciones. */
function buildAuthorUrn(target, memberId, organizationId, scopes) {
  if (target === "organization") {
    if (!organizationId) throw fail(ERR.INSUFFICIENT_DATA, "Falta organizationId");
    const hasOrgScope = scopes.includes("w_organization_social") || scopes.includes("rw_organization_admin");
    if (!hasOrgScope) throw fail(ERR.PERMISSION_REQUIRED, "Sin scope de organización para publicar");
    return `urn:li:organization:${organizationId}`;
  }
  if (!memberId) throw fail(ERR.LINKEDIN_AUTH_FAILED, "Sin memberId");
  return `urn:li:person:${memberId}`;
}

function normalizeOrganizationId(raw) {
  const organizationId = String(raw || "").trim();
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(organizationId)) {
    throw fail(ERR.INSUFFICIENT_DATA, "organizationId inválido");
  }
  return organizationId;
}

async function requireOwnedOrganization(uid, rawOrganizationId) {
  const organizationId = normalizeOrganizationId(rawOrganizationId);
  const snap = await db.doc(`users/${uid}/linkedinOrganizations/${organizationId}`).get();
  if (!snap.exists || (snap.data() && snap.data().status !== "active")) {
    throw fail(ERR.PERMISSION_REQUIRED, "Organización no verificada para este usuario");
  }
  return organizationId;
}

// ===========================================================================
//  1) linkedinStartAuth  — inicia el flujo OAuth
// ===========================================================================
exports.linkedinStartAuth = onCall(async (request) => {
  const uid = requireAuth(request);
  if (!process.env.LINKEDIN_CLIENT_ID || !process.env.LINKEDIN_REDIRECT_URI) {
    throw fail(ERR.CONFIG_MISSING, "LINKEDIN_CLIENT_ID / REDIRECT_URI ausentes");
  }
  const includeOrg = request.data && request.data.includeOrg === true;
  const state = randomToken(24);

  await db.doc(`oauthStates/${state}`).set({
    uid,
    includeOrg,
    provider: "linkedin",
    createdAt: FieldValue.serverTimestamp(),
    expiresAt: Date.now() + 10 * 60 * 1000, // 10 minutos
  });

  const authUrl = li.buildAuthUrl(state, includeOrg);
  return { authUrl };
});

// ===========================================================================
//  2) linkedinOAuthCallback — LinkedIn redirige aquí con ?code&state
//     (HTTP público; valida state; intercambia token; redirige al frontend)
// ===========================================================================
exports.linkedinOAuthCallback = onRequest(
  { secrets: [LINKEDIN_CLIENT_SECRET, TOKEN_ENCRYPTION_KEY] },
  async (req, res) => {
    const returnUrl = process.env.LINKEDIN_FRONTEND_RETURN_URL || "/";
    const redirectBack = (params) => {
      const qs = new URLSearchParams(params).toString();
      res.redirect(`${returnUrl}?${qs}`);
    };

    try {
      const { code, state, error, error_description } = req.query;

      if (error) {
        // El usuario canceló o LinkedIn devolvió error de autorización
        console.error("[oauthCallback] LinkedIn error:", error, error_description);
        return redirectBack({ linkedin: "error", code: ERR.LINKEDIN_AUTH_FAILED });
      }
      if (!code || !state) {
        return redirectBack({ linkedin: "error", code: ERR.INSUFFICIENT_DATA });
      }

      // Validar y consumir el state (anti-CSRF)
      const stateRef = db.doc(`oauthStates/${state}`);
      const stateSnap = await stateRef.get();
      if (!stateSnap.exists) {
        return redirectBack({ linkedin: "error", code: ERR.LINKEDIN_AUTH_FAILED });
      }
      const stateData = stateSnap.data();
      await stateRef.delete(); // un solo uso
      if (isExpired(stateData.expiresAt)) {
        return redirectBack({ linkedin: "error", code: ERR.LINKEDIN_AUTH_FAILED });
      }
      const uid = stateData.uid;

      // Intercambio seguro code -> token (con CLIENT_SECRET)
      const token = await li.exchangeCodeForToken(String(code));
      const profile = await li.getUserInfo(token.accessToken);

      const scopes = token.scope ? token.scope.split(/[ ,]+/).filter(Boolean) : li.MEMBER_SCOPES;
      const expiresAt = Date.now() + (Number(token.expiresInSec) || 0) * 1000;

      await connectionRef(uid).set(
        {
          provider: "linkedin",
          linkedinMemberId: profile.memberId,
          accessTokenEncrypted: encrypt(token.accessToken),
          refreshTokenEncrypted: token.refreshToken ? encrypt(token.refreshToken) : null,
          expiresAt,
          scopes,
          // Snapshot NO sensible para mostrar en la UI
          profileName: profile.name,
          profilePicture: profile.picture,
          profileEmail: profile.email,
          status: "active",
          createdAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      return redirectBack({ linkedin: "connected" });
    } catch (e) {
      const code = (e && e.details && e.details.code) || ERR.UNKNOWN_ERROR;
      console.error("[oauthCallback] fallo:", code, String(e && e.message));
      return redirectBack({ linkedin: "error", code });
    }
  }
);

// ===========================================================================
//  3) linkedinDisconnect
// ===========================================================================
exports.linkedinDisconnect = onCall(async (request) => {
  const uid = requireAuth(request);
  await connectionRef(uid).set(
    {
      status: "disconnected",
      accessTokenEncrypted: FieldValue.delete(),
      refreshTokenEncrypted: FieldValue.delete(),
      updatedAt: FieldValue.serverTimestamp(),
    },
    { merge: true }
  );
  return { status: "disconnected" };
});

// ===========================================================================
//  4) linkedinGetProfile — estado de conexión + datos seguros (sin token)
// ===========================================================================
exports.linkedinGetProfile = onCall(async (request) => {
  const uid = requireAuth(request);
  const snap = await connectionRef(uid).get();
  if (!snap.exists) {
    return { status: "disconnected", profile: null };
  }
  const c = snap.data();
  const expired = c.status === "active" && isExpired(c.expiresAt);
  return {
    status: expired ? "expired" : c.status,
    profile: {
      memberId: c.linkedinMemberId || null,
      name: c.profileName || null,
      picture: c.profilePicture || null,
      email: c.profileEmail || null,
    },
    scopes: c.scopes || [],
    expiresAt: c.expiresAt || null,
  };
});

// ===========================================================================
//  5) linkedinGetOrganizations
// ===========================================================================
exports.linkedinGetOrganizations = onCall(
  { secrets: [TOKEN_ENCRYPTION_KEY] },
  async (request) => {
    const uid = requireAuth(request);
    const { accessToken } = await getActiveToken(uid);
    const orgs = await li.getOrganizations(accessToken); // puede lanzar PERMISSION_REQUIRED

    // Cachear en Firestore (solo lectura para el cliente)
    const batch = db.batch();
    orgs.forEach((o) => {
      const ref = db.doc(`users/${uid}/linkedinOrganizations/${o.id}`);
      batch.set(ref, {
        organizationId: o.id,
        name: o.name,
        status: "active",
        updatedAt: FieldValue.serverTimestamp(),
        createdAt: FieldValue.serverTimestamp(),
      }, { merge: true });
    });
    await batch.commit();

    return { organizations: orgs };
  }
);

// ===========================================================================
//  6) linkedinCreatePost — guarda borrador o publica ahora (con confirmación)
//     data: { text, target: 'person'|'organization', organizationId?, action: 'draft'|'publish', confirm? }
// ===========================================================================
exports.linkedinCreatePost = onCall(
  { secrets: [TOKEN_ENCRYPTION_KEY] },
  async (request) => {
    const uid = requireAuth(request);
    const data = request.data || {};
    const text = (data.text || "").trim();
    const target = data.target === "organization" ? "organization" : "person";
    const action = data.action === "publish" ? "publish" : "draft";

    if (!text) throw fail(ERR.INSUFFICIENT_DATA, "El texto del post está vacío");
    const organizationId = target === "organization" && data.organizationId
      ? await requireOwnedOrganization(uid, data.organizationId)
      : null;

    if (action === "draft") {
      const ref = await db.collection(`users/${uid}/linkedinDrafts`).add({
        text,
        target,
        organizationId,
        status: "active",
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      return { saved: true, draftId: ref.id };
    }

    // action === 'publish' -> requiere confirmación explícita del usuario
    if (data.confirm !== true) {
      throw fail(ERR.INSUFFICIENT_DATA, "Falta confirmación explícita para publicar");
    }
    const { accessToken, memberId, scopes } = await getActiveToken(uid);
    const authorUrn = buildAuthorUrn(target, memberId, organizationId, scopes);

    let postUrn;
    try {
      postUrn = await li.publishPost(accessToken, authorUrn, text);
    } catch (e) {
      await db.collection(`users/${uid}/linkedinDrafts`).add({
        text, target, organizationId,
        status: "failed",
        lastError: (e && e.details && e.details.code) || ERR.UNKNOWN_ERROR,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      throw e;
    }

    await db.collection(`users/${uid}/linkedinDrafts`).add({
      text, target, organizationId,
      status: "published",
      postUrn: postUrn || null,
      publishedAt: FieldValue.serverTimestamp(),
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    return { published: true, postUrn: postUrn || null };
  }
);

// ===========================================================================
//  7) linkedinSchedulePost
//     data: { text, target, organizationId?, scheduledAt (ISO o ms) }
// ===========================================================================
exports.linkedinSchedulePost = onCall(async (request) => {
  const uid = requireAuth(request);
  const data = request.data || {};
  const text = (data.text || "").trim();
  const target = data.target === "organization" ? "organization" : "person";

  if (!text) throw fail(ERR.INSUFFICIENT_DATA, "El texto del post está vacío");
  const when = new Date(data.scheduledAt);
  if (isNaN(when.getTime()) || when.getTime() <= Date.now()) {
    throw fail(ERR.INSUFFICIENT_DATA, "La fecha de programación debe ser futura y válida");
  }
  const organizationId = target === "organization"
    ? await requireOwnedOrganization(uid, data.organizationId)
    : null;

  const ref = await db.collection(`users/${uid}/linkedinScheduledPosts`).add({
    text,
    target,
    organizationId,
    scheduledAt: Timestamp.fromDate(when),
    status: "scheduled",
    createdAt: FieldValue.serverTimestamp(),
    updatedAt: FieldValue.serverTimestamp(),
  });
  return { scheduled: true, postId: ref.id, scheduledAt: when.toISOString() };
});

// ===========================================================================
//  8) linkedinPublishScheduledPosts — ejecución programada (cada 5 min)
// ===========================================================================
exports.linkedinPublishScheduledPosts = onSchedule(
  { schedule: "every 5 minutes", secrets: [TOKEN_ENCRYPTION_KEY] },
  async () => {
    const now = Timestamp.now();
    const due = await db
      .collectionGroup("linkedinScheduledPosts")
      .where("status", "==", "scheduled")
      .where("scheduledAt", "<=", now)
      .limit(20)
      .get();

    for (const doc of due.docs) {
      const post = doc.data();
      const uid = doc.ref.parent.parent && doc.ref.parent.parent.id;
      try {
        if (!uid) throw fail(ERR.UNKNOWN_ERROR, "uid no resuelto");
        const { accessToken, memberId, scopes } = await getActiveToken(uid);
        const authorUrn = buildAuthorUrn(post.target, memberId, post.organizationId, scopes);
        const postUrn = await li.publishPost(accessToken, authorUrn, post.text);
        await doc.ref.set({
          status: "published",
          postUrn: postUrn || null,
          publishedAt: FieldValue.serverTimestamp(),
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      } catch (e) {
        const code = (e && e.details && e.details.code) || ERR.UNKNOWN_ERROR;
        console.error(`[scheduler] fallo post ${doc.id}:`, code);
        await doc.ref.set({
          status: "failed",
          lastError: code, // código seguro, nunca el token
          updatedAt: FieldValue.serverTimestamp(),
        }, { merge: true });
      }
    }
    return;
  }
);

// ===========================================================================
//  9) linkedinGetAnalytics
//     data: { organizationId? }  — analítica de organización (la de miembro no
//     está soportada por la API pública -> UNSUPPORTED_ANALYTICS)
// ===========================================================================
exports.linkedinGetAnalytics = onCall(
  { secrets: [TOKEN_ENCRYPTION_KEY] },
  async (request) => {
    const uid = requireAuth(request);
    const data = request.data || {};
    if (!data.organizationId) {
      // Analíticas de perfil personal no disponibles por API
      throw fail(ERR.UNSUPPORTED_ANALYTICS, "Member analytics no soportado por API");
    }
    const { accessToken } = await getActiveToken(uid);
    const rows = await li.getOrganizationAnalytics(accessToken, data.organizationId);

    await db.collection(`users/${uid}/linkedinAnalytics`).add({
      organizationId: data.organizationId,
      rows,
      status: "active",
      createdAt: FieldValue.serverTimestamp(),
      updatedAt: FieldValue.serverTimestamp(),
    });

    return { status: "available", rows };
  }
);

// ===========================================================================
//  10) linkedinGenerateContentIdeas
// ===========================================================================
exports.linkedinGenerateContentIdeas = onCall(
  async (request) => {
    requireAuth(request);
    const count = Math.min(Math.max(Number(request.data && request.data.count) || 5, 1), 8);
    const { source, ideas } = await generateContentIdeas(count);
    return { source, ideas };
  }
);

// ===========================================================================
//  Inventario de Oficina · identifyBookCover
//  Identifica un libro a partir de una foto de su portada (IA de visión).
// ===========================================================================
exports.identifyBookCover = onCall(async (request) => {
  requireAuth(request);
  const imageBase64 = request.data && request.data.imageBase64;
  return identifyBookFromCover(imageBase64);
});

// ===========================================================================
//  11) getEducationNews — últimas noticias educativas
//      Real, gratis, sin IA. Se lee en el backend para evitar CORS.
//      Fuente: Google Noticias RSS (requiere User-Agent de navegador real;
//      con UA de bot devuelve HTTP 503 desde IPs de servidor).
//      data: { topic?: 'general'|'legislacion'|'mineduc'|'superior' }
// ===========================================================================
const NEWS_QUERIES = {
  general: "educación Chile",
  legislacion: "ley educación Chile OR reforma educacional Chile",
  mineduc: "MINEDUC Chile",
  superior: "educación superior Chile",
};

const NEWS_UA =
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 " +
  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36";

const NEWS_TTL_MS = 30 * 60 * 1000; // 30 minutos
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Descarga noticias de Google con reintentos ante 503/429. Devuelve items o null. */
async function fetchGoogleNews(topicKey) {
  const q = NEWS_QUERIES[topicKey] || NEWS_QUERIES.general;
  const url =
    `https://news.google.com/rss/search?q=${encodeURIComponent(q)}` +
    `&hl=es-419&gl=CL&ceid=CL:es`;
  for (let attempt = 0; attempt < 4; attempt++) {
    try {
      const res = await fetch(url, {
        headers: {
          "User-Agent": NEWS_UA,
          Accept: "application/rss+xml, application/xml;q=0.9, */*;q=0.8",
          "Accept-Language": "es-CL,es;q=0.9",
        },
      });
      if (res.status === 503 || res.status === 429) { await sleep(600 * (attempt + 1)); continue; }
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const xml = await res.text();
      const items = parseRssItems(xml).slice(0, 12);
      if (items.length) return items;
    } catch (e) {
      await sleep(400);
    }
  }
  return null;
}

/** Devuelve noticias del tema usando caché Firestore (30 min) con fallback a caché vieja. */
async function getNewsCached(topicKey) {
  const ref = db.doc(`newsCache/${topicKey}`);
  const snap = await ref.get();
  const cache = snap.exists ? snap.data() : null;
  const fresh = cache && cache.fetchedAt && (Date.now() - cache.fetchedAt) < NEWS_TTL_MS &&
    Array.isArray(cache.items) && cache.items.length;
  if (fresh) return { items: cache.items, cached: true };

  const fetched = await fetchGoogleNews(topicKey);
  if (fetched) {
    await ref.set({ items: fetched, fetchedAt: Date.now(), topic: topicKey, updatedAt: FieldValue.serverTimestamp() });
    return { items: fetched, cached: false };
  }
  // Si Google falla pero hay caché previa (aunque vieja), la usamos.
  if (cache && Array.isArray(cache.items) && cache.items.length) {
    return { items: cache.items, cached: true, stale: true };
  }
  return null;
}

exports.getEducationNews = onCall(async (request) => {
  requireAuth(request);
  const topic = NEWS_QUERIES[request.data && request.data.topic] ? request.data.topic : "general";
  const result = await getNewsCached(topic);
  if (!result) throw fail(ERR.UNKNOWN_ERROR, "news: sin resultados ni caché");
  return { topic, items: result.items, cached: !!result.cached, stale: !!result.stale };
});

// Refresca la caché de noticias cada 30 min (mantiene el feed "caliente" sin 503).
exports.refreshEducationNews = onSchedule({ schedule: "every 30 minutes" }, async () => {
  for (const topicKey of Object.keys(NEWS_QUERIES)) {
    const items = await fetchGoogleNews(topicKey);
    if (items) {
      await db.doc(`newsCache/${topicKey}`).set({
        items, fetchedAt: Date.now(), topic: topicKey, updatedAt: FieldValue.serverTimestamp(),
      });
    }
    await sleep(1000); // espacia peticiones para no gatillar rate-limit
  }
});

function parseRssItems(xml) {
  const items = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/g;
  let m;
  while ((m = itemRegex.exec(xml)) !== null) {
    const block = m[1];
    const get = (tag) => {
      const r = new RegExp(`<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`);
      const mm = r.exec(block);
      return mm ? mm[1] : "";
    };
    let title = decodeXmlText(get("title"));
    const link = decodeXmlText(get("link"));
    const pubDate = get("pubDate").trim();
    // Google expone la fuente en <source> y además agrega " - Fuente" al título.
    let source = decodeXmlText(get("source"));
    if (title.includes(" - ")) {
      const idx = title.lastIndexOf(" - ");
      const tail = title.slice(idx + 3).trim();
      if (!source) source = tail;
      title = title.slice(0, idx).trim();
    }
    if (title && link) items.push({ title, link, source, pubDate });
  }
  return items;
}

function decodeXmlText(s) {
  return String(s)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, "$1")
    .replace(/<[^>]+>/g, "")
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => safeCodePoint(parseInt(h, 16)))
    .replace(/&#(\d+);/g, (_, n) => safeCodePoint(parseInt(n, 10)))
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&apos;/g, "'")
    .replace(/&amp;/g, "&")
    .trim();
}

function safeCodePoint(n) {
  try { return String.fromCodePoint(n); } catch (_) { return ""; }
}

// ===========================================================================
//  Control de acceso: solo correos autorizados pueden iniciar sesión.
//  Se ejecuta ANTES de crear la sesión (Google y email/contraseña).
//  - SUPER_ADMINS: correos del dueño, SIEMPRE permitidos (evita auto-bloqueo).
//  - Lista adicional editable en Firestore: config/allowlist -> { emails: [...] }
// ===========================================================================
const SUPER_ADMINS = [
  "felipe@cofreeducationgroup.cl",
  "cofregonzalezf@gmail.com",
];

exports.enforceAllowlist = beforeUserSignedIn(async (event) => {
  const email = String((event.data && event.data.email) || "").toLowerCase().trim();
  if (!email) {
    throw new IdentityError("permission-denied", "Cuenta sin correo válido.");
  }
  if (SUPER_ADMINS.includes(email)) return; // dueño: siempre permitido

  let allowed = [];
  try {
    const snap = await db.doc("config/allowlist").get();
    if (snap.exists && Array.isArray(snap.data().emails)) {
      allowed = snap.data().emails.map((e) => String(e).toLowerCase().trim());
    }
  } catch (_) { /* si falla la lectura, solo pasan los super admins */ }

  if (!allowed.includes(email)) {
    throw new IdentityError(
      "permission-denied",
      "Tu correo no está autorizado para acceder a esta área privada."
    );
  }
});

