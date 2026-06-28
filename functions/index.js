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

    if (action === "draft") {
      const ref = await db.collection(`users/${uid}/linkedinDrafts`).add({
        text,
        target,
        organizationId: data.organizationId || null,
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
    const authorUrn = buildAuthorUrn(target, memberId, data.organizationId, scopes);

    let postUrn;
    try {
      postUrn = await li.publishPost(accessToken, authorUrn, text);
    } catch (e) {
      await db.collection(`users/${uid}/linkedinDrafts`).add({
        text, target, organizationId: data.organizationId || null,
        status: "failed",
        lastError: (e && e.details && e.details.code) || ERR.UNKNOWN_ERROR,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
      throw e;
    }

    await db.collection(`users/${uid}/linkedinDrafts`).add({
      text, target, organizationId: data.organizationId || null,
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

  const ref = await db.collection(`users/${uid}/linkedinScheduledPosts`).add({
    text,
    target,
    organizationId: data.organizationId || null,
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
