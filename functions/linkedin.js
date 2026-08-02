"use strict";

/**
 * Cliente de la API de LinkedIn.
 * Usa fetch nativo (Node 20). Nunca loguea tokens completos.
 */

const { ERR, fail, redactSecrets } = require("./util");

const OAUTH_AUTHORIZE = "https://www.linkedin.com/oauth/v2/authorization";
const OAUTH_TOKEN = "https://www.linkedin.com/oauth/v2/accessToken";
const API_BASE = "https://api.linkedin.com";

// Scopes mínimos para perfil + publicación como miembro.
const MEMBER_SCOPES = ["openid", "profile", "email", "w_member_social"];
// Scopes adicionales para páginas/organizaciones (requieren aprobación de LinkedIn).
const ORG_SCOPES = ["r_organization_admin", "w_organization_social", "rw_organization_admin"];

function apiVersion() {
  return process.env.LINKEDIN_API_VERSION || "202606";
}

function restHeaders(accessToken) {
  return {
    Authorization: `Bearer ${accessToken}`,
    "Content-Type": "application/json",
    "X-Restli-Protocol-Version": "2.0.0",
    "LinkedIn-Version": apiVersion(),
  };
}

/**
 * Construye la URL de autorización OAuth 2.0 (Authorization Code Flow).
 * @param {string} state  token anti-CSRF
 * @param {boolean} includeOrg  si pedir también scopes de organización
 */
function buildAuthUrl(state, includeOrg = false) {
  const clientId = process.env.LINKEDIN_CLIENT_ID;
  const redirectUri = process.env.LINKEDIN_REDIRECT_URI;
  if (!clientId || !redirectUri) {
    throw fail(ERR.CONFIG_MISSING, "Falta LINKEDIN_CLIENT_ID o LINKEDIN_REDIRECT_URI");
  }
  const scopes = includeOrg ? MEMBER_SCOPES.concat(ORG_SCOPES) : MEMBER_SCOPES;
  const params = new URLSearchParams({
    response_type: "code",
    client_id: clientId,
    redirect_uri: redirectUri,
    state,
    scope: scopes.join(" "),
  });
  return `${OAUTH_AUTHORIZE}?${params.toString()}`;
}

/** Intercambia el `code` por un access_token. SOLO se llama desde backend. */
async function exchangeCodeForToken(code) {
  const clientId = process.env.LINKEDIN_CLIENT_ID;
  const clientSecret = process.env.LINKEDIN_CLIENT_SECRET;
  const redirectUri = process.env.LINKEDIN_REDIRECT_URI;
  if (!clientId || !clientSecret || !redirectUri) {
    throw fail(ERR.CONFIG_MISSING, "Configuración OAuth incompleta");
  }

  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code,
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uri: redirectUri,
  });

  const res = await fetch(OAUTH_TOKEN, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body,
  });

  if (!res.ok) {
    const detail = await safeText(res);
    throw fail(ERR.LINKEDIN_AUTH_FAILED, `Token exchange falló: ${res.status} ${detail}`);
  }
  const json = await res.json();
  return {
    accessToken: json.access_token,
    expiresInSec: json.expires_in,
    scope: json.scope,
    refreshToken: json.refresh_token || null,
    refreshExpiresInSec: json.refresh_token_expires_in || null,
  };
}

/** Obtiene el perfil OpenID del miembro (sub = id del miembro). */
async function getUserInfo(accessToken) {
  const res = await fetch(`${API_BASE}/v2/userinfo`, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (res.status === 401) throw fail(ERR.LINKEDIN_AUTH_FAILED, "userinfo 401");
  if (!res.ok) throw fail(ERR.UNKNOWN_ERROR, `userinfo ${res.status}`);
  const j = await res.json();
  return {
    memberId: j.sub,
    name: j.name || null,
    email: j.email || null,
    picture: j.picture || null,
    locale: j.locale || null,
  };
}

/**
 * Lista organizaciones donde el miembro es administrador.
 * Requiere scope r_organization_admin / rw_organization_admin.
 * Si falta permiso -> PERMISSION_REQUIRED.
 */
async function getOrganizations(accessToken) {
  const url =
    `${API_BASE}/v2/organizationAcls?q=roleAssignee&role=ADMINISTRATOR&state=APPROVED` +
    `&projection=(elements*(organization~(id,localizedName)))`;
  const res = await fetch(url, { headers: restHeaders(accessToken) });

  if (res.status === 403) {
    throw fail(ERR.PERMISSION_REQUIRED, "organizationAcls 403 (scopes de organización faltantes)");
  }
  if (res.status === 401) throw fail(ERR.TOKEN_EXPIRED, "organizationAcls 401");
  if (!res.ok) {
    const detail = await safeText(res);
    throw fail(ERR.UNKNOWN_ERROR, `organizationAcls ${res.status} ${detail}`);
  }
  const j = await res.json();
  const elements = Array.isArray(j.elements) ? j.elements : [];
  return elements
    .map((el) => {
      const org = el["organization~"] || {};
      const rawId = el.organization || "";
      const id = org.id || (typeof rawId === "string" ? rawId.split(":").pop() : null);
      return id ? { id: String(id), name: org.localizedName || `Organización ${id}` } : null;
    })
    .filter(Boolean);
}

/**
 * Publica un post (texto) usando la API REST /rest/posts.
 * @param {string} authorUrn  urn:li:person:{id} o urn:li:organization:{id}
 * @returns {string} URN del post creado
 */
async function publishPost(accessToken, authorUrn, text) {
  const payload = {
    author: authorUrn,
    commentary: text,
    visibility: "PUBLIC",
    distribution: {
      feedDistribution: "MAIN_FEED",
      targetEntities: [],
      thirdPartyDistributionChannels: [],
    },
    lifecycleState: "PUBLISHED",
    isReshareDisabledByAuthor: false,
  };

  const res = await fetch(`${API_BASE}/rest/posts`, {
    method: "POST",
    headers: restHeaders(accessToken),
    body: JSON.stringify(payload),
  });

  if (res.status === 401) throw fail(ERR.TOKEN_EXPIRED, "posts 401");
  if (res.status === 403) throw fail(ERR.PERMISSION_REQUIRED, "posts 403 (sin permiso para este autor)");
  if (res.status !== 201 && !res.ok) {
    const detail = await safeText(res);
    throw fail(ERR.UNKNOWN_ERROR, `posts ${res.status} ${detail}`);
  }
  // El URN del post viene en el header x-restli-id
  return res.headers.get("x-restli-id") || res.headers.get("x-linkedin-id") || null;
}

/**
 * Intenta obtener analíticas de una organización.
 * Las analíticas a nivel de MIEMBRO no están disponibles por API pública.
 * Si no hay permisos -> PERMISSION_REQUIRED. Si no se soporta -> UNSUPPORTED_ANALYTICS.
 * NUNCA inventa métricas.
 */
async function getOrganizationAnalytics(accessToken, organizationId) {
  const orgUrn = encodeURIComponent(`urn:li:organization:${organizationId}`);
  const url =
    `${API_BASE}/rest/organizationalEntityShareStatistics` +
    `?q=organizationalEntity&organizationalEntity=${orgUrn}`;
  const res = await fetch(url, { headers: restHeaders(accessToken) });

  if (res.status === 403) throw fail(ERR.PERMISSION_REQUIRED, "shareStatistics 403");
  if (res.status === 401) throw fail(ERR.TOKEN_EXPIRED, "shareStatistics 401");
  if (res.status === 404 || res.status === 400) {
    throw fail(ERR.UNSUPPORTED_ANALYTICS, `shareStatistics ${res.status}`);
  }
  if (!res.ok) {
    const detail = await safeText(res);
    throw fail(ERR.UNKNOWN_ERROR, `shareStatistics ${res.status} ${detail}`);
  }
  const j = await res.json();
  const elements = Array.isArray(j.elements) ? j.elements : [];
  // Devuelve SOLO lo que la API entrega realmente.
  return elements.map((el) => {
    const s = el.totalShareStatistics || {};
    return {
      impressions: numOrNull(s.impressionCount),
      clicks: numOrNull(s.clickCount),
      likes: numOrNull(s.likeCount),
      comments: numOrNull(s.commentCount),
      shares: numOrNull(s.shareCount),
      engagement: numOrNull(s.engagement),
    };
  });
}

// --- helpers internos ---
async function safeText(res) {
  try {
    const t = await res.text();
    return redactSecrets(t).slice(0, 500);
  } catch (_) {
    return "(sin cuerpo)";
  }
}
function numOrNull(v) {
  return typeof v === "number" ? v : null;
}

module.exports = {
  MEMBER_SCOPES,
  ORG_SCOPES,
  buildAuthUrl,
  exchangeCodeForToken,
  getUserInfo,
  getOrganizations,
  publishPost,
  getOrganizationAnalytics,
};
