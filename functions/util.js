"use strict";

/**
 * Utilidades compartidas: errores tipados, cifrado de tokens y helpers.
 */

const crypto = require("crypto");
const { HttpsError } = require("firebase-functions/v2/https");

// ---------------------------------------------------------------------------
//  Códigos de error de negocio (contrato con el frontend)
// ---------------------------------------------------------------------------
const ERR = {
  CONFIG_MISSING: "CONFIG_MISSING",
  AUTH_REQUIRED: "AUTH_REQUIRED",
  LINKEDIN_AUTH_FAILED: "LINKEDIN_AUTH_FAILED",
  PERMISSION_REQUIRED: "PERMISSION_REQUIRED",
  UNSUPPORTED_ANALYTICS: "UNSUPPORTED_ANALYTICS",
  INSUFFICIENT_DATA: "INSUFFICIENT_DATA",
  TOKEN_EXPIRED: "TOKEN_EXPIRED",
  NOT_CONNECTED: "NOT_CONNECTED",
  UNKNOWN_ERROR: "UNKNOWN_ERROR",
};

// Mensajes públicos seguros (nunca incluyen datos técnicos sensibles)
const PUBLIC_MESSAGES = {
  CONFIG_MISSING: "El servicio no está configurado correctamente. Contacta al administrador.",
  AUTH_REQUIRED: "Debes iniciar sesión para realizar esta acción.",
  LINKEDIN_AUTH_FAILED: "LinkedIn rechazó la sesión. Vuelve a conectar tu cuenta.",
  PERMISSION_REQUIRED: "Tu app de LinkedIn no tiene los permisos necesarios para esta operación.",
  UNSUPPORTED_ANALYTICS: "Esta analítica no está disponible a través de la API de LinkedIn.",
  INSUFFICIENT_DATA: "Faltan datos para completar la operación.",
  TOKEN_EXPIRED: "Tu conexión con LinkedIn expiró. Vuelve a conectar tu cuenta.",
  NOT_CONNECTED: "No tienes una cuenta de LinkedIn conectada.",
  UNKNOWN_ERROR: "Ocurrió un error inesperado. Inténtalo nuevamente.",
};

// Mapea el código de negocio a la categoría de HttpsError de Firebase
const HTTPS_CATEGORY = {
  CONFIG_MISSING: "failed-precondition",
  AUTH_REQUIRED: "unauthenticated",
  LINKEDIN_AUTH_FAILED: "unauthenticated",
  PERMISSION_REQUIRED: "permission-denied",
  UNSUPPORTED_ANALYTICS: "unimplemented",
  INSUFFICIENT_DATA: "invalid-argument",
  TOKEN_EXPIRED: "unauthenticated",
  NOT_CONNECTED: "failed-precondition",
  UNKNOWN_ERROR: "internal",
};

/**
 * Lanza un HttpsError estandarizado para funciones onCall.
 * `code` es uno de ERR.*; el frontend lo lee en error.details.code.
 */
function fail(code, technicalLog) {
  if (technicalLog) {
    // Log técnico PRIVADO (Cloud Logging). Nunca se devuelve al cliente.
    console.error(`[${code}]`, redactSecrets(technicalLog));
  }
  const category = HTTPS_CATEGORY[code] || "internal";
  const publicMessage = PUBLIC_MESSAGES[code] || PUBLIC_MESSAGES.UNKNOWN_ERROR;
  return new HttpsError(category, code, { code, message: publicMessage });
}

/**
 * Verifica autenticación Firebase en una función onCall (v2).
 * Devuelve el uid o lanza AUTH_REQUIRED.
 */
function requireAuth(request) {
  const uid = request.auth && request.auth.uid;
  if (!uid) {
    throw fail(ERR.AUTH_REQUIRED);
  }
  return uid;
}

// ---------------------------------------------------------------------------
//  Cifrado de tokens (AES-256-GCM)
// ---------------------------------------------------------------------------

function getEncryptionKey() {
  const raw = process.env.TOKEN_ENCRYPTION_KEY;
  if (!raw) throw fail(ERR.CONFIG_MISSING, "TOKEN_ENCRYPTION_KEY no configurada");
  const key = Buffer.from(raw, "base64");
  if (key.length !== 32) {
    throw fail(ERR.CONFIG_MISSING, "TOKEN_ENCRYPTION_KEY debe ser 32 bytes en base64");
  }
  return key;
}

/** Cifra texto plano -> string "iv.tag.ciphertext" en base64. */
function encrypt(plainText) {
  const key = getEncryptionKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const enc = Buffer.concat([cipher.update(String(plainText), "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv.toString("base64"), tag.toString("base64"), enc.toString("base64")].join(".");
}

/** Descifra string "iv.tag.ciphertext" -> texto plano. */
function decrypt(payload) {
  const key = getEncryptionKey();
  const [ivB64, tagB64, dataB64] = String(payload).split(".");
  if (!ivB64 || !tagB64 || !dataB64) {
    throw fail(ERR.UNKNOWN_ERROR, "Formato de token cifrado inválido");
  }
  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    key,
    Buffer.from(ivB64, "base64")
  );
  decipher.setAuthTag(Buffer.from(tagB64, "base64"));
  const dec = Buffer.concat([
    decipher.update(Buffer.from(dataB64, "base64")),
    decipher.final(),
  ]);
  return dec.toString("utf8");
}

// ---------------------------------------------------------------------------
//  Helpers varios
// ---------------------------------------------------------------------------

/** Genera un token aleatorio url-safe (para el parámetro `state` de OAuth). */
function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString("base64url");
}

/** Oculta posibles secretos antes de loguear (defensa en profundidad). */
function redactSecrets(value) {
  let str = typeof value === "string" ? value : JSON.stringify(value);
  // Oculta Bearer tokens y valores largos tipo token
  str = str.replace(/Bearer\s+[A-Za-z0-9._-]+/g, "Bearer ***");
  str = str.replace(/[A-Za-z0-9_-]{40,}/g, "***REDACTED***");
  return str;
}

/** true si el timestamp (ms) ya pasó. */
function isExpired(expiresAtMs) {
  return !expiresAtMs || Date.now() >= Number(expiresAtMs);
}

module.exports = {
  ERR,
  PUBLIC_MESSAGES,
  fail,
  requireAuth,
  encrypt,
  decrypt,
  randomToken,
  redactSecrets,
  isExpired,
};
