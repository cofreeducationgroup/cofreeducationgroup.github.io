"use strict";

/**
 * Identificación de libros a partir de una foto de portada (visión IA).
 * Requiere OPENAI_API_KEY (Firebase Secret) — a diferencia de ai.js, aquí no hay
 * un modo "local" posible: identificar un libro desde una foto necesita un modelo
 * de visión real.
 */

const { ERR, fail } = require("./util");

const MAX_BASE64_LENGTH = 8_000_000; // ~6MB de imagen decodificada, margen de sobra

/**
 * Recibe una data URL "data:image/...;base64,AAAA..." ya redimensionada por el
 * cliente. Devuelve { titulo, autor, editorial, anio, isbn, confianza }.
 */
async function identifyBookFromCover(imageDataUrl) {
  if (typeof imageDataUrl !== "string" || !imageDataUrl.startsWith("data:image/")) {
    throw fail(ERR.INSUFFICIENT_DATA, "imageBase64 ausente o con formato inválido");
  }
  if (imageDataUrl.length > MAX_BASE64_LENGTH) {
    throw fail(ERR.INSUFFICIENT_DATA, "Imagen demasiado grande");
  }

  const apiKey = process.env.OPENAI_API_KEY;
  if (!apiKey) {
    throw fail(ERR.CONFIG_MISSING, "OPENAI_API_KEY no configurada");
  }

  const system =
    "Eres un catalogador de biblioteca experto. Se te muestra una foto de la portada " +
    "de un libro y debes identificarlo. Responde EXCLUSIVAMENTE con un JSON con la forma " +
    '{"titulo":"","autor":"","editorial":"","anio":null,"isbn":"","confianza":"alta|media|baja"}. ' +
    "Si no puedes determinar un campo con certeza razonable, déjalo vacío (o null en anio) " +
    "en vez de inventar datos. No agregues texto fuera del JSON.";

  const res = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      model: "gpt-4o-mini",
      messages: [
        { role: "system", content: system },
        {
          role: "user",
          content: [
            { type: "text", text: "Identifica este libro a partir de su portada." },
            { type: "image_url", image_url: { url: imageDataUrl } },
          ],
        },
      ],
      response_format: { type: "json_object" },
      temperature: 0.2,
      max_tokens: 500,
    }),
  });

  if (!res.ok) {
    const bodyText = await res.text().catch(() => "");
    throw fail(ERR.UNKNOWN_ERROR, `OpenAI ${res.status}: ${bodyText.slice(0, 300)}`);
  }

  const j = await res.json();
  const content = j.choices && j.choices[0] && j.choices[0].message.content;
  let parsed;
  try {
    parsed = JSON.parse(content);
  } catch (e) {
    throw fail(ERR.UNKNOWN_ERROR, `Respuesta de OpenAI no es JSON válido: ${content}`);
  }

  return {
    titulo: typeof parsed.titulo === "string" ? parsed.titulo.trim() : "",
    autor: typeof parsed.autor === "string" ? parsed.autor.trim() : "",
    editorial: typeof parsed.editorial === "string" ? parsed.editorial.trim() : "",
    anio: Number.isFinite(parsed.anio) ? parsed.anio : null,
    isbn: typeof parsed.isbn === "string" ? parsed.isbn.trim() : "",
    confianza: ["alta", "media", "baja"].includes(parsed.confianza) ? parsed.confianza : "media",
  };
}

module.exports = { identifyBookFromCover };
