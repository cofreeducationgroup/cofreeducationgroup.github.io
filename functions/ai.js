"use strict";

/**
 * Generación de ideas de contenido para LinkedIn.
 * - Si OPENAI_API_KEY está configurada: usa OpenAI (IA real).
 * - Si no: usa un generador local determinista (sin IA externa), claramente
 *   etiquetado como "local". No inventa datos analíticos, solo propone ideas.
 */

const { redactSecrets } = require("./util");

const TEMAS = [
  "educación",
  "datos",
  "inteligencia artificial",
  "innovación pedagógica",
  "neurociencia",
  "liderazgo educativo",
  "transformación digital en instituciones",
];

const AUDIENCIAS = ["directivos", "docentes", "instituciones", "familias", "estudiantes"];
const OBJETIVOS = ["visibilidad", "conversión", "autoridad", "comunidad"];

/**
 * Devuelve { source: "openai" | "local", ideas: [...] }
 * Cada idea: { titulo, angulo, borradorPost, audiencia, objetivo, cta }
 */
async function generateContentIdeas(count = 5) {
  const apiKey = process.env.OPENAI_API_KEY;
  if (apiKey) {
    try {
      const ideas = await viaOpenAI(apiKey, count);
      if (ideas && ideas.length) return { source: "openai", ideas };
    } catch (e) {
      console.error("[AI] OpenAI falló, usando generador local:", redactSecrets(String(e)));
    }
  }
  return { source: "local", ideas: localIdeas(count) };
}

async function viaOpenAI(apiKey, count) {
  const system =
    "Eres estratega de contenido B2B para COFRÉ Education Group, consultora chilena " +
    "de educación basada en datos, IA y neurociencia. Generas ideas de posts de LinkedIn " +
    "profesionales, en español de Chile, sin emojis excesivos.";
  const user =
    `Genera ${count} ideas de contenido para LinkedIn alineadas a estos temas: ` +
    `${TEMAS.join(", ")}. ` +
    `Devuelve EXCLUSIVAMENTE un JSON con la forma {"ideas":[{` +
    `"titulo":"","angulo":"","borradorPost":"","audiencia":"directivos|docentes|instituciones|familias|estudiantes",` +
    `"objetivo":"visibilidad|conversión|autoridad|comunidad","cta":""}]}.`;

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
        { role: "user", content: user },
      ],
      response_format: { type: "json_object" },
      temperature: 0.8,
    }),
  });

  if (!res.ok) throw new Error(`OpenAI ${res.status}`);
  const j = await res.json();
  const content = j.choices && j.choices[0] && j.choices[0].message.content;
  const parsed = JSON.parse(content);
  return Array.isArray(parsed.ideas) ? parsed.ideas.slice(0, count) : [];
}

// --- Generador local determinista (fallback sin IA externa) ---
function localIdeas(count) {
  const plantillas = [
    {
      tema: "datos",
      titulo: "Lo que tus datos escolares ya te están diciendo",
      angulo: "Convertir cifras de SIMCE y asistencia en decisiones pedagógicas concretas.",
      borradorPost:
        "Cada colegio ya tiene los datos que necesita para mejorar. El problema no es la falta de información, sino la falta de lectura. En COFRÉ ayudamos a transformar resultados SIMCE, asistencia y convivencia en un plan de acción priorizado. ¿Tu institución está usando sus datos o solo guardándolos?",
      audiencia: "directivos",
      objetivo: "autoridad",
      cta: "Conversemos un diagnóstico de datos para tu colegio.",
    },
    {
      tema: "inteligencia artificial",
      titulo: "IA en el aula: entusiasmo sin estrategia es riesgo",
      angulo: "Adopción responsable de IA con política institucional, no improvisada.",
      borradorPost:
        "Adoptar IA en un colegio sin política institucional es como dar autos sin licencias. La pregunta no es si usar IA, sino cómo hacerlo con criterio pedagógico y resguardos. Diseñamos políticas y capacitaciones para que la IA potencie el aprendizaje, no lo reemplace.",
      audiencia: "instituciones",
      objetivo: "conversión",
      cta: "Agenda una asesoría de adopción de IA.",
    },
    {
      tema: "neurociencia",
      titulo: "Cómo aprende el cerebro (y por qué tu PME debería saberlo)",
      angulo: "Fundamentar proyectos educativos en evidencia de neurociencia.",
      borradorPost:
        "Un Plan de Mejoramiento Educativo coherente con cómo aprende el cerebro es más efectivo y sostenible. La neurociencia no es una moda: es una base para diseñar experiencias de aprendizaje que funcionan. Así construimos PME con fundamento, no con intuición.",
      audiencia: "docentes",
      objetivo: "autoridad",
      cta: "Descubre cómo fundamentar tu próximo proyecto educativo.",
    },
    {
      tema: "liderazgo educativo",
      titulo: "Liderar con evidencia: el nuevo estándar directivo",
      angulo: "El rol del equipo directivo en una cultura basada en datos.",
      borradorPost:
        "El liderazgo educativo del futuro no adivina: mide, interpreta y decide. Los equipos directivos que integran datos a su gestión toman mejores decisiones y comunican con más claridad a su comunidad. ¿Tu liderazgo se apoya en evidencia o en percepción?",
      audiencia: "directivos",
      objetivo: "comunidad",
      cta: "Hablemos de liderazgo basado en datos.",
    },
    {
      tema: "transformación digital en instituciones",
      titulo: "Transformación digital no es comprar tecnología",
      angulo: "Procesos y personas antes que herramientas.",
      borradorPost:
        "Muchos colegios confunden transformación digital con comprar pantallas. La verdadera transformación cambia procesos y fortalece a las personas. La tecnología es el medio, no el fin. Acompañamos instituciones a transformarse con propósito, no por moda.",
      audiencia: "instituciones",
      objetivo: "visibilidad",
      cta: "Comencemos tu hoja de ruta digital.",
    },
    {
      tema: "innovación pedagógica",
      titulo: "Innovar sin perder rigor",
      angulo: "Innovación pedagógica medible y alineada a MINEDUC.",
      borradorPost:
        "Innovar en educación no significa improvisar. Las mejores innovaciones pedagógicas son medibles, replicables y coherentes con el marco curricular. Diseñamos proyectos que innovan con instrumentos de seguimiento desde el día uno.",
      audiencia: "docentes",
      objetivo: "autoridad",
      cta: "Diseñemos juntos tu próxima innovación medible.",
    },
  ];

  const out = [];
  for (let i = 0; i < count; i++) {
    const base = plantillas[i % plantillas.length];
    out.push({
      titulo: base.titulo,
      angulo: base.angulo,
      borradorPost: base.borradorPost,
      audiencia: AUDIENCIAS.includes(base.audiencia) ? base.audiencia : "instituciones",
      objetivo: OBJETIVOS.includes(base.objetivo) ? base.objetivo : "autoridad",
      cta: base.cta,
    });
  }
  return out;
}

module.exports = { generateContentIdeas, TEMAS };
