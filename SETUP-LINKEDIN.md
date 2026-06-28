# Módulo "LinkedIn Center" — Guía de configuración y despliegue

Integra LinkedIn (OAuth 2.0 + publicación + programación + analíticas + ideas IA)
en el área privada del sitio. El **frontend** vive en GitHub Pages (`linkedin.html`)
y el **backend seguro** en **Firebase Cloud Functions**.

> ⚠️ **Requisito de plan:** Cloud Functions y Cloud Scheduler requieren el plan
> **Blaze** (pago por uso) de Firebase. Tiene capa gratuita generosa, pero necesita
> una tarjeta asociada. Sin Blaze, el backend **no se puede desplegar**.

---

## 0. Requisitos previos (en tu computador)

1. **Node.js 20** → https://nodejs.org (en este Mac no está instalado todavía).
2. **Firebase CLI**:
   ```bash
   npm install -g firebase-tools
   firebase login
   ```
3. Estar dentro de la carpeta del repo al ejecutar los comandos.

---

## 1. Activar servicios en Firebase

1. **Plan Blaze:** Firebase Console → ⚙️ → *Uso y facturación* → cambiar a **Blaze**.
2. **Firestore:** Console → *Firestore Database* → *Crear base de datos* → modo **Production**.
3. **Authentication:** ya está activo (login existente). No se toca.

---

## 2. Crear la app en LinkedIn Developer Portal

1. Entra a https://www.linkedin.com/developers/apps → *Create app*.
2. Asóciala a tu página de empresa COFRÉ (si la tienes).
3. En **Auth**:
   - Copia **Client ID** y **Client Secret**.
   - En *Authorized redirect URLs* agrega la URL de la función callback
     (la obtienes en el paso 4, tras el primer deploy). Formato típico:
     ```
     https://us-central1-cofre-education-group.cloudfunctions.net/linkedinOAuthCallback
     ```
4. En **Products**, solicita:
   - **Sign In with LinkedIn using OpenID Connect** (da `openid`, `profile`, `email`).
   - **Share on LinkedIn** (da `w_member_social`).
   - Para páginas de empresa: **Community Management API** (da
     `r_organization_admin`, `w_organization_social`). *Requiere aprobación de
     LinkedIn; mientras no esté aprobada, el módulo mostrará `PERMISSION_REQUIRED`.*

---

## 3. Configurar variables y secretos

### a) Variables no secretas → `functions/.env`
Copia el ejemplo y complétalo:
```bash
cp functions/.env.example functions/.env
```
Edita `functions/.env`:
```
LINKEDIN_CLIENT_ID=tu_client_id
LINKEDIN_REDIRECT_URI=https://us-central1-cofre-education-group.cloudfunctions.net/linkedinOAuthCallback
LINKEDIN_FRONTEND_RETURN_URL=https://www.cofreeducationgroup.cl/linkedin.html
LINKEDIN_API_VERSION=202405
```
> `functions/.env` está en `.gitignore` y NO se sube al repo.

### b) Secretos → Firebase Secrets
```bash
# Secreto de cliente de LinkedIn
firebase functions:secrets:set LINKEDIN_CLIENT_SECRET

# Clave de cifrado de tokens (genérala así y pégala cuando lo pida):
openssl rand -base64 32
firebase functions:secrets:set TOKEN_ENCRYPTION_KEY

# OPCIONAL: solo si quieres ideas IA reales con OpenAI
firebase functions:secrets:set OPENAI_API_KEY
```

---

## 4. Desplegar

```bash
# Instalar dependencias del backend
cd functions && npm install && cd ..

# Desplegar reglas de Firestore, índices y funciones
firebase deploy --only firestore:rules,firestore:indexes,functions
```

Al terminar, la consola imprime la **URL real** de cada función. Copia la de
`linkedinOAuthCallback` y:
1. Pégala como `LINKEDIN_REDIRECT_URI` en `functions/.env` (si difería).
2. Regístrala en *Authorized redirect URLs* de LinkedIn (paso 2.3).
3. Si la cambiaste, vuelve a desplegar: `firebase deploy --only functions`.

> El frontend (`linkedin.html`, `panel.html`) se publica como el resto del sitio:
> commit + push a GitHub (no usa Firebase Hosting).

---

## 5. Estructura de datos (Firestore)

```
users/{uid}/linkedin/connection         → token CIFRADO + estado (cliente DENEGADO)
users/{uid}/linkedinOrganizations/{id}  → páginas administrables (solo lectura)
users/{uid}/linkedinDrafts/{id}         → borradores y publicados
users/{uid}/linkedinScheduledPosts/{id} → programados (status/scheduledAt)
users/{uid}/linkedinAnalytics/{id}      → snapshots de analíticas reales
oauthStates/{state}                     → anti-CSRF temporal (cliente DENEGADO)
```

---

## 6. Pruebas manuales

1. **Login:** entra en `/login.html` con tu usuario.
2. **Abrir módulo:** Panel → tarjeta *LinkedIn Center*.
3. **Conectar LinkedIn:** botón *Conectar LinkedIn* → autoriza → vuelves con
   "✅ LinkedIn conectado".
4. **Detectar páginas:** si tienes Community Management aprobado, aparecen en el
   selector. Si no → mensaje `PERMISSION_REQUIRED`.
5. **Publicar en perfil:** escribe texto → *Publicar ahora* → confirmar.
6. **Publicar en página:** elige página → publicar (requiere permiso aprobado).
7. **Programar:** elige fecha futura → *Programar*. El scheduler publica cada 5 min.
8. **Analíticas:** elige página → *Ver analíticas*. Sin permiso → "Sin permisos".
9. **Ideas IA:** *Generar ideas* (OpenAI si hay clave, si no generador local).
10. **Desconectar:** botón *Desconectar*.

---

## 7. Limitaciones reales por permisos de LinkedIn

- **Analíticas de perfil personal:** NO existen en la API pública → `UNSUPPORTED_ANALYTICS`.
- **Páginas de empresa (publicar/analizar):** requieren **Community Management API**
  aprobada por LinkedIn. Sin aprobación → `PERMISSION_REQUIRED`.
- **Tokens de LinkedIn:** expiran (~60 días). Al expirar → `TOKEN_EXPIRED` y hay que
  reconectar (el refresh token solo está disponible en programas aprobados).
- El módulo **nunca inventa métricas**: muestra solo lo que la API devuelve.
