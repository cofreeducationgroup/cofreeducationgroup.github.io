# Configuración del acceso privado (login)

El login usa **Firebase Authentication** (Google). Las contraseñas se guardan
encriptadas en los servidores de Google, nunca en este repositorio.

## Pasos para activarlo (una sola vez)

### 1. Crear el proyecto en Firebase
1. Entra a https://console.firebase.google.com con tu cuenta Google.
2. "Agregar proyecto" → nómbralo, por ejemplo, `cofre-education-group`.
3. Puedes desactivar Google Analytics (no es necesario).

### 2. Activar el método de acceso
1. En el menú: **Compilación → Authentication → Comenzar**.
2. Pestaña **Sign-in method** → activa **Correo electrónico/contraseña** → Guardar.

### 3. Crear TU usuario
1. En **Authentication → Users → Agregar usuario**.
2. Escribe tu correo y una contraseña. Esa será tu credencial de acceso.
   (Aquí defines tu contraseña; nadie más la ve.)

### 4. Registrar la app web y copiar la configuración
1. En **Configuración del proyecto** (engranaje, arriba a la izquierda).
2. Baja a **Tus apps** → ícono web **</>** → registra la app (sin Hosting).
3. Copia el objeto `firebaseConfig` que te muestra.

### 5. Pegar la configuración en el código
Reemplaza el bloque `firebaseConfig` (los valores `REEMPLAZAR_...`) en **ambos**
archivos, con los datos de tu proyecto:
- `login.html`
- `panel.html`

### 6. Autorizar tu dominio
En **Authentication → Settings → Dominios autorizados**, agrega:
- `cofreeducationgroup.cl`
- `www.cofreeducationgroup.cl`
- `felipecofre4.github.io` (por si pruebas desde el dominio de GitHub)

(`localhost` ya viene autorizado para pruebas locales.)

## Cómo se usa
- `login.html` → pantalla de ingreso (enlace "Ingresar" en el menú del sitio).
- `panel.html` → área privada; si no hay sesión, redirige al login.
- Botón "Cerrar sesión" en el panel.

## Nota de seguridad
Los valores de `firebaseConfig` (apiKey, etc.) son **públicos a propósito**:
no son secretos. La seguridad la da el backend de Firebase y la lista de
dominios autorizados, no esconder esas claves.
