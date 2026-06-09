# Login seguro OWASP (demo local)

Proyecto web con HTML, CSS y JS para login seguro, priorizando:

1. CAPTCHA de Cloudflare Turnstile.
2. Mensajes genericos en fallos de autenticacion para evitar enumeracion de usuarios.
3. Almacenamiento de contrasenas con hashing seguro (Argon2id).

## Requisitos

- Node.js 20+
- npm

## Configuracion

1. Instala dependencias:
   npm install

2. Crea tu archivo de entorno:
   - Copia `.env.example` a `.env`.
   - `.env.example` incluye claves de prueba oficiales de Turnstile para demo local.
   - Para produccion, reemplaza esas claves con las de tu sitio en Cloudflare.

3. Inicia el servidor:
   npm run dev

4. Abre la app:
   http://localhost:3000

## Flujo

- Registro en `/api/register`:
  - Valida email y contrasena minima.
  - Guarda solo el hash Argon2id de la contrasena.

- Login en `/api/login`:
  - Requiere token Turnstile valido.
  - Responde con mensaje generico cuando falla autenticacion o captcha.

## Checklist de seguridad aplicado

- CAPTCHA en login, verificado server-side.
- Mensajes de error no reveladores.
- Hashing Argon2id con parametros de costo.
- Rate limiting en endpoint de login.
- Cookies de sesion HttpOnly y SameSite.
- Helmet y CSP para cabeceras de seguridad.
