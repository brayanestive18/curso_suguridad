const loginForm = document.querySelector("#login-form");
const registerForm = document.querySelector("#register-form");
const loginMessage = document.querySelector("#login-message");
const registerMessage = document.querySelector("#register-message");

let captchaWidgetId = null;
let captchaToken = "";

async function getCaptchaSiteKey() {
  const response = await fetch("/api/config", { credentials: "same-origin" });
  if (!response.ok) {
    throw new Error("No se pudo cargar configuracion");
  }
  const payload = await response.json();
  return payload.captchaSiteKey || "";
}

async function setupTurnstile() {
  try {
    const siteKey = await getCaptchaSiteKey();
    if (!siteKey) {
      loginMessage.textContent =
        "Captcha no configurado en servidor. Define claves de Turnstile.";
      loginForm.querySelector("button[type='submit']").disabled = true;
      return;
    }

    if (!window.turnstile) {
      loginMessage.textContent =
        "No se pudo cargar captcha. Recarga la pagina e intenta de nuevo.";
      loginForm.querySelector("button[type='submit']").disabled = true;
      return;
    }

    captchaWidgetId = window.turnstile.render("#captcha-container", {
      sitekey: siteKey,
      callback: (token) => {
        captchaToken = token;
      },
      "expired-callback": () => {
        captchaToken = "";
      },
      "error-callback": () => {
        captchaToken = "";
      }
    });
  } catch (_err) {
    loginMessage.textContent =
      "No se pudo inicializar captcha. Recarga la pagina e intenta de nuevo.";
    loginForm.querySelector("button[type='submit']").disabled = true;
  }
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    credentials: "same-origin",
    body: JSON.stringify(body)
  });

  let payload = { ok: false, message: "Solicitud rechazada." };
  try {
    payload = await response.json();
  } catch (_err) {
    payload = { ok: false, message: "Solicitud rechazada." };
  }

  return { response, payload };
}

loginForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  loginMessage.textContent = "Procesando...";

  const formData = new FormData(loginForm);
  const email = formData.get("email");
  const password = formData.get("password");

  const { response, payload } = await postJson("/api/login", {
    email,
    password,
    turnstileToken: captchaToken
  });

  if (!response.ok) {
    loginMessage.textContent =
      "Credenciales invalidas o intento no valido.";
    if (window.turnstile && captchaWidgetId !== null) {
      window.turnstile.reset(captchaWidgetId);
      captchaToken = "";
    }
    return;
  }

  loginMessage.textContent = `Bienvenido, ${payload.email}.`;
  loginForm.reset();
  if (window.turnstile && captchaWidgetId !== null) {
    window.turnstile.reset(captchaWidgetId);
    captchaToken = "";
  }
});

registerForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  registerMessage.textContent = "Creando cuenta...";

  const formData = new FormData(registerForm);
  const email = formData.get("email");
  const password = formData.get("password");

  const { payload } = await postJson("/api/register", {
    email,
    password
  });

  registerMessage.textContent = payload.message;
  if (payload.ok) {
    registerForm.reset();
  }
});

window.addEventListener("load", setupTurnstile);
