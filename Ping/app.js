const safeForm = document.querySelector("#safeForm");
const vulnForm = document.querySelector("#vulnForm");
const safeOutput = document.querySelector("#safeOutput");
const vulnOutput = document.querySelector("#vulnOutput");

const DANGEROUS_CHARS = /[;&|`$<>\\()]/;
const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[a-zA-Z0-9-]{1,63}(\.(?!-)[a-zA-Z0-9-]{1,63})*$/;

function isValidIPv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) {
    return false;
  }

  return parts.every((p) => {
    if (!/^\d{1,3}$/.test(p)) {
      return false;
    }

    const num = Number(p);
    return num >= 0 && num <= 255;
  });
}

function validateSafeTarget(raw) {
  const target = raw.trim();

  if (!target) {
    return { ok: false, message: "La entrada no puede estar vacia." };
  }

  if (target.length > 253) {
    return { ok: false, message: "Longitud maxima excedida (253 caracteres)." };
  }

  if (DANGEROUS_CHARS.test(target) || target.includes(" ")) {
    return {
      ok: false,
      message:
        "Se detectaron metacaracteres o espacios. Solo IPv4/hostname estricto.",
    };
  }

  if (isValidIPv4(target) || HOSTNAME_RE.test(target)) {
    return { ok: true, normalized: target.toLowerCase() };
  }

  return {
    ok: false,
    message: "Formato invalido. Usa IPv4 (8.8.8.8) o hostname (example.com).",
  };
}

function fakePing(target) {
  const latency = Math.floor(Math.random() * 45) + 7;
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve(
        [
          `Haciendo ping a ${target} con 32 bytes de datos:`,
          `Respuesta desde ${target}: bytes=32 tiempo=${latency}ms TTL=117`,
          `Respuesta desde ${target}: bytes=32 tiempo=${latency + 2}ms TTL=117`,
          "",
          `Estadisticas de ping para ${target}:`,
          "Paquetes: enviados = 2, recibidos = 2, perdidos = 0 (0% perdidos)",
        ].join("\n")
      );
    }, 420);
  });
}

safeForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const input = new FormData(safeForm).get("safeTarget") || "";
  const result = validateSafeTarget(String(input));

  if (!result.ok) {
    safeOutput.textContent = [
      "[RECHAZADO] Politica OWASP activa.",
      `Motivo: ${result.message}`,
      "Defensa aplicada: allowlist + control de longitud + bloqueo de metacaracteres.",
    ].join("\n");
    return;
  }

  const commandPreview = `Comando seguro (parametrizado): ping -- ${result.normalized}`;
  safeOutput.textContent = `${commandPreview}\nEjecutando...`;

  const output = await fakePing(result.normalized);
  safeOutput.textContent = `${commandPreview}\n\n${output}`;
});

vulnForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const raw = String(new FormData(vulnForm).get("vulnTarget") || "");
  const insecureCommand = `Comando construido (inseguro): ping ${raw}`;

  vulnOutput.textContent = `${insecureCommand}\nEjecutando...`;

  const payload = raw.trim() || "127.0.0.1";
  const baseTarget = payload.split(/[;&|]/)[0].trim() || "127.0.0.1";
  const output = await fakePing(baseTarget);

  let injectionWarning = "\n\n[Sin evidencia obvia de inyeccion en esta entrada]";
  if (/[;&|]/.test(payload)) {
    injectionWarning = [
      "",
      "[ALERTA] Posible command injection detectada.",
      "La entrada contenia separadores de comandos (;, &, |).",
      "Un backend vulnerable podria ejecutar instrucciones adicionales.",
    ].join("\n");
  }

  vulnOutput.textContent = `${insecureCommand}\n\n${output}${injectionWarning}`;
});
