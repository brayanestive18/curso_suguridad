"use strict";

const safeForm   = document.querySelector("#safe-form");
const safeClear  = document.querySelector("#safe-clear");
const safeInput  = document.querySelector("#safe-input");
const safeOutput = document.querySelector("#safe-output");

const vulnForm   = document.querySelector("#vuln-form");
const vulnClear  = document.querySelector("#vuln-clear");
const vulnInput  = document.querySelector("#vuln-input");
const vulnOutput = document.querySelector("#vuln-output");

// ── SEGURO ─────────────────────────────────────────────────────────────────
// textContent asigna texto plano: el navegador escapa < > & " '
// antes de renderizar. Ningun tag HTML ni script puede ejecutarse.
safeForm.addEventListener("submit", (event) => {
  event.preventDefault();
  safeOutput.textContent = safeInput.value;
  safeOutput.classList.add("has-content");
});

safeClear.addEventListener("click", () => {
  safeInput.value = "";
  safeOutput.textContent = "";
  safeOutput.classList.remove("has-content");
});

// ── VULNERABLE ─────────────────────────────────────────────────────────────
// innerHTML inserta el valor del usuario como HTML sin ninguna sanitizacion.
// Cualquier tag, atributo de evento (onerror, onload, onclick) o
// etiqueta <script> se interpretara y ejecutara en el navegador.
vulnForm.addEventListener("submit", (event) => {
  event.preventDefault();
  // INSEGURO A PROPOSITO: demuestra XSS DOM-based
  vulnOutput.innerHTML = vulnInput.value;
  vulnOutput.classList.add("has-content");
});

vulnClear.addEventListener("click", () => {
  vulnInput.value = "";
  vulnOutput.innerHTML = "";
  vulnOutput.classList.remove("has-content");
});
