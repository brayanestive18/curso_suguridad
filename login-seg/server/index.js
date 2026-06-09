const path = require("path");
const express = require("express");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const cookieParser = require("cookie-parser");
const dotenv = require("dotenv");

const { openDb } = require("./db");
const { createAuthRouter, ensureDemoUser } = require("./auth");

dotenv.config();

const app = express();
const db = openDb();
const sessions = new Map();

const PORT = Number(process.env.PORT || 3000);
const TURNSTILE_SITE_KEY = process.env.TURNSTILE_SITE_KEY || "";
const TURNSTILE_SECRET_KEY = process.env.TURNSTILE_SECRET_KEY || "";

app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "https://challenges.cloudflare.com"
        ],
        frameSrc: ["'self'", "https://challenges.cloudflare.com"],
        connectSrc: ["'self'", "https://challenges.cloudflare.com"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", "data:"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"]
      }
    }
  })
);
app.use(express.json({ limit: "10kb" }));
app.use(cookieParser());

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 8,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    ok: false,
    message: "Credenciales invalidas o intento no valido."
  }
});

app.get("/api/config", (_req, res) => {
  res.status(200).json({
    captchaSiteKey: TURNSTILE_SITE_KEY
  });
});

app.use("/api/login", loginLimiter);
app.use(
  "/api",
  createAuthRouter({
    db,
    sessions,
    turnstileSecretKey: TURNSTILE_SECRET_KEY
  })
);

app.use(express.static(path.join(__dirname, "..", "public")));

app.use((_req, res) => {
  res.sendFile(path.join(__dirname, "..", "public", "index.html"));
});

async function start() {
  try {
    await ensureDemoUser(
      db,
      process.env.DEMO_USER_EMAIL,
      process.env.DEMO_USER_PASSWORD
    );

    app.listen(PORT, () => {
      if (!TURNSTILE_SITE_KEY || !TURNSTILE_SECRET_KEY) {
        console.warn(
          "Turnstile no esta configurado. Define TURNSTILE_SITE_KEY y TURNSTILE_SECRET_KEY."
        );
      }
      console.log(`Servidor escuchando en http://localhost:${PORT}`);
    });
  } catch (err) {
    console.error("No se pudo iniciar el servidor", err);
    process.exit(1);
  }
}

start();
