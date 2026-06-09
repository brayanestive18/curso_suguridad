const crypto = require("crypto");
const express = require("express");
const argon2 = require("argon2");

const GENERIC_AUTH_MESSAGE = "Credenciales invalidas o intento no valido.";

const HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 2,
  parallelism: 1
};

let dummyHashPromise;

function normalizeEmail(rawEmail) {
  return String(rawEmail || "").trim().toLowerCase();
}

function isValidEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function isStrongEnoughPassword(password) {
  return typeof password === "string" && password.length >= 12;
}

async function getDummyHash() {
  if (!dummyHashPromise) {
    dummyHashPromise = argon2.hash(
      "dummy-password-for-timing-equalization-only",
      HASH_OPTIONS
    );
  }
  return dummyHashPromise;
}

async function hashPassword(password) {
  return argon2.hash(password, HASH_OPTIONS);
}

async function verifyTurnstile(turnstileSecretKey, token, remoteIp) {
  if (!turnstileSecretKey || !token) {
    return false;
  }

  const body = new URLSearchParams();
  body.set("secret", turnstileSecretKey);
  body.set("response", token);
  if (remoteIp) {
    body.set("remoteip", remoteIp);
  }

  try {
    const response = await fetch(
      "https://challenges.cloudflare.com/turnstile/v0/siteverify",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body: body.toString()
      }
    );

    if (!response.ok) {
      return false;
    }

    const result = await response.json();
    return Boolean(result.success);
  } catch (_err) {
    return false;
  }
}

async function ensureDemoUser(db, email, password) {
  const normalizedEmail = normalizeEmail(email);
  if (!isValidEmail(normalizedEmail) || !isStrongEnoughPassword(password)) {
    return;
  }

  const existingUser = await db.get("SELECT id FROM users WHERE email = ?", [
    normalizedEmail
  ]);

  if (existingUser) {
    return;
  }

  const passwordHash = await hashPassword(password);
  await db.run(
    "INSERT INTO users (email, password_hash) VALUES (?, ?)",
    [normalizedEmail, passwordHash]
  );
}

function createAuthRouter({ db, sessions, turnstileSecretKey }) {
  const router = express.Router();

  router.post("/register", async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");

    if (!isValidEmail(email) || !isStrongEnoughPassword(password)) {
      res.status(400).json({
        ok: false,
        message:
          "Registro invalido. Usa un email valido y una contrasena de 12 o mas caracteres."
      });
      return;
    }

    try {
      const existingUser = await db.get("SELECT id FROM users WHERE email = ?", [
        email
      ]);
      if (existingUser) {
        res.status(400).json({
          ok: false,
          message: "No se pudo completar el registro."
        });
        return;
      }

      const passwordHash = await hashPassword(password);
      await db.run(
        "INSERT INTO users (email, password_hash) VALUES (?, ?)",
        [email, passwordHash]
      );

      res.status(201).json({
        ok: true,
        message: "Cuenta creada correctamente."
      });
    } catch (_err) {
      res.status(500).json({
        ok: false,
        message: "No se pudo completar el registro."
      });
    }
  });

  router.post("/login", async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const password = String(req.body?.password || "");
    const turnstileToken = String(req.body?.turnstileToken || "");
    const remoteIp = req.ip;

    if (!isValidEmail(email) || !password || !turnstileToken) {
      res.status(401).json({ ok: false, message: GENERIC_AUTH_MESSAGE });
      return;
    }

    const captchaOk = await verifyTurnstile(
      turnstileSecretKey,
      turnstileToken,
      remoteIp
    );

    if (!captchaOk) {
      res.status(401).json({ ok: false, message: GENERIC_AUTH_MESSAGE });
      return;
    }

    try {
      const user = await db.get(
        "SELECT id, email, password_hash FROM users WHERE email = ?",
        [email]
      );

      const hashToCheck = user ? user.password_hash : await getDummyHash();
      const passwordOk = await argon2.verify(hashToCheck, password);

      if (!user || !passwordOk) {
        res.status(401).json({ ok: false, message: GENERIC_AUTH_MESSAGE });
        return;
      }

      const sessionId = crypto.randomBytes(32).toString("hex");
      sessions.set(sessionId, {
        userId: user.id,
        email: user.email,
        createdAt: Date.now()
      });

      res.cookie("sid", sessionId, {
        httpOnly: true,
        sameSite: "lax",
        secure: process.env.NODE_ENV === "production",
        maxAge: 1000 * 60 * 60 * 8
      });

      res.status(200).json({
        ok: true,
        message: "Inicio de sesion correcto.",
        email: user.email
      });
    } catch (_err) {
      res.status(401).json({ ok: false, message: GENERIC_AUTH_MESSAGE });
    }
  });

  router.post("/logout", (req, res) => {
    const sessionId = req.cookies?.sid;
    if (sessionId) {
      sessions.delete(sessionId);
    }

    res.clearCookie("sid");
    res.status(200).json({ ok: true });
  });

  router.get("/me", (req, res) => {
    const sessionId = req.cookies?.sid;
    if (!sessionId || !sessions.has(sessionId)) {
      res.status(401).json({ ok: false });
      return;
    }

    const session = sessions.get(sessionId);
    res.status(200).json({ ok: true, email: session.email });
  });

  return router;
}

module.exports = {
  createAuthRouter,
  ensureDemoUser,
  GENERIC_AUTH_MESSAGE
};
