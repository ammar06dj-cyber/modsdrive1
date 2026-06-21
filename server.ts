import dotenv from "dotenv";
dotenv.config();

import express from "express";
import path from "path";
import crypto from "crypto";
import rateLimit from "express-rate-limit";
import { createServer as createViteServer } from "vite";
import pino from "pino";
import pinoHttp from "pino-http";
import helmet from "helmet";

const logger = pino({
  level: "info",
});

function safeCompare(a: string, b: string): boolean {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const key = crypto.randomBytes(32);
  const hashA = crypto.createHmac("sha256", key).update(a).digest();
  const hashB = crypto.createHmac("sha256", key).update(b).digest();
  return crypto.timingSafeEqual(hashA, hashB);
}

function getClientIp(req: express.Request): string | null {
  // 1. Try X-Forwarded-For (can be comma-separated list of IPs set by reverse proxy/load balancer)
  const xForwardedFor = req.headers["x-forwarded-for"];
  if (xForwardedFor) {
    const ips = typeof xForwardedFor === "string"
      ? xForwardedFor.split(",")
      : Array.isArray(xForwardedFor)
        ? xForwardedFor
        : [];
    const clientIp = ips[0]?.trim();
    if (clientIp) return clientIp;
  }

  // 2. Try X-Real-IP
  const xRealIp = req.headers["x-real-ip"];
  if (typeof xRealIp === "string" && xRealIp.trim()) {
    return xRealIp.trim();
  }

  // 3. Try standard remoteAddress from socket
  const remoteAddress = req.socket?.remoteAddress;
  if (typeof remoteAddress === "string" && remoteAddress.trim()) {
    return remoteAddress.trim();
  }

  // 4. Try standard Express request.ip property
  if (typeof req.ip === "string" && req.ip.trim()) {
    return req.ip.trim();
  }

  return null;
}

async function startServer() {
  const app = express();
  const PORT = 3000;

  // Enable Helmet for enhanced security headers (X-Content-Type-Options, Strict-Transport-Security, etc.)
  app.use(helmet({
    contentSecurityPolicy: false, // Vite runs inline scripts during development
    frameguard: false, // Allow framing so the app loads correctly in the AI Studio preview iframe
  }));

  // Cloud Run ingress / reverse proxy trust setting
  app.set("trust proxy", 1);

  // HTTPS enforcement middleware in production
  if (process.env.NODE_ENV === "production" || process.env.HTTPS_REDIRECT === "true") {
    app.use((req, res, next) => {
      // Check trust proxy req.secure status or X-Forwarded-Proto header
      const isHttps = req.secure || req.headers["x-forwarded-proto"] === "https";
      if (!isHttps) {
        const secureUrl = `https://${req.headers.host}${req.url}`;
        logger.info({ url: req.url, secureUrl }, "Redirecting non-HTTPS request to secure HTTPS endpoint");
        return res.redirect(301, secureUrl);
      }
      next();
    });
  }

  // Pino-HTTP middleware for logging all requests
  app.use(pinoHttp({
    logger,
    autoLogging: {
      ignore: (req) => {
        const url = req.url || "";
        // Don't log development source files, hot-reloading assets, or dependencies to prevent console clutter
        return (
          url.startsWith("/@") ||
          url.startsWith("/src/") ||
          url.startsWith("/node_modules/") ||
          url.includes("hot-update") ||
          /\.(js|ts|tsx|css|png|jpg|jpeg|svg|webp|gif|ico|map)$/.test(url.split("?")[0])
        );
      },
    },
    customProps: (req) => ({
      ip: getClientIp(req as any) || "Unknown IP",
    }),
  }));

  app.use(express.json());

  // Define admin authentication rate limiter: max 5 requests per 15 minutes per IP
  const adminAuthLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 3,
    message: { error: "Too many attempts. Try again later." },
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Password strength validation middleware to prevent memory exhaustion and timing issues
  const validateAdminPasswordPayload = (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    const { password } = req.body;

    if (!password || typeof password !== "string") {
      res.status(400).json({ error: "Password must be a non-empty string." });
      return;
    }

    // Prevent massive payloads to avoid memory issues (maximum 128 characters)
    // Ensures a minimum secure length of 8 characters
    if (password.length < 8 || password.length > 128) {
      res.status(400).json({ error: "Password length must be between 8 and 128 characters." });
      return;
    }

    // Secure non-backtracking regex checking to prevent ReDoS and validate standard characters
    const safePasswordPattern = /^[a-zA-Z0-9!@#$%^&*()_+=\-[\]{}|\\:;"'<>,.?/~`]{8,128}$/;
    if (!safePasswordPattern.test(password)) {
      res.status(400).json({ error: "Password contains invalid characters or doesn't match complexity requirements." });
      return;
    }

    next();
  };

  // Define general rate limiter for all other routes: max 100 requests per 15 minutes per IP
  const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100,
    message: { error: "Too many requests. Please try again later." },
    statusCode: 429,
    standardHeaders: true,
    legacyHeaders: false,
  });

  // Admin Auth POST endpoint
  app.post("/api/admin-auth", adminAuthLimiter, validateAdminPasswordPayload, (req, res) => {
    const { password } = req.body;
    const ip = getClientIp(req) || "Unknown IP";

    if (!password) {
      res.status(400).json({ error: "Password is required" });
      return;
    }

    let adminPassword = process.env.ADMIN_PASSWORD;
    if (!adminPassword) {
      logger.error("Error: ADMIN_PASSWORD environment variable is NOT set! Control panel authentication is currently disabled.");
      res.status(500).json({ error: "Server misconfiguration: admin authentication is not configured." });
      return;
    }

    const isMatch = safeCompare(password, adminPassword);

    // Apply random delay to prevent timing attacks (100ms - 300ms)
    const delay = Math.floor(Math.random() * 201) + 100;

    setTimeout(() => {
      if (isMatch) {
        res.status(200).json({ authenticated: true });
      } else {
        const timestamp = new Date().toISOString();
        logger.warn({ ip, timestamp }, `Failed admin login attempt`);
        res.status(401).json({ authenticated: false, error: "Invalid authentication credentials." });
      }
    }, delay);
  });

  // Apply general rate limit to all other routes
  app.use(generalLimiter);

  // Serve Vite application
  if (process.env.NODE_ENV !== "production") {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: "spa",
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(process.cwd(), "dist");
    app.use(express.static(distPath));
    app.get("*", (req, res) => {
      res.sendFile(path.join(distPath, "index.html"));
    });
  }

  app.listen(PORT, "0.0.0.0", () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}

startServer();
