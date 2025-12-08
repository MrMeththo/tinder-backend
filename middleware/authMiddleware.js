// backend/middleware/authMiddleware.js
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "dev-secret-change-me";

/**
 * Middleware koji provjerava JWT i postavlja req.userId
 *
 * Očekuje header:
 * Authorization: Bearer <token>
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization || "";

  if (!authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    if (!decoded || !decoded.userId) {
      return res.status(401).json({ error: "Invalid token" });
    }

    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.error("JWT verify error:", err);
    return res.status(401).json({ error: "Invalid token" });
  }
}

module.exports = {
  requireAuth,
  JWT_SECRET,
};
