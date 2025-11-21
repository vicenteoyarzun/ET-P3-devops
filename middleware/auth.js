const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET;

/**
 * 🧩 Middleware de autenticación JWT
 * 
 * Verifica la validez del token JWT enviado en la cabecera `Authorization`.
 * Si el token es válido, añade los datos decodificados del usuario (`req.user`)
 * al objeto `request` y permite continuar al siguiente middleware/controlador.
 * 
 * Requisitos:
 *  - El token debe enviarse en el encabezado como: `Authorization: Bearer <token>`
 * 
 * Respuestas posibles:
 *  - 401 → No se envió token
 *  - 403 → Token inválido o expirado
 */
function authenticateToken(req, res, next) {
  // Extrae el encabezado Authorization: "Bearer <token>"
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  // Si no se envía token, se deniega el acceso
  if (!token) {
    return res.status(401).json({ error: "Token requerido" });
  }

  // Verifica la validez y firma del token
  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: "Token inválido o expirado" });
    }

    // Guarda la información del usuario en la request para uso posterior
    req.user = user;
    next();
  });
}

module.exports = authenticateToken;
