require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require("fs");
const path = require("path");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { User } = require('./models');
const authenticateToken = require("./middleware/auth");
const client = require('prom-client');
const logFile = "./logs/app.log";

fs.mkdirSync(path.dirname(logFile), { recursive: true });

const app = express();
const register = new client.Registry();

// Métrica personalizada
const httpRequestsTotal = new client.Counter({
  name: 'http_requests_total',
  help: 'Número total de peticiones HTTP recibidas',
  labelNames: ['method', 'route', 'status_code'],
});

const httpRequestDuration = new client.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duración de las peticiones HTTP en segundos',
  labelNames: ['method', 'route', 'status_code'],
  buckets: [0.1, 0.3, 0.5, 1, 2, 5],
});

// Registrar métricas
register.registerMetric(httpRequestsTotal);
register.registerMetric(httpRequestDuration);
register.setDefaultLabels({ app: 'node-metrics-demo' });
client.collectDefaultMetrics({ register });

function writeLog(level, msg) {
  const line = `${new Date().toISOString()} [${level}] ${msg}\n`;
  // stdout
  if (level === "ERROR") console.error(line.trim());
  else console.log(line.trim());
  // archivo
  fs.appendFileSync(logFile, line);
}
// ----------------------------------------------------------
// ⚙️ Configuración general
// ----------------------------------------------------------
app.use(cors({
  origin: '*', // o 'https://yn8csy-3000.csb.app' si quieres restringir
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true,
}));
// Middleware para medir peticiones
app.use((req, res, next) => {
  const end = httpRequestDuration.startTimer();
  res.on('finish', () => {
    httpRequestsTotal.inc({ method: req.method, route: req.path, status_code: res.statusCode });
    end({ method: req.method, route: req.path, status_code: res.statusCode });
  });
  next();
});
app.use(express.json());

// Variables de entorno
const JWT_SECRET = process.env.JWT_SECRET;
const SECRET_KEY = process.env.SECRET_KEY; // Clave compartida con el frontend (para cifrado simétrico)
const BCRYPT_ROUNDS = parseInt(process.env.BCRYPT_SALT_ROUNDS || '12');

// ----------------------------------------------------------
// 🧍 Usuarios simulados (modo desarrollo / prueba rápida)
// ----------------------------------------------------------
const USERS = [
  { id: 1, username: "admin", password: "123456", email: "admin@mail.com" },
  { id: 2, username: "user", password: "654321", email: "user@mail.com" },
];

// ----------------------------------------------------------
// 🟢 LOGIN — Genera y devuelve un token JWT
// ----------------------------------------------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;
  writeLog("INFO", "login de usuario");
  // Buscar usuario en la lista (simulada)
  const user = USERS.find(
    (u) => u.username === username && u.password === password
  );

  if (!user) {
    writeLog("ERROR", username+ ": Intenta ingresar con Credenciales inválidas" );
    return res.status(401).json({ error: "Credenciales inválidas" });
  }

  // 🎫 Firmar token con datos mínimos
  const token = jwt.sign(
    { id: user.id, username: user.username, email: user.email },
    JWT_SECRET,
    { expiresIn: "1h" }
  );

  return res.json({ message: "✅ Login exitoso", token });
});

// Endpoint de métricas
app.get('/metrics', async (req, res) => {
  res.set('Content-Type', register.contentType);
  res.end(await register.metrics());
});


// ----------------------------------------------------------
// 🔓 Desencriptar contraseña recibida desde el Frontend
// ----------------------------------------------------------
function decryptPassword(encrypted) {
  // 1️⃣ Decodificar texto Base64 enviado desde el front
  const decoded = Buffer.from(encrypted, "base64").toString("utf8");

  // 2️⃣ Validar que termine con la clave compartida (integridad)
  if (!decoded.endsWith(SECRET_KEY)) {
    throw new Error("Clave inválida o mensaje alterado");
  }

  // 3️⃣ Retornar la contraseña original sin la clave secreta
  return decoded.slice(0, -SECRET_KEY.length);
}

// ----------------------------------------------------------
// 🧾 REGISTRO DE USUARIO — Requiere token y encripta contraseñas
// ----------------------------------------------------------
app.post('/register', async (req, res) => {
  try {
    writeLog("INFO", "Registro de usuarios");

    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      writeLog("ERROR", 'Faltan campos requeridos' );

      return res.status(400).json({ error: 'Faltan campos requeridos' });
    }

    // 1️⃣ Desencriptar clave recibida desde el frontend
    // const passwordPlain = decryptPassword(password);

    // 2️⃣ Generar hash seguro antes de guardar
    const hash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    console.log("🔐 Clave hasheada:", hash);

    // 3️⃣ Crear usuario en la base de datos
    const newUser = await User.create({
      username,
      email,
      password: hash,
    });

    return res.status(201).json({
      message: '✅ Usuario registrado exitosamente',
      user: {
        id: newUser.id,
        username: newUser.username,
        email: newUser.email,
      },
    });
  } catch (error) {
    writeLog("ERROR", "❌ Error al registrar usuario:");

    console.error("❌ Error al registrar usuario:", error);
    res.status(400).json({
      error: 'Error al registrar usuario',
      details: error.message,
    });
  }
});

// ----------------------------------------------------------
// 📋 Obtener todos los usuarios (protegido)
// ----------------------------------------------------------
app.get("/users", async (req, res) => {
  try {
    writeLog("INFO", 'obtener usuarios' );
    const users = await User.findAll({
      attributes: ["id", "username", "email"],
    });
    res.json(users);
  } catch (error) {
    writeLog("ERROR", "❌ Error al obtener usuarios:");

    console.error("Error al obtener usuarios:", error);
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

// ----------------------------------------------------------
// ⚠️ Endpoint sin autenticación (solo para desarrollo)
// ----------------------------------------------------------
app.get("/usersSinSeguridad", async (req, res) => {
  try {
    writeLog("INFO", 'obtener usuarios sin seguridad' );
    const users = await User.findAll({
      attributes: ["id", "username", "email"],
    });
    res.json(users);
  } catch (error) {
    writeLog("ERROR", "❌ Error al obtener usuarios sin seguridad");
    console.error("Error al obtener usuarios:", error);
    res.status(500).json({ error: "Error al obtener usuarios" });
  }
});

// ----------------------------------------------------------
// 🔑 Actualizar contraseña del usuario autenticado
// ----------------------------------------------------------
app.put("/actualizaContrasena", async (req, res) => {
  try {
    writeLog("INFO", 'actualizar contraseña' );
    const { username, password, newPassword } = req.body;

    if (!username || !password || !newPassword) {
      return res.status(400).json({ error: "Faltan datos obligatorios" });
    }

    // 🧩 Desencriptar contraseñas enviadas desde el frontend
    // const plainPassword = decryptPassword(password);
    // const plainNewPassword = decryptPassword(newPassword);

    // 🔍 Buscar usuario en BD
    const user = await User.findOne({
      where: { username },
      attributes: ["id", "username", "email", "password"],
    });

    if (!user) {
        writeLog("ERROR", username+": Usuario no encontrado" );
        return res.status(404).json({ error: "Usuario no encontrado" });
    }

    // 🔒 Verificar contraseña actual
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
        writeLog("ERROR", username+": Contraseña actual incorrecta" );
      return res.status(401).json({ error: "Contraseña actual incorrecta" });
    }

    // ✅ Generar nuevo hash seguro
    const newHash = await bcrypt.hash(password, BCRYPT_ROUNDS);

    // 💾 Actualizar registro del usuario
    await user.update({ password: newHash });

    return res.json({
      message: "✅ Contraseña actualizada correctamente",
      user: {
        id: user.id,
        username: user.username,
        email: user.email,
      },
    });
  } catch (error) {
    writeLog("ERROR", "❌ Error interno al actualizar la contraseña" );
    console.error("Error al actualizar contraseña:", error);
    res.status(500).json({
      error: "❌ Error interno al actualizar la contraseña",
      details: error.message,
    });
  }
});

// ----------------------------------------------------------
// 🚀 Iniciar servidor
// ----------------------------------------------------------
const PORT = process.env.PORT || 3001;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Servidor corriendo en puerto ${PORT}`);
});