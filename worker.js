// ============================================================================
//  ASLAN — Sistema de Gestión Interna + Portal del Cliente  ·  v2.0
//  Cloudflare Worker (ES Module) · backend + frontend en UN solo archivo
//  Stack: Workers + D1 (DB) + KV (SESSIONS) + R2 (FILES)
//  Roles: admin · gerente · empleado · cliente
//  Sin dependencias npm en runtime. CDN solo en el frontend.
// ============================================================================
//
//  DESPLIEGUE RÁPIDO (resumen):
//   1) Necesitas un wrangler.toml con bindings: DB (D1), SESSIONS (KV), FILES (R2)
//      y un secret JWT_SECRET (wrangler secret put JWT_SECRET).
//   2) wrangler deploy
//   3) Inicializa la base UNA sola vez:  GET  /api/setup   (crea tablas + datos demo)
//   4) Entra al sistema interno en  /   y al portal del cliente en  /portal
//
//  Usuarios demo que crea /api/setup:
//   admin@aslan.com    / Admin2024!     (admin)
//   gerente@aslan.com  / Gerente2024!   (gerente)
//   empleado@aslan.com / Emp2024!       (empleado)
//   cliente@demo.com   / Cliente2024!   (cliente — solo /portal)
// ============================================================================

// ---------------------------------------------------------------------------
//  CONSTANTES GLOBALES
// ---------------------------------------------------------------------------
const EMPRESA = {
  nombre: "ASLAN",
  direccion: "Luis Carracci 50, Delegación Benito Juárez, CDMX",
  email: "contacto@marmolesaslan.com",
  telefono: "+52 55 7609 8525",
  whatsapp: "525576098525",
  rfc: "ASL123456XYZ",
};

const ROLES = ["admin", "gerente", "empleado", "cliente"];

// Las 8 etapas del proceso ASLAN (visibles en el portal del cliente)
const ETAPAS = [
  { clave: "cotizacion_aceptada", nombre: "Cotización Aceptada", icono: "📋", desc: "El proyecto fue confirmado" },
  { clave: "material_confirmado", nombre: "Material en Almacén", icono: "🎯", desc: "Tu material está en nuestro almacén" },
  { clave: "pendiente_aprobacion", nombre: "Losa Lista para Aprobar", icono: "👁️", desc: "Requiere tu aprobación" },
  { clave: "en_corte", nombre: "En Proceso de Corte", icono: "⚙️", desc: "Tu mármol está siendo procesado" },
  { clave: "control_calidad", nombre: "Control de Calidad", icono: "🔍", desc: "Revisión y acabados finales" },
  { clave: "listo_entrega", nombre: "Listo para Entrega", icono: "📦", desc: "Tu pedido está listo" },
  { clave: "en_camino", nombre: "En Camino", icono: "🚛", desc: "Tu pedido está en ruta" },
  { clave: "entregado", nombre: "Entregado", icono: "✅", desc: "Proyecto completado" },
];

// ---------------------------------------------------------------------------
//  HELPERS DE RESPUESTA
// ---------------------------------------------------------------------------
const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,PUT,DELETE,OPTIONS",
  "access-control-allow-headers": "Content-Type, Authorization, X-Setup-Token",
};

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json; charset=utf-8", ...CORS, ...extra },
  });
}
const ok = (data = null) => json({ ok: true, data });
const fail = (error, status = 400) => json({ ok: false, error }, status);

function html(body, status = 200) {
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", ...CORS } });
}

// ---------------------------------------------------------------------------
//  BASE64URL
// ---------------------------------------------------------------------------
function bufToB64url(buf) {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlToBuf(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}
const enc = new TextEncoder();

// ---------------------------------------------------------------------------
//  CONTRASEÑAS  (PBKDF2 · 100k · SHA-256 · salt 32 bytes)  ->  "salt:hash"
// ---------------------------------------------------------------------------
async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256
  );
  return bufToB64url(salt) + ":" + bufToB64url(new Uint8Array(bits));
}
async function verifyPassword(password, stored) {
  try {
    const [saltB64, hashB64] = stored.split(":");
    const salt = b64urlToBuf(saltB64);
    const key = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, key, 256
    );
    return bufToB64url(new Uint8Array(bits)) === hashB64;
  } catch (e) {
    return false;
  }
}

// ---------------------------------------------------------------------------
//  JWT  (HMAC-SHA256 vía Web Crypto)
// ---------------------------------------------------------------------------
async function hmacKey(secret) {
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function createJWT(payload, secret, horas = 8) {
  const header = { alg: "HS256", typ: "JWT" };
  const now = Math.floor(Date.now() / 1000);
  const body = { ...payload, iat: now, exp: now + horas * 3600 };
  const p1 = bufToB64url(enc.encode(JSON.stringify(header)));
  const p2 = bufToB64url(enc.encode(JSON.stringify(body)));
  const data = p1 + "." + p2;
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return data + "." + bufToB64url(new Uint8Array(sig));
}
async function verifyJWT(token, secret) {
  try {
    const [p1, p2, p3] = token.split(".");
    if (!p1 || !p2 || !p3) return null;
    const key = await hmacKey(secret);
    const valid = await crypto.subtle.verify("HMAC", key, b64urlToBuf(p3), enc.encode(p1 + "." + p2));
    if (!valid) return null;
    const payload = JSON.parse(new TextDecoder().decode(b64urlToBuf(p2)));
    if (payload.exp && payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch (e) {
    return null;
  }
}

// ---------------------------------------------------------------------------
//  AUTH MIDDLEWARE
// ---------------------------------------------------------------------------
function getToken(request) {
  const h = request.headers.get("Authorization") || "";
  if (h.startsWith("Bearer ")) return h.slice(7);
  return null;
}
async function requireAuth(request, env) {
  const token = getToken(request);
  if (!token) return null;
  const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  return await verifyJWT(token, secret);
}
function hasRole(payload, ...roles) {
  return payload && roles.includes(payload.rol);
}

// ---------------------------------------------------------------------------
//  AUDITORÍA
// ---------------------------------------------------------------------------
async function audit(env, usuarioId, accion, modulo, registroId, datos, request) {
  try {
    await env.DB.prepare(
      "INSERT INTO audit_log (usuario_id, accion, modulo, registro_id, datos_json, ip, user_agent) VALUES (?,?,?,?,?,?,?)"
    ).bind(
      usuarioId || null, accion, modulo, registroId || null,
      datos ? JSON.stringify(datos) : null,
      request ? (request.headers.get("cf-connecting-ip") || "") : "",
      request ? (request.headers.get("user-agent") || "") : ""
    ).run();
  } catch (e) { /* no romper el flujo por auditoría */ }
}

// ============================================================================
//  ESQUEMA D1 EMBEBIDO  (se ejecuta en /api/setup)
// ============================================================================
const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS usuarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  rol TEXT NOT NULL DEFAULT 'empleado',
  cargo TEXT, area TEXT, telefono TEXT, foto_url TEXT,
  activo INTEGER NOT NULL DEFAULT 1,
  password_debe_cambiar INTEGER NOT NULL DEFAULT 0,
  ultimo_acceso DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS clientes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL, empresa TEXT, tipo TEXT, etapa TEXT DEFAULT 'prospecto',
  telefono TEXT, email TEXT, ciudad TEXT, direccion TEXT, lat REAL, lon REAL,
  rfc TEXT, notas TEXT, empleado_asignado_id INTEGER,
  valor_vida_calculado REAL DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS contactos_cliente (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id INTEGER NOT NULL, nombre TEXT, cargo TEXT, telefono TEXT,
  email TEXT, whatsapp TEXT, preferencia_contacto TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS notas_crm (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id INTEGER NOT NULL, usuario_id INTEGER, nota TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cotizaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folio TEXT, cliente_id INTEGER, usuario_id INTEGER,
  estado TEXT DEFAULT 'borrador',
  subtotal REAL DEFAULT 0, descuento_global_pct REAL DEFAULT 0,
  iva_pct REAL DEFAULT 16, total REAL DEFAULT 0,
  vigencia_dias INTEGER DEFAULT 15, notas TEXT, condiciones TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS cotizacion_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cotizacion_id INTEGER NOT NULL, producto_id INTEGER,
  descripcion TEXT, cantidad REAL, unidad TEXT,
  precio_unitario REAL, descuento_linea_pct REAL DEFAULT 0, subtotal_linea REAL
);
CREATE TABLE IF NOT EXISTS productos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sku TEXT, nombre TEXT NOT NULL, categoria TEXT, acabado TEXT,
  dimensiones TEXT, procedencia TEXT,
  stock_actual REAL DEFAULT 0, stock_minimo REAL DEFAULT 0,
  unidad TEXT DEFAULT 'm2', ubicacion_almacen TEXT,
  precio_costo REAL DEFAULT 0, precio_venta REAL DEFAULT 0,
  notas_tecnicas TEXT, estado TEXT DEFAULT 'activo',
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS fotos_producto (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  producto_id INTEGER NOT NULL, url_r2 TEXT, orden INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS movimientos_inventario (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  producto_id INTEGER NOT NULL, tipo TEXT, cantidad REAL,
  referencia TEXT, motivo TEXT, usuario_id INTEGER, proveedor_id INTEGER,
  notas TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proveedores (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT NOT NULL, pais TEXT, contacto TEXT, telefono TEXT, email TEXT,
  tiempo_entrega_dias INTEGER, notas TEXT, activo INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS empleados_perfil (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL UNIQUE, curp TEXT, rfc TEXT,
  fecha_nacimiento TEXT, fecha_ingreso TEXT, salario REAL, tipo_contrato TEXT,
  consentimiento_gps INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS gps_checkins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL, tipo TEXT, lat REAL, lon REAL,
  precision_metros REAL, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS geofencing_config (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  nombre TEXT, lat_centro REAL, lon_centro REAL, radio_metros REAL,
  activo INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS geofencing_alertas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER, lat REAL, lon REAL, distancia_metros REAL,
  revisada INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proyectos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folio TEXT, cotizacion_id INTEGER, cliente_id INTEGER,
  descripcion TEXT, tipo TEXT, estado TEXT DEFAULT 'nuevo',
  avance_pct INTEGER DEFAULT 0,
  etapa_portal TEXT DEFAULT 'cotizacion_aceptada',
  portal_activo INTEGER DEFAULT 0,
  m2_procesados REAL DEFAULT 0, m2_totales REAL DEFAULT 0,
  fecha_inicio TEXT, fecha_entrega_estimada TEXT, fecha_entrega_real TEXT,
  material_principal TEXT, notas TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS proyecto_empleados (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, usuario_id INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS proyecto_tareas (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, descripcion TEXT,
  completada INTEGER DEFAULT 0, completada_en DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proyecto_fotos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, url_r2 TEXT, etapa TEXT,
  descripcion TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proyecto_materiales (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, producto_id INTEGER,
  cantidad_requerida REAL, cantidad_usada REAL, reservado INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wa_conversaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  numero_wa TEXT, cliente_id INTEGER, asignado_a INTEGER,
  ultimo_mensaje_en DATETIME, no_leidos INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS wa_mensajes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  conversacion_id INTEGER NOT NULL, direction TEXT, tipo TEXT,
  contenido TEXT, media_url TEXT, wa_message_id TEXT,
  usuario_enviador_id INTEGER, leido INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER, accion TEXT, modulo TEXT, registro_id INTEGER,
  datos_json TEXT, ip TEXT, user_agent TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portal_accesos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL UNIQUE, cliente_id INTEGER NOT NULL UNIQUE,
  activo INTEGER DEFAULT 1, ultimo_acceso DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS proyecto_etapas_historial (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, etapa_clave TEXT, etapa_nombre TEXT,
  nota TEXT, foto_url TEXT, visible_cliente INTEGER DEFAULT 1,
  cambiado_por_id INTEGER, avance_pct INTEGER DEFAULT 0,
  m2_procesados REAL, m2_totales REAL, fecha_estimada_entrega TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portal_fotos_proyecto (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, tipo TEXT, url_r2 TEXT,
  descripcion TEXT, orden INTEGER DEFAULT 0, subido_por_id INTEGER,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portal_aprobaciones_losa (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, foto_url_losa TEXT, descripcion_losa TEXT,
  estado TEXT DEFAULT 'pendiente', nota_cliente TEXT,
  aprobado_por_id INTEGER, respondido_en DATETIME,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portal_mensajes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  proyecto_id INTEGER NOT NULL, remitente_id INTEGER, direction TEXT,
  mensaje TEXT, leido INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS portal_notificaciones (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  usuario_id INTEGER NOT NULL, tipo TEXT, titulo TEXT, mensaje TEXT,
  proyecto_id INTEGER, leida INTEGER DEFAULT 0,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_clientes_etapa ON clientes(etapa);
CREATE INDEX IF NOT EXISTS idx_productos_cat ON productos(categoria);
CREATE INDEX IF NOT EXISTS idx_proyectos_cliente ON proyectos(cliente_id);
CREATE INDEX IF NOT EXISTS idx_portal_msg_proy ON portal_mensajes(proyecto_id);
CREATE INDEX IF NOT EXISTS idx_etapas_proy ON proyecto_etapas_historial(proyecto_id);
`;

// ---------------------------------------------------------------------------
//  SETUP: crear tablas + datos demo
// ---------------------------------------------------------------------------
async function runSetup(env, request) {
  // Solo permitido si no hay admin todavía, o si trae el X-Setup-Token correcto
  let yaHayAdmin = false;
  try {
    const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM usuarios WHERE rol='admin' AND deleted_at IS NULL").first();
    yaHayAdmin = r && r.n > 0;
  } catch (e) { yaHayAdmin = false; }

  if (yaHayAdmin) {
    const tok = request.headers.get("X-Setup-Token");
    if (!env.SETUP_TOKEN || tok !== env.SETUP_TOKEN) {
      return fail("El sistema ya está inicializado. Usa el header X-Setup-Token para re-ejecutar.", 403);
    }
  }

  // Crear todas las tablas
  for (const stmt of SCHEMA_SQL.split(";")) {
    const s = stmt.trim();
    if (s) await env.DB.prepare(s).run();
  }

  // Usuarios demo
  const usuarios = [
    ["Administrador ASLAN", "admin@aslan.com", "Admin2024!", "admin", "Dirección", "administracion", 0],
    ["Gerente ASLAN", "gerente@aslan.com", "Gerente2024!", "gerente", "Gerente General", "administracion", 1],
    ["Empleado ASLAN", "empleado@aslan.com", "Emp2024!", "empleado", "Asesor de Ventas", "ventas", 1],
    ["Cliente Demo", "cliente@demo.com", "Cliente2024!", "cliente", "Cliente", "", 1],
  ];
  for (const u of usuarios) {
    const existe = await env.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind(u[1]).first();
    if (existe) continue;
    const ph = await hashPassword(u[2]);
    await env.DB.prepare(
      "INSERT INTO usuarios (nombre,email,password_hash,rol,cargo,area,password_debe_cambiar) VALUES (?,?,?,?,?,?,?)"
    ).bind(u[0], u[1], ph, u[3], u[4], u[5], u[6]).run();
  }

  // Cliente CRM demo (ligado al usuario cliente@demo.com)
  let clienteDemo = await env.DB.prepare("SELECT id FROM clientes WHERE email=?").bind("cliente@demo.com").first();
  if (!clienteDemo) {
    const emp = await env.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind("empleado@aslan.com").first();
    await env.DB.prepare(
      "INSERT INTO clientes (nombre,empresa,tipo,etapa,telefono,email,ciudad,empleado_asignado_id,valor_vida_calculado) VALUES (?,?,?,?,?,?,?,?,?)"
    ).bind("Arq. Daniela Ríos", "Estudio Ríos Arquitectura", "arquitecto", "cliente_activo",
           "5512345678", "cliente@demo.com", "CDMX", emp ? emp.id : null, 480000).run();
    clienteDemo = await env.DB.prepare("SELECT id FROM clientes WHERE email=?").bind("cliente@demo.com").first();
  }

  // 5 clientes adicionales de ejemplo
  const clientesEj = [
    ["Constructora Montería", "Constructora Montería SA", "constructora", "negociacion", "5523456789", "ventas@monteria.mx", "Monterrey", 1250000],
    ["Inmobiliaria Cumbre", "Grupo Cumbre", "desarrolladora", "propuesta_enviada", "5534567890", "compras@cumbre.mx", "Guadalajara", 0],
    ["Roberto Salinas", "Residencial", "residencial", "primer_contacto", "5545678901", "rsalinas@gmail.com", "CDMX", 0],
    ["Arq. Mónica Vela", "Vela Diseño", "arquitecto", "prospecto", "5556789012", "monica@veladiseno.mx", "Puebla", 0],
    ["Desarrollos Altavista", "Altavista Capital", "desarrolladora", "cliente_activo", "5567890123", "obras@altavista.mx", "CDMX", 920000],
  ];
  const cn = await env.DB.prepare("SELECT COUNT(*) AS n FROM clientes").first();
  if (cn.n < 3) {
    for (const c of clientesEj) {
      await env.DB.prepare(
        "INSERT INTO clientes (nombre,empresa,tipo,etapa,telefono,email,ciudad,valor_vida_calculado) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]).run();
    }
  }

  // 15 productos ASLAN
  const productos = [
    ["ASL-MAR-0001", "Calacatta Gold", "Mármol Importado", "Pulido", "300x180x2 cm", "Italia", 85, 20, "m2", "Rack A-1", 4200, 7800],
    ["ASL-MAR-0002", "Statuario Venato", "Mármol Importado", "Pulido", "300x160x2 cm", "Italia", 60, 15, "m2", "Rack A-2", 4600, 8400],
    ["ASL-MAR-0003", "Emperador Dark", "Mármol Importado", "Pulido", "280x170x2 cm", "España", 95, 20, "m2", "Rack A-3", 2800, 5200],
    ["ASL-MAR-0004", "Crema Marfil", "Mármol Importado", "Pulido", "300x180x2 cm", "España", 120, 25, "m2", "Rack A-4", 2400, 4600],
    ["ASL-MAR-0005", "Negro Marquina", "Mármol Importado", "Pulido", "290x160x2 cm", "España", 70, 15, "m2", "Rack B-1", 3100, 5800],
    ["ASL-MAR-0006", "Travertino Romano", "Mármol Importado", "Hone", "300x150x2 cm", "Italia", 110, 25, "m2", "Rack B-2", 1900, 3800],
    ["ASL-MAR-0007", "Onix Miel", "Mármol Importado", "Pulido", "260x140x2 cm", "Irán", 25, 8, "m2", "Rack B-3", 6800, 12500],
    ["ASL-MAR-0008", "Botticino Classico", "Mármol Importado", "Pulido", "300x170x2 cm", "Italia", 80, 18, "m2", "Rack B-4", 2600, 4900],
    ["ASL-NAC-0001", "Crema Maya", "Mármol Nacional", "Pulido", "290x150x2 cm", "Yucatán", 200, 40, "m2", "Rack C-1", 950, 2100],
    ["ASL-NAC-0002", "Travertino Durango", "Mármol Nacional", "Hone", "300x150x2 cm", "Durango", 180, 35, "m2", "Rack C-2", 880, 1950],
    ["ASL-NAC-0003", "Rosa Tepic", "Mármol Nacional", "Pulido", "280x140x2 cm", "Nayarit", 90, 20, "m2", "Rack C-3", 720, 1650],
    ["ASL-NAC-0004", "Negro San Luis", "Mármol Nacional", "Pulido", "270x150x2 cm", "San Luis Potosí", 60, 15, "m2", "Rack C-4", 1100, 2400],
    ["ASL-CUA-0001", "Cuarzo Blanco Polar", "Cuarzo", "Pulido", "320x160x2 cm", "—", 45, 12, "m2", "Rack D-1", 3200, 6200],
    ["ASL-CUC-0001", "Cuarcita Taj Mahal", "Cuarcita", "Pulido", "300x180x2 cm", "Brasil", 30, 8, "m2", "Rack D-2", 4800, 8900],
    ["ASL-POR-0001", "Porcelanato Marfil 120x120", "Porcelanato", "Natural", "120x120x1.2 cm", "España", 320, 60, "m2", "Rack E-1", 480, 1100],
  ];
  const pn = await env.DB.prepare("SELECT COUNT(*) AS n FROM productos").first();
  if (pn.n < 5) {
    for (const p of productos) {
      await env.DB.prepare(
        "INSERT INTO productos (sku,nombre,categoria,acabado,dimensiones,procedencia,stock_actual,stock_minimo,unidad,ubicacion_almacen,precio_costo,precio_venta) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)"
      ).bind(p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], p[8], p[9], p[10], p[11]).run();
    }
  }

  // Cotización + proyecto demo ligados al cliente demo, con portal activo
  const proyN = await env.DB.prepare("SELECT COUNT(*) AS n FROM proyectos").first();
  if (proyN.n === 0 && clienteDemo) {
    const emp = await env.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind("empleado@aslan.com").first();
    await env.DB.prepare(
      "INSERT INTO cotizaciones (folio,cliente_id,usuario_id,estado,subtotal,iva_pct,total,notas) VALUES (?,?,?,?,?,?,?,?)"
    ).bind("COT-2026-0001", clienteDemo.id, emp ? emp.id : null, "aceptada", 414000, 16, 480240, "Suministro y corte Calacatta Gold").run();
    const cot = await env.DB.prepare("SELECT id FROM cotizaciones WHERE folio=?").bind("COT-2026-0001").first();

    await env.DB.prepare(
      "INSERT INTO proyectos (folio,cotizacion_id,cliente_id,descripcion,tipo,estado,avance_pct,etapa_portal,portal_activo,m2_procesados,m2_totales,fecha_inicio,fecha_entrega_estimada,material_principal) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind("PROY-2026-0001", cot ? cot.id : null, clienteDemo.id,
           "Suministro y corte de cubiertas — Residencia Lomas", "completo", "ejecucion", 60,
           "en_corte", 1, 28.5, 47.5,
           "2026-05-20", "2026-06-18", "Calacatta Gold").run();
    const proy = await env.DB.prepare("SELECT id FROM proyectos WHERE folio=?").bind("PROY-2026-0001").first();

    if (proy) {
      // Historial de etapas
      const hist = [
        ["cotizacion_aceptada", "Cotización Aceptada", "Proyecto confirmado. ¡Gracias por tu confianza!"],
        ["material_confirmado", "Material en Almacén", "Tu Calacatta Gold llegó a nuestro almacén."],
        ["en_corte", "En Proceso de Corte", "Comenzamos el corte de tus cubiertas."],
      ];
      for (const h of hist) {
        await env.DB.prepare(
          "INSERT INTO proyecto_etapas_historial (proyecto_id,etapa_clave,etapa_nombre,nota,cambiado_por_id,avance_pct) VALUES (?,?,?,?,?,?)"
        ).bind(proy.id, h[0], h[1], h[2], emp ? emp.id : null, 60).run();
      }
      // Losa para aprobación (ya aprobada en el demo)
      await env.DB.prepare(
        "INSERT INTO portal_aprobaciones_losa (proyecto_id,foto_url_losa,descripcion_losa,estado) VALUES (?,?,?,?)"
      ).bind(proy.id, "", "Losa Calacatta Gold seleccionada · 300x180 cm · veta central", "aprobado").run();
      // Mensaje demo
      await env.DB.prepare(
        "INSERT INTO portal_mensajes (proyecto_id,remitente_id,direction,mensaje) VALUES (?,?,?,?)"
      ).bind(proy.id, emp ? emp.id : null, "aslan", "Hola Daniela, tu material ya está en proceso de corte. Cualquier duda aquí estamos.").run();
      // Vincular portal_accesos
      const uCliente = await env.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind("cliente@demo.com").first();
      const existeAcc = await env.DB.prepare("SELECT id FROM portal_accesos WHERE usuario_id=?").bind(uCliente.id).first();
      if (!existeAcc) {
        await env.DB.prepare("INSERT INTO portal_accesos (usuario_id,cliente_id,activo) VALUES (?,?,1)").bind(uCliente.id, clienteDemo.id).run();
      }
    }
  }

  return ok({ mensaje: "Sistema inicializado correctamente.", usuarios_demo: usuarios.map(u => ({ email: u[1], rol: u[3] })) });
}

// ============================================================================
//  API — AUTENTICACIÓN
// ============================================================================
// LOGIN ÚNICO para todos. El destino (portal o sistema interno) se decide
// por el rol del usuario, no por la URL. El cliente entra por el mismo lugar.
async function handleLogin(request, env) {
  const body = await request.json().catch(() => ({}));
  const { email, password } = body;
  if (!email || !password) return fail("Email y contraseña son obligatorios.");

  const u = await env.DB.prepare("SELECT * FROM usuarios WHERE email=? AND deleted_at IS NULL").bind(email).first();
  if (!u || !u.activo) return fail("Credenciales inválidas.", 401);

  const valido = await verifyPassword(password, u.password_hash);
  if (!valido) return fail("Credenciales inválidas.", 401);

  const esCliente = u.rol === "cliente";
  await env.DB.prepare("UPDATE usuarios SET ultimo_acceso=CURRENT_TIMESTAMP WHERE id=?").bind(u.id).run();
  if (esCliente) {
    // Registrar último acceso al portal si tiene acceso configurado
    await env.DB.prepare("UPDATE portal_accesos SET ultimo_acceso=CURRENT_TIMESTAMP WHERE usuario_id=?").bind(u.id).run().catch(() => {});
  }
  const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  const token = await createJWT({ sub: u.id, rol: u.rol, nombre: u.nombre, tipo: esCliente ? "portal" : "interno" }, secret);
  await audit(env, u.id, "login", "auth", u.id, null, request);

  return ok({
    token,
    usuario: {
      id: u.id, nombre: u.nombre, email: u.email, rol: u.rol, cargo: u.cargo,
      debe_cambiar: !!u.password_debe_cambiar,
      destino: esCliente ? "portal" : "interno",
    },
  });
}

async function handleChangePassword(request, env, payload) {
  const body = await request.json().catch(() => ({}));
  const { actual, nueva } = body;
  if (!nueva || nueva.length < 6) return fail("La nueva contraseña debe tener al menos 6 caracteres.");
  const u = await env.DB.prepare("SELECT * FROM usuarios WHERE id=?").bind(payload.sub).first();
  if (!u) return fail("Usuario no encontrado.", 404);
  if (actual && !(await verifyPassword(actual, u.password_hash))) return fail("La contraseña actual es incorrecta.", 401);
  const ph = await hashPassword(nueva);
  await env.DB.prepare("UPDATE usuarios SET password_hash=?, password_debe_cambiar=0, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(ph, u.id).run();
  await audit(env, u.id, "change_password", "auth", u.id, null, request);
  return ok({ mensaje: "Contraseña actualizada." });
}

// ============================================================================
//  API — DASHBOARD
// ============================================================================
async function dashboardStats(env) {
  const q = async (sql) => (await env.DB.prepare(sql).first()).n;
  const clientes = await q("SELECT COUNT(*) AS n FROM clientes WHERE deleted_at IS NULL");
  const cotizMes = await q("SELECT COUNT(*) AS n FROM cotizaciones WHERE deleted_at IS NULL AND created_at >= date('now','start of month')");
  const proyectos = await q("SELECT COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL AND estado NOT IN ('cerrado','entregado')");
  const stockCritico = await q("SELECT COUNT(*) AS n FROM productos WHERE deleted_at IS NULL AND stock_actual <= stock_minimo");
  const empleadosHoy = await q("SELECT COUNT(DISTINCT usuario_id) AS n FROM gps_checkins WHERE tipo='checkin' AND created_at >= date('now')");
  const pipeline = (await env.DB.prepare("SELECT COALESCE(SUM(total),0) AS n FROM cotizaciones WHERE estado IN ('enviada','borrador','aceptada') AND deleted_at IS NULL").first()).n;
  const porCategoria = await env.DB.prepare("SELECT categoria, COUNT(*) AS n FROM productos WHERE deleted_at IS NULL GROUP BY categoria").all();
  const recientes = await env.DB.prepare(
    "SELECT c.folio, c.total, c.estado, cl.nombre AS cliente FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id WHERE c.deleted_at IS NULL ORDER BY c.created_at DESC LIMIT 10"
  ).all();
  return ok({
    kpis: { clientes, cotizMes, proyectos, stockCritico, empleadosHoy, pipeline },
    porCategoria: porCategoria.results || [],
    recientes: recientes.results || [],
  });
}

// ============================================================================
//  API — CLIENTES (CRM)
// ============================================================================
async function handleClientes(request, env, payload, method, id) {
  if (method === "GET" && !id) {
    const r = await env.DB.prepare(
      "SELECT c.*, u.nombre AS empleado_nombre FROM clientes c LEFT JOIN usuarios u ON u.id=c.empleado_asignado_id WHERE c.deleted_at IS NULL ORDER BY c.updated_at DESC"
    ).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const c = await env.DB.prepare("SELECT * FROM clientes WHERE id=? AND deleted_at IS NULL").bind(id).first();
    if (!c) return fail("Cliente no encontrado.", 404);
    return ok(c);
  }
  if (method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.nombre) return fail("El nombre es obligatorio.");
    const res = await env.DB.prepare(
      "INSERT INTO clientes (nombre,empresa,tipo,etapa,telefono,email,ciudad,direccion,rfc,notas,empleado_asignado_id) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(b.nombre, b.empresa || null, b.tipo || null, b.etapa || "prospecto", b.telefono || null,
           b.email || null, b.ciudad || null, b.direccion || null, b.rfc || null, b.notas || null,
           b.empleado_asignado_id || null).run();
    await audit(env, payload.sub, "crear", "clientes", res.meta.last_row_id, b, request);
    return ok({ id: res.meta.last_row_id });
  }
  if (method === "PUT" && id) {
    const b = await request.json().catch(() => ({}));
    const campos = ["nombre", "empresa", "tipo", "etapa", "telefono", "email", "ciudad", "direccion", "rfc", "notas", "empleado_asignado_id"];
    const sets = [], vals = [];
    for (const c of campos) if (c in b) { sets.push(c + "=?"); vals.push(b[c]); }
    if (!sets.length) return fail("Nada que actualizar.");
    vals.push(id);
    await env.DB.prepare("UPDATE clientes SET " + sets.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...vals).run();
    await audit(env, payload.sub, "editar", "clientes", id, b, request);
    return ok({ id });
  }
  if (method === "DELETE" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
    await env.DB.prepare("UPDATE clientes SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    await audit(env, payload.sub, "eliminar", "clientes", id, null, request);
    return ok({ id });
  }
  return fail("Método no soportado.", 405);
}

// ============================================================================
//  API — COTIZACIONES
// ============================================================================
// Genera el siguiente folio del año: PREFIJO-AÑO-0001
async function siguienteFolio(env, prefijo, tabla) {
  const year = new Date().getFullYear();
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM " + tabla + " WHERE folio LIKE ?").bind(prefijo + "-" + year + "-%").first();
  return prefijo + "-" + year + "-" + String((r.n || 0) + 1).padStart(4, "0");
}

// Calcula totales a partir de las líneas + descuentos + IVA
function calcularTotales(items, descGlobalPct, ivaPct) {
  let subtotal = 0;
  const lineas = items.map((it) => {
    const cant = Number(it.cantidad) || 0;
    const pu = Number(it.precio_unitario) || 0;
    const dl = Number(it.descuento_linea_pct) || 0;
    const sl = +(cant * pu * (1 - dl / 100)).toFixed(2);
    subtotal += sl;
    return { ...it, subtotal_linea: sl };
  });
  subtotal = +subtotal.toFixed(2);
  const base = +(subtotal * (1 - (Number(descGlobalPct) || 0) / 100)).toFixed(2);
  const iva = +(base * ((Number(ivaPct) || 0) / 100)).toFixed(2);
  const total = +(base + iva).toFixed(2);
  return { lineas, subtotal, total };
}

async function handleCotizaciones(request, env, payload, method, id, url) {
  if (method === "GET" && !id) {
    const clienteFiltro = url.searchParams.get("cliente");
    let sql = "SELECT c.*, cl.nombre AS cliente, u.nombre AS vendedor FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id LEFT JOIN usuarios u ON u.id=c.usuario_id WHERE c.deleted_at IS NULL";
    const binds = [];
    if (clienteFiltro) { sql += " AND c.cliente_id=?"; binds.push(clienteFiltro); }
    sql += " ORDER BY c.created_at DESC, c.id DESC";
    const r = await env.DB.prepare(sql).bind(...binds).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const c = await env.DB.prepare(
      "SELECT c.*, cl.nombre AS cliente, cl.empresa AS cliente_empresa, cl.rfc AS cliente_rfc FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id WHERE c.id=? AND c.deleted_at IS NULL"
    ).bind(id).first();
    if (!c) return fail("Cotización no encontrada.", 404);
    const items = await env.DB.prepare("SELECT * FROM cotizacion_items WHERE cotizacion_id=? ORDER BY id ASC").bind(id).all();
    c.items = items.results || [];
    return ok(c);
  }
  if (method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.cliente_id) return fail("Selecciona un cliente.");
    const items = Array.isArray(b.items) ? b.items.filter((it) => it && (it.descripcion || it.producto_id)) : [];
    if (!items.length) return fail("Agrega al menos una línea de producto.");
    const ivaPct = b.iva_pct !== undefined ? Number(b.iva_pct) : 16;
    const { lineas, subtotal, total } = calcularTotales(items, b.descuento_global_pct, ivaPct);
    const folio = await siguienteFolio(env, "COT", "cotizaciones");
    const res = await env.DB.prepare(
      "INSERT INTO cotizaciones (folio,cliente_id,usuario_id,estado,subtotal,descuento_global_pct,iva_pct,total,vigencia_dias,notas,condiciones) VALUES (?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(folio, b.cliente_id, payload.sub, b.estado || "borrador", subtotal,
           Number(b.descuento_global_pct) || 0, ivaPct, total, Number(b.vigencia_dias) || 15,
           b.notas || null, b.condiciones || null).run();
    const cotId = res.meta.last_row_id;
    for (const ln of lineas) {
      await env.DB.prepare(
        "INSERT INTO cotizacion_items (cotizacion_id,producto_id,descripcion,cantidad,unidad,precio_unitario,descuento_linea_pct,subtotal_linea) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(cotId, ln.producto_id || null, ln.descripcion || "", Number(ln.cantidad) || 0,
             ln.unidad || "m2", Number(ln.precio_unitario) || 0, Number(ln.descuento_linea_pct) || 0, ln.subtotal_linea).run();
    }
    await audit(env, payload.sub, "crear", "cotizaciones", cotId, { folio, total }, request);
    return ok({ id: cotId, folio, subtotal, total });
  }
  if (method === "PUT" && id) {
    const b = await request.json().catch(() => ({}));
    // Cambio de estado simple
    if (b.estado && Object.keys(b).length === 1) {
      const validos = ["borrador", "enviada", "aceptada", "rechazada", "expirada"];
      if (!validos.includes(b.estado)) return fail("Estado inválido.");
      await env.DB.prepare("UPDATE cotizaciones SET estado=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(b.estado, id).run();
      await audit(env, payload.sub, "estado", "cotizaciones", id, { estado: b.estado }, request);
      return ok({ id, estado: b.estado });
    }
    return fail("Para editar líneas, crea una nueva cotización (esta capa solo cambia el estado).");
  }
  if (method === "DELETE" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
    await env.DB.prepare("UPDATE cotizaciones SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    return ok({ id });
  }
  return fail("Método no soportado.", 405);
}

// Convierte una cotización aceptada en un proyecto/orden de trabajo
async function convertirCotizacion(request, env, payload, id) {
  const c = await env.DB.prepare("SELECT * FROM cotizaciones WHERE id=? AND deleted_at IS NULL").bind(id).first();
  if (!c) return fail("Cotización no encontrada.", 404);
  const yaProy = await env.DB.prepare("SELECT id, folio FROM proyectos WHERE cotizacion_id=? AND deleted_at IS NULL").bind(id).first();
  if (yaProy) return fail("Esta cotización ya tiene el proyecto " + yaProy.folio + ".", 409);

  const items = await env.DB.prepare("SELECT descripcion, cantidad, unidad FROM cotizacion_items WHERE cotizacion_id=? ORDER BY id ASC").bind(id).all();
  const lista = items.results || [];
  const material = lista.length ? (lista[0].descripcion || "Material") : "Material";
  let m2 = 0;
  lista.forEach((it) => { if ((it.unidad || "").toLowerCase() === "m2") m2 += Number(it.cantidad) || 0; });

  const folio = await siguienteFolio(env, "PROY", "proyectos");
  const res = await env.DB.prepare(
    "INSERT INTO proyectos (folio,cotizacion_id,cliente_id,descripcion,tipo,estado,etapa_portal,portal_activo,m2_totales,material_principal,fecha_inicio) VALUES (?,?,?,?,?,?,?,?,?,?,date('now'))"
  ).bind(folio, id, c.cliente_id, (c.notas || "Proyecto de " + c.folio), "completo", "nuevo",
         "cotizacion_aceptada", 0, m2, material).run();

  await env.DB.prepare("UPDATE cotizaciones SET estado='aceptada', updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
  await audit(env, payload.sub, "convertir", "cotizaciones", id, { proyecto: folio }, request);
  return ok({ proyecto_id: res.meta.last_row_id, folio });
}

// ============================================================================
//  API — PRODUCTOS (INVENTARIO)
// ============================================================================
async function handleProductos(request, env, payload, method, id) {
  if (method === "GET" && !id) {
    const r = await env.DB.prepare("SELECT * FROM productos WHERE deleted_at IS NULL ORDER BY categoria, nombre").all();
    return ok(r.results || []);
  }
  if (method === "POST") {
    if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente da de alta productos.", 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nombre) return fail("El nombre es obligatorio.");
    const sku = b.sku || await siguienteSku(env, b.categoria);
    const res = await env.DB.prepare(
      "INSERT INTO productos (sku,nombre,categoria,acabado,dimensiones,procedencia,stock_actual,stock_minimo,unidad,ubicacion_almacen,precio_costo,precio_venta,notas_tecnicas,estado) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(sku, b.nombre, b.categoria || null, b.acabado || null, b.dimensiones || null,
           b.procedencia || null, Number(b.stock_actual) || 0, Number(b.stock_minimo) || 0, b.unidad || "m2",
           b.ubicacion_almacen || null, Number(b.precio_costo) || 0, Number(b.precio_venta) || 0, b.notas_tecnicas || null, b.estado || "activo").run();
    await audit(env, payload.sub, "crear", "productos", res.meta.last_row_id, { sku }, request);
    return ok({ id: res.meta.last_row_id, sku });
  }
  if (method === "PUT" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente edita productos.", 403);
    const b = await request.json().catch(() => ({}));
    const campos = ["sku", "nombre", "categoria", "acabado", "dimensiones", "procedencia", "stock_actual", "stock_minimo", "unidad", "ubicacion_almacen", "precio_costo", "precio_venta", "notas_tecnicas", "estado"];
    const sets = [], vals = [];
    for (const c of campos) if (c in b) { sets.push(c + "=?"); vals.push(b[c]); }
    if (!sets.length) return fail("Nada que actualizar.");
    vals.push(id);
    await env.DB.prepare("UPDATE productos SET " + sets.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...vals).run();
    await audit(env, payload.sub, "editar", "productos", id, b, request);
    return ok({ id });
  }
  if (method === "DELETE" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
    await env.DB.prepare("UPDATE productos SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    return ok({ id });
  }
  return fail("Método no soportado.", 405);
}

// SKU automático: ASL-{CAT3}-{####}
function skuPrefijo(cat) {
  const map = { "Mármol Importado": "MAR", "Mármol Nacional": "NAC", "Cuarzo": "CUA", "Cuarcita": "CUC", "Porcelanato": "POR", "Madera de Ingeniería": "MAD", "Granito": "GRA" };
  if (map[cat]) return map[cat];
  const limpio = (cat || "").normalize("NFD").replace(/[^A-Za-z]/g, "");
  return (limpio.slice(0, 3) || "OTR").toUpperCase();
}
async function siguienteSku(env, cat) {
  const pref = skuPrefijo(cat);
  const r = await env.DB.prepare("SELECT COUNT(*) AS n FROM productos WHERE sku LIKE ?").bind("ASL-" + pref + "-%").first();
  return "ASL-" + pref + "-" + String((r.n || 0) + 1).padStart(4, "0");
}

// ============================================================================
//  API — MOVIMIENTOS DE INVENTARIO
// ============================================================================
async function registrarMovimiento(request, env, payload, prodId) {
  // admin / gerente / empleado pueden registrar movimientos
  const prod = await env.DB.prepare("SELECT * FROM productos WHERE id=? AND deleted_at IS NULL").bind(prodId).first();
  if (!prod) return fail("Producto no encontrado.", 404);
  const b = await request.json().catch(() => ({}));
  const tipos = ["entrada", "salida", "ajuste", "reserva", "devolucion"];
  if (!tipos.includes(b.tipo)) return fail("Tipo de movimiento inválido.");
  const cant = Number(b.cantidad);
  if (b.tipo === "ajuste") { if (!(cant >= 0)) return fail("La cantidad de ajuste no puede ser negativa."); }
  else if (!(cant > 0)) return fail("La cantidad debe ser mayor a 0.");

  let nuevo = Number(prod.stock_actual) || 0;
  if (b.tipo === "entrada" || b.tipo === "devolucion") nuevo += cant;
  else if (b.tipo === "salida") nuevo -= cant;
  else if (b.tipo === "ajuste") nuevo = cant;          // fija el stock al valor contado
  // "reserva": no modifica el stock físico (queda como registro informativo)

  if (b.tipo !== "reserva") {
    await env.DB.prepare("UPDATE productos SET stock_actual=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(nuevo, prodId).run();
  }
  await env.DB.prepare(
    "INSERT INTO movimientos_inventario (producto_id,tipo,cantidad,referencia,motivo,usuario_id,proveedor_id,notas) VALUES (?,?,?,?,?,?,?,?)"
  ).bind(prodId, b.tipo, cant, b.referencia || null, b.motivo || null, payload.sub, b.proveedor_id || null, b.notas || null).run();
  await audit(env, payload.sub, "movimiento_" + b.tipo, "inventario", prodId, { cantidad: cant, stock: nuevo }, request);
  return ok({ stock_actual: nuevo, bajo_minimo: nuevo <= (Number(prod.stock_minimo) || 0) });
}

async function movimientosProducto(env, prodId) {
  const r = await env.DB.prepare(
    "SELECT m.*, u.nombre AS usuario FROM movimientos_inventario m LEFT JOIN usuarios u ON u.id=m.usuario_id WHERE m.producto_id=? ORDER BY m.created_at DESC, m.id DESC"
  ).bind(prodId).all();
  return ok(r.results || []);
}

async function movimientosGlobal(env, url) {
  let sql = "SELECT m.*, p.nombre AS producto, p.sku, u.nombre AS usuario FROM movimientos_inventario m LEFT JOIN productos p ON p.id=m.producto_id LEFT JOIN usuarios u ON u.id=m.usuario_id WHERE 1=1";
  const binds = [];
  const tipo = url.searchParams.get("tipo");
  if (tipo) { sql += " AND m.tipo=?"; binds.push(tipo); }
  sql += " ORDER BY m.created_at DESC, m.id DESC LIMIT 200";
  const r = await env.DB.prepare(sql).bind(...binds).all();
  return ok(r.results || []);
}

// ============================================================================
//  API — PROVEEDORES
// ============================================================================
async function handleProveedores(request, env, payload, method, id) {
  if (method === "GET") {
    const r = await env.DB.prepare("SELECT * FROM proveedores ORDER BY nombre").all();
    return ok(r.results || []);
  }
  if (method === "POST") {
    if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nombre) return fail("El nombre es obligatorio.");
    const res = await env.DB.prepare(
      "INSERT INTO proveedores (nombre,pais,contacto,telefono,email,tiempo_entrega_dias,notas,activo) VALUES (?,?,?,?,?,?,?,1)"
    ).bind(b.nombre, b.pais || null, b.contacto || null, b.telefono || null, b.email || null, b.tiempo_entrega_dias || null, b.notas || null).run();
    return ok({ id: res.meta.last_row_id });
  }
  if (method === "PUT" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
    const b = await request.json().catch(() => ({}));
    const campos = ["nombre", "pais", "contacto", "telefono", "email", "tiempo_entrega_dias", "notas", "activo"];
    const sets = [], vals = [];
    for (const c of campos) if (c in b) { sets.push(c + "=?"); vals.push(b[c]); }
    if (!sets.length) return fail("Nada que actualizar.");
    vals.push(id);
    await env.DB.prepare("UPDATE proveedores SET " + sets.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...vals).run();
    return ok({ id });
  }
  if (method === "DELETE" && id) {
    if (!hasRole(payload, "admin")) return fail("Solo admin elimina proveedores.", 403);
    await env.DB.prepare("DELETE FROM proveedores WHERE id=?").bind(id).run();
    return ok({ id });
  }
  return fail("Método no soportado.", 405);
}

// ============================================================================
//  API — PROYECTOS
// ============================================================================
async function handleProyectos(request, env, payload, method, id) {
  if (method === "GET" && !id) {
    const r = await env.DB.prepare(
      "SELECT p.*, cl.nombre AS cliente FROM proyectos p LEFT JOIN clientes cl ON cl.id=p.cliente_id WHERE p.deleted_at IS NULL ORDER BY p.updated_at DESC"
    ).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const p = await env.DB.prepare(
      "SELECT p.*, cl.nombre AS cliente FROM proyectos p LEFT JOIN clientes cl ON cl.id=p.cliente_id WHERE p.id=? AND p.deleted_at IS NULL"
    ).bind(id).first();
    if (!p) return fail("Proyecto no encontrado.", 404);
    return ok(p);
  }
  return fail("Método no soportado.", 405);
}

// ============================================================================
//  API — PORTAL DEL CLIENTE
// ============================================================================
async function portalClienteId(env, payload) {
  const acc = await env.DB.prepare("SELECT cliente_id FROM portal_accesos WHERE usuario_id=? AND activo=1").bind(payload.sub).first();
  return acc ? acc.cliente_id : null;
}

async function portalDashboard(env, payload) {
  const clienteId = await portalClienteId(env, payload);
  if (!clienteId) return fail("Sin acceso configurado.", 403);
  const cliente = await env.DB.prepare("SELECT nombre, empresa FROM clientes WHERE id=?").bind(clienteId).first();
  const activos = await env.DB.prepare(
    "SELECT id, folio, descripcion, material_principal, etapa_portal, avance_pct, fecha_inicio, fecha_entrega_estimada FROM proyectos WHERE cliente_id=? AND portal_activo=1 AND deleted_at IS NULL AND estado NOT IN ('cerrado') ORDER BY updated_at DESC"
  ).bind(clienteId).all();
  const anteriores = await env.DB.prepare(
    "SELECT id, folio, descripcion, material_principal, etapa_portal, fecha_entrega_real FROM proyectos WHERE cliente_id=? AND portal_activo=1 AND deleted_at IS NULL AND estado='cerrado' ORDER BY updated_at DESC"
  ).bind(clienteId).all();
  const noLeidas = (await env.DB.prepare("SELECT COUNT(*) AS n FROM portal_notificaciones WHERE usuario_id=? AND leida=0").bind(payload.sub).first()).n;
  return ok({
    cliente, activos: activos.results || [], anteriores: anteriores.results || [],
    asesor: await portalAsesor(env, clienteId), noLeidas, etapas: ETAPAS,
  });
}

async function portalAsesor(env, clienteId) {
  const c = await env.DB.prepare("SELECT empleado_asignado_id FROM clientes WHERE id=?").bind(clienteId).first();
  if (!c || !c.empleado_asignado_id) return null;
  const u = await env.DB.prepare("SELECT nombre, cargo, telefono, foto_url FROM usuarios WHERE id=?").bind(c.empleado_asignado_id).first();
  return u || null;
}

async function portalProyectoDetalle(env, payload, id) {
  const clienteId = await portalClienteId(env, payload);
  const p = await env.DB.prepare("SELECT * FROM proyectos WHERE id=? AND cliente_id=? AND portal_activo=1").bind(id, clienteId).first();
  if (!p) return fail("Proyecto no disponible.", 404);
  const historial = await env.DB.prepare(
    "SELECT etapa_clave, etapa_nombre, nota, foto_url, created_at FROM proyecto_etapas_historial WHERE proyecto_id=? AND visible_cliente=1 ORDER BY created_at ASC, id ASC"
  ).bind(id).all();
  const fotos = await env.DB.prepare("SELECT tipo, url_r2, descripcion FROM portal_fotos_proyecto WHERE proyecto_id=? ORDER BY orden").bind(id).all();
  const losas = await env.DB.prepare("SELECT * FROM portal_aprobaciones_losa WHERE proyecto_id=? ORDER BY created_at DESC, id DESC").bind(id).all();
  const mensajes = await env.DB.prepare("SELECT direction, mensaje, created_at FROM portal_mensajes WHERE proyecto_id=? ORDER BY created_at ASC, id ASC").bind(id).all();
  return ok({
    proyecto: p, etapas: ETAPAS, historial: historial.results || [],
    fotos: fotos.results || [], losas: losas.results || [], mensajes: mensajes.results || [],
    asesor: await portalAsesor(env, clienteId),
  });
}

async function portalAprobarLosa(request, env, payload, id) {
  const clienteId = await portalClienteId(env, payload);
  const p = await env.DB.prepare("SELECT id FROM proyectos WHERE id=? AND cliente_id=?").bind(id, clienteId).first();
  if (!p) return fail("Proyecto no disponible.", 404);
  const b = await request.json().catch(() => ({}));
  const estado = b.aprobado ? "aprobado" : "revision_solicitada";
  await env.DB.prepare(
    "UPDATE portal_aprobaciones_losa SET estado=?, nota_cliente=?, respondido_en=CURRENT_TIMESTAMP WHERE proyecto_id=? AND id=?"
  ).bind(estado, b.nota || null, id, b.losa_id).run();
  return ok({ estado });
}

async function portalEnviarMensaje(request, env, payload, id) {
  const clienteId = await portalClienteId(env, payload);
  const p = await env.DB.prepare("SELECT id FROM proyectos WHERE id=? AND cliente_id=?").bind(id, clienteId).first();
  if (!p) return fail("Proyecto no disponible.", 404);
  const b = await request.json().catch(() => ({}));
  if (!b.mensaje) return fail("Mensaje vacío.");
  await env.DB.prepare(
    "INSERT INTO portal_mensajes (proyecto_id,remitente_id,direction,mensaje) VALUES (?,?,?,?)"
  ).bind(id, payload.sub, "cliente", b.mensaje).run();
  return ok({ enviado: true });
}

// ============================================================================
//  GESTIÓN DEL PORTAL DESDE EL SISTEMA INTERNO  (admin / gerente)
// ============================================================================
function tempPass() {
  const c = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  let s = "";
  for (let i = 0; i < 8; i++) s += c[Math.floor(Math.random() * c.length)];
  return "ASL-" + s;
}
// Crea una notificación dentro del portal para el cliente dueño del proyecto
async function notifCliente(env, proyectoId, clienteId, tipo, titulo, mensaje) {
  try {
    const acc = await env.DB.prepare("SELECT usuario_id FROM portal_accesos WHERE cliente_id=?").bind(clienteId).first();
    if (acc) {
      await env.DB.prepare(
        "INSERT INTO portal_notificaciones (usuario_id,tipo,titulo,mensaje,proyecto_id) VALUES (?,?,?,?,?)"
      ).bind(acc.usuario_id, tipo, titulo, mensaje, proyectoId).run();
    }
  } catch (e) { /* noop */ }
}

async function handleAdminPortal(request, env, payload, id, accion, method) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo administración o gerencia gestiona el portal.", 403);
  const proy = await env.DB.prepare("SELECT * FROM proyectos WHERE id=? AND deleted_at IS NULL").bind(id).first();
  if (!proy) return fail("Proyecto no encontrado.", 404);

  // GET estado del portal para este proyecto
  if (accion === "" && method === "GET") {
    const cliente = await env.DB.prepare("SELECT id,nombre,email,empresa FROM clientes WHERE id=?").bind(proy.cliente_id).first();
    const acceso = proy.cliente_id ? await env.DB.prepare("SELECT activo, ultimo_acceso FROM portal_accesos WHERE cliente_id=?").bind(proy.cliente_id).first() : null;
    const losas = await env.DB.prepare("SELECT * FROM portal_aprobaciones_losa WHERE proyecto_id=? ORDER BY created_at DESC, id DESC").bind(id).all();
    const mensajes = await env.DB.prepare("SELECT direction,mensaje,created_at FROM portal_mensajes WHERE proyecto_id=? ORDER BY created_at ASC, id ASC").bind(id).all();
    const historial = await env.DB.prepare("SELECT etapa_clave,etapa_nombre,nota,created_at FROM proyecto_etapas_historial WHERE proyecto_id=? ORDER BY created_at DESC, id DESC LIMIT 20").bind(id).all();
    return ok({
      proyecto: proy, etapas: ETAPAS, cliente, acceso,
      losas: losas.results || [], mensajes: mensajes.results || [], historial: historial.results || [],
    });
  }

  const b = method !== "GET" ? await request.json().catch(() => ({})) : {};

  // PUT cambiar etapa visible al cliente (+ nota + avance) -> historial + notificación
  if (accion === "etapa" && method === "PUT") {
    const et = ETAPAS.find((e) => e.clave === b.etapa_clave);
    if (!et) return fail("Etapa inválida.");
    const avance = (b.avance_pct !== undefined && b.avance_pct !== null && b.avance_pct !== "") ? Number(b.avance_pct) : proy.avance_pct;
    await env.DB.prepare("UPDATE proyectos SET etapa_portal=?, avance_pct=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(et.clave, avance, id).run();
    await env.DB.prepare(
      "INSERT INTO proyecto_etapas_historial (proyecto_id,etapa_clave,etapa_nombre,nota,cambiado_por_id,avance_pct) VALUES (?,?,?,?,?,?)"
    ).bind(id, et.clave, et.nombre, b.nota || null, payload.sub, avance).run();
    await notifCliente(env, id, proy.cliente_id, "etapa_cambio", "Tu proyecto avanzó", et.nombre);
    await audit(env, payload.sub, "portal_etapa", "portal", id, { etapa: et.clave }, request);
    return ok({ etapa: et.clave, avance });
  }

  // PUT avance / m² / fecha estimada
  if (accion === "avance" && method === "PUT") {
    const campos = { avance_pct: "avance_pct", m2_procesados: "m2_procesados", m2_totales: "m2_totales", fecha_entrega_estimada: "fecha_entrega_estimada" };
    const sets = [], vals = [];
    for (const k in campos) if (k in b && b[k] !== "") { sets.push(campos[k] + "=?"); vals.push(b[k]); }
    if (!sets.length) return fail("Nada que actualizar.");
    vals.push(id);
    await env.DB.prepare("UPDATE proyectos SET " + sets.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...vals).run();
    return ok({ ok: true });
  }

  // POST agregar losa para aprobación del cliente
  if (accion === "losa" && method === "POST") {
    if (!b.descripcion_losa) return fail("Describe la losa.");
    await env.DB.prepare(
      "INSERT INTO portal_aprobaciones_losa (proyecto_id,foto_url_losa,descripcion_losa,estado) VALUES (?,?,?,'pendiente')"
    ).bind(id, b.foto_url_losa || "", b.descripcion_losa).run();
    await notifCliente(env, id, proy.cliente_id, "losa_aprobacion", "Losa lista para aprobar", b.descripcion_losa);
    return ok({ ok: true });
  }

  // POST responder en el chat del portal (mensaje del equipo ASLAN)
  if (accion === "mensaje" && method === "POST") {
    if (!b.mensaje) return fail("Mensaje vacío.");
    await env.DB.prepare(
      "INSERT INTO portal_mensajes (proyecto_id,remitente_id,direction,mensaje) VALUES (?,?,'aslan',?)"
    ).bind(id, payload.sub, b.mensaje).run();
    await notifCliente(env, id, proy.cliente_id, "mensaje", "Nuevo mensaje de ASLAN", b.mensaje.slice(0, 60));
    return ok({ ok: true });
  }

  // PUT activar/desactivar acceso al portal para este proyecto
  if (accion === "toggle" && method === "PUT") {
    const activo = b.activo ? 1 : 0;
    await env.DB.prepare("UPDATE proyectos SET portal_activo=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(activo, id).run();
    await audit(env, payload.sub, "portal_toggle", "portal", id, { activo }, request);
    return ok({ portal_activo: activo });
  }

  // POST invitar: crear/activar el usuario cliente, ligarlo y activar el portal
  if (accion === "invitar" && method === "POST") {
    const cliente = await env.DB.prepare("SELECT id,nombre,email FROM clientes WHERE id=?").bind(proy.cliente_id).first();
    if (!cliente) return fail("El proyecto no tiene cliente.", 400);
    if (!cliente.email) return fail("El cliente no tiene email. Agrégalo primero en su ficha.", 400);

    const origin = new URL(request.url).origin;
    let user = await env.DB.prepare("SELECT id,rol FROM usuarios WHERE email=? AND deleted_at IS NULL").bind(cliente.email).first();
    let passInfo = null;

    if (!user) {
      const pass = tempPass();
      const ph = await hashPassword(pass);
      const res = await env.DB.prepare(
        "INSERT INTO usuarios (nombre,email,password_hash,rol,password_debe_cambiar) VALUES (?,?,?,'cliente',1)"
      ).bind(cliente.nombre, cliente.email, ph).run();
      user = { id: res.meta.last_row_id, rol: "cliente" };
      passInfo = pass;
    } else if (user.rol !== "cliente") {
      return fail("Ese email ya pertenece a un usuario interno.", 409);
    }

    // Ligar usuario <-> cliente en portal_accesos (si no existe)
    const acc = await env.DB.prepare("SELECT id FROM portal_accesos WHERE usuario_id=?").bind(user.id).first();
    if (!acc) {
      await env.DB.prepare("INSERT INTO portal_accesos (usuario_id,cliente_id,activo) VALUES (?,?,1)").bind(user.id, cliente.id).run();
    } else {
      await env.DB.prepare("UPDATE portal_accesos SET activo=1 WHERE usuario_id=?").bind(user.id).run();
    }
    await env.DB.prepare("UPDATE proyectos SET portal_activo=1 WHERE id=?").bind(id).run();
    await audit(env, payload.sub, "portal_invitar", "portal", id, { cliente: cliente.email }, request);

    const waMsg = "Hola " + cliente.nombre + ", tu portal ASLAN está listo: " + origin + "/login  ·  Usuario: " + cliente.email + (passInfo ? "  ·  Contraseña temporal: " + passInfo : "");
    return ok({
      email: cliente.email,
      password_temporal: passInfo, // null si el usuario ya existía
      ya_existia: passInfo === null,
      url: origin + "/login",
      whatsapp_link: "https://wa.me/" + (cliente_wa_num(cliente) || "") + "?text=" + encodeURIComponent(waMsg),
      mensaje_whatsapp: waMsg,
    });
  }

  return fail("Acción de portal no soportada.", 405);
}
function cliente_wa_num() { return ""; } // el número del cliente se resuelve en la capa de WhatsApp

// ============================================================================
//  ROUTER PRINCIPAL
// ============================================================================
async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") return new Response(null, { headers: CORS });

  // ---- API ----
  if (path.startsWith("/api/")) {
    // Setup (público con candado)
    if (path === "/api/setup") return await runSetup(env, request);

    // Auth pública del portal y del sistema interno
    // Login ÚNICO (ambas rutas usan el mismo handler; se mantiene el alias por compatibilidad)
    if ((path === "/api/auth/login" || path === "/api/portal/auth/login") && method === "POST") return await handleLogin(request, env);

    // De aquí en adelante requiere token
    const payload = await requireAuth(request, env);
    if (!payload) return fail("No autenticado.", 401);

    // ----- Endpoints del PORTAL (solo tipo portal + rol cliente) -----
    if (path.startsWith("/api/portal/")) {
      if (payload.tipo !== "portal" || payload.rol !== "cliente") return fail("Acceso denegado.", 403);
      if (path === "/api/portal/auth/change-password" && method === "POST") return await handleChangePassword(request, env, payload);
      if (path === "/api/portal/dashboard") return await portalDashboard(env, payload);
      const mProy = path.match(/^\/api\/portal\/proyectos\/(\d+)$/);
      if (mProy) return await portalProyectoDetalle(env, payload, mProy[1]);
      const mLosa = path.match(/^\/api\/portal\/proyectos\/(\d+)\/losa\/aprobar$/);
      if (mLosa && method === "POST") return await portalAprobarLosa(request, env, payload, mLosa[1]);
      const mMsg = path.match(/^\/api\/portal\/proyectos\/(\d+)\/mensajes$/);
      if (mMsg && method === "POST") return await portalEnviarMensaje(request, env, payload, mMsg[1]);
      return fail("Endpoint de portal no encontrado.", 404);
    }

    // ----- A partir de aquí: SISTEMA INTERNO. El cliente no entra. -----
    if (payload.rol === "cliente") return fail("Los clientes solo acceden al portal.", 403);

    if (path === "/api/me") return ok({ id: payload.sub, nombre: payload.nombre, rol: payload.rol });
    if (path === "/api/auth/change-password" && method === "POST") return await handleChangePassword(request, env, payload);
    if (path === "/api/dashboard/stats") return await dashboardStats(env);

    let m;
    m = path.match(/^\/api\/clientes(?:\/(\d+))?$/);
    if (m) return await handleClientes(request, env, payload, method, m[1]);
    m = path.match(/^\/api\/cotizaciones\/(\d+)\/convertir$/);
    if (m && method === "POST") return await convertirCotizacion(request, env, payload, m[1]);
    m = path.match(/^\/api\/cotizaciones(?:\/(\d+))?$/);
    if (m) return await handleCotizaciones(request, env, payload, method, m[1], url);
    m = path.match(/^\/api\/productos\/(\d+)\/movimientos$/);
    if (m && method === "GET") return await movimientosProducto(env, m[1]);
    m = path.match(/^\/api\/productos\/(\d+)\/movimiento$/);
    if (m && method === "POST") return await registrarMovimiento(request, env, payload, m[1]);
    m = path.match(/^\/api\/productos(?:\/(\d+))?$/);
    if (m) return await handleProductos(request, env, payload, method, m[1]);
    if (path === "/api/movimientos" && method === "GET") return await movimientosGlobal(env, url);
    m = path.match(/^\/api\/proveedores(?:\/(\d+))?$/);
    if (m) return await handleProveedores(request, env, payload, method, m[1]);
    m = path.match(/^\/api\/proyectos(?:\/(\d+))?$/);
    if (m) return await handleProyectos(request, env, payload, method, m[1]);

    // ----- Gestión del PORTAL desde el sistema interno (admin/gerente) -----
    const mAdmin = path.match(/^\/api\/admin\/proyectos\/(\d+)\/portal(?:\/(\w+))?$/);
    if (mAdmin) return await handleAdminPortal(request, env, payload, mAdmin[1], mAdmin[2] || "", method);

    return fail("Endpoint no encontrado.", 404);
  }

  // ---- FRONTEND ----
  // Login ÚNICO: mismo acceso para todos, en cualquiera de estas rutas.
  if (path === "/login" || path === "/portal" || path === "/portal/") return html(renderLogin());
  if (path.startsWith("/portal/")) return html(renderPortalApp());
  if (path === "/check-in" || path === "/checkin") return html(renderCheckin());
  // Cualquier otra ruta -> SPA interna (en cliente decide: login / dashboard / portal según rol)
  return html(renderApp());
}

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env);
    } catch (e) {
      return fail("Error interno: " + (e && e.message ? e.message : String(e)), 500);
    }
  },
};

// ============================================================================
//  ESTILOS COMPARTIDOS
// ============================================================================
function baseStyles(portal) {
  const bg = portal ? "#0f0f0f" : "#1a1a1a";
  const card = portal ? "#181818" : "#222222";
  return `
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:${bg};--card:${card};--gold:#8B6D3F;--gold2:#A07D4A;--txt:#E8E0D0;--txt2:#999;--ok:#4CAF50;--err:#E53935;--warn:#FFC107;--bd:rgba(139,109,63,0.28)}
body{background:var(--bg);color:var(--txt);font-family:'Montserrat',system-ui,sans-serif;line-height:1.5}
h1,h2,h3,.serif{font-family:'Cormorant Garamond',Georgia,serif}
a{color:var(--gold2);text-decoration:none}
.btn{background:var(--gold);color:#fff;border:none;padding:.7rem 1.2rem;border-radius:4px;font-weight:600;cursor:pointer;font-family:inherit;font-size:.92rem;transition:.15s}
.btn:hover{background:var(--gold2)}
.btn.sec{background:transparent;border:1px solid var(--gold);color:var(--gold2)}
.btn.ok{background:var(--ok)} .btn.err{background:var(--err)} .btn.block{width:100%}
input,select,textarea{background:#111;border:1px solid var(--bd);color:var(--txt);padding:.65rem .8rem;border-radius:4px;font-family:inherit;width:100%;font-size:.92rem}
input:focus,select,textarea:focus{outline:none;border-color:var(--gold)}
label{display:block;font-size:.78rem;color:var(--txt2);margin:.6rem 0 .25rem;text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:1.2rem;box-shadow:0 4px 20px rgba(0,0,0,.4)}
.pill{display:inline-block;padding:.18rem .65rem;border-radius:99px;font-size:.72rem;font-weight:600}
.muted{color:var(--txt2)}
table{width:100%;border-collapse:collapse;font-size:.86rem}
th{text-align:left;color:var(--gold2);font-weight:600;padding:.6rem;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--card)}
td{padding:.55rem .6rem;border-bottom:1px solid rgba(255,255,255,.05)}
tr:hover td{background:rgba(139,109,63,.06)}
.toast{position:fixed;top:1rem;right:1rem;background:var(--card);border:1px solid var(--gold);padding:.8rem 1.1rem;border-radius:6px;z-index:9999;box-shadow:0 6px 30px rgba(0,0,0,.6)}
`;
}

const FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Montserrat:wght@300;400;500;600;700&display=swap" rel="stylesheet">`;

// ============================================================================
//  FRONTEND — LOGIN INTERNO
// ============================================================================
function renderLogin() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Acceso</title>${FONTS}<style>${baseStyles(false)}
.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;background:radial-gradient(circle at 35% 15%,#252015,#1a1a1a 62%)}
.box{width:100%;max-width:390px}
.logo{text-align:center;margin-bottom:1.6rem}
.logo h1{font-size:2.9rem;letter-spacing:.35em;color:var(--gold)}
.logo p{color:var(--txt2);font-size:.82rem;letter-spacing:.16em;font-style:italic;font-family:'Cormorant Garamond',serif}
.err{color:var(--err);font-size:.85rem;margin-top:.6rem;min-height:1rem}
</style></head><body>
<div class="wrap"><div class="box">
<div class="logo"><h1>ASLAN</h1><p>Acceso a tu cuenta</p></div>
<div class="card">
<label>Correo</label><input id="email" type="email" placeholder="tu@correo.com" autocomplete="username">
<label>Contraseña</label><input id="pass" type="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')entrar()">
<div style="height:1rem"></div>
<button class="btn block" onclick="entrar()">Acceder</button>
<div class="err" id="err"></div>
</div>
<p class="muted" style="text-align:center;margin-top:1.2rem;font-size:.8rem">¿Necesitas acceso? <a href="https://wa.me/${EMPRESA.whatsapp}" target="_blank">Contáctanos por WhatsApp</a></p>
</div></div>
<script>
// Si ya hay sesión, manda a donde corresponde según el rol.
(function(){
  var t=localStorage.getItem('aslan_token');
  var u=null; try{u=JSON.parse(localStorage.getItem('aslan_user')||'null');}catch(e){}
  if(t&&u){location.href=(u.rol==='cliente')?'/portal/dashboard':'/dashboard';}
})();
async function entrar(){
  var em=document.getElementById('email').value, pw=document.getElementById('pass').value;
  var e=document.getElementById('err'); e.textContent='';
  try{
    var r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:em,password:pw})});
    var d=await r.json();
    if(!d.ok){e.textContent=d.error;return;}
    localStorage.setItem('aslan_token',d.data.token);
    localStorage.setItem('aslan_user',JSON.stringify(d.data.usuario));
    // Mismo login para todos: el destino lo decide el rol.
    location.href=(d.data.usuario.destino==='portal')?'/portal/dashboard':'/dashboard';
  }catch(x){e.textContent='Error de conexión.';}
}
</script></body></html>`;
}

// ============================================================================
//  FRONTEND — SPA INTERNA
// ============================================================================
function renderApp() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Panel</title>${FONTS}<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script><style>${baseStyles(false)}
.layout{display:flex;min-height:100vh}
.side{width:240px;background:#111;border-right:1px solid var(--bd);padding:1.2rem .8rem;flex-shrink:0}
.side h1{color:var(--gold);font-size:1.8rem;letter-spacing:.3em;text-align:center;margin-bottom:1.4rem}
.nav a{display:block;padding:.6rem .8rem;border-radius:6px;color:var(--txt);font-size:.9rem;margin-bottom:.2rem;cursor:pointer}
.nav a:hover{background:rgba(139,109,63,.12)}
.nav a.active{background:var(--gold);color:#fff}
.side .user{position:absolute;bottom:1rem;font-size:.8rem;color:var(--txt2)}
.main{flex:1;padding:1.6rem;overflow:auto}
.hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem}
.hd h2{font-size:2rem;color:var(--gold)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.4rem}
.kpi .n{font-size:2.2rem;color:var(--gold);font-family:'Cormorant Garamond',serif;font-weight:700}
.kpi .l{font-size:.78rem;color:var(--txt2);text-transform:uppercase;letter-spacing:.04em}
.grid{display:grid;gap:1rem}
@media(max-width:768px){.side{position:fixed;left:-260px;transition:.2s;z-index:50;height:100%}.side.open{left:0}.main{padding:1rem}.menu-btn{display:block!important}}
.menu-btn{display:none;background:none;border:1px solid var(--bd);color:var(--gold);padding:.4rem .7rem;border-radius:4px;font-size:1.2rem;cursor:pointer}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:99;padding:1rem}
.modal.open{display:flex}
.modal .inner{background:var(--card);border:1px solid var(--gold);border-radius:10px;padding:1.4rem;max-width:420px;width:100%;max-height:90vh;overflow:auto}
td[contenteditable]{cursor:text;border-bottom:1px dashed rgba(139,109,63,.4)}
td[contenteditable]:focus{outline:1px solid var(--gold);background:rgba(139,109,63,.08)}
</style></head><body>
<div class="layout">
<aside class="side" id="side">
<h1>ASLAN</h1>
<nav class="nav" id="nav"></nav>
<div class="user" id="userBox"></div>
</aside>
<main class="main">
<div class="hd"><button class="menu-btn" onclick="document.getElementById('side').classList.toggle('open')">☰</button><h2 id="titulo">Dashboard</h2><div id="acciones"></div></div>
<div id="content">Cargando…</div>
</main></div>
<div class="modal" id="modal"><div class="inner" id="modalInner"></div></div>
<script>
function openModal(h){document.getElementById('modalInner').innerHTML=h;document.getElementById('modal').classList.add('open');}
function closeModal(){document.getElementById('modal').classList.remove('open');}
var TOKEN=localStorage.getItem('aslan_token');
var USER=JSON.parse(localStorage.getItem('aslan_user')||'null');
if(!TOKEN||!USER){location.href='/login';}
else if(USER.rol==='cliente'){location.href='/portal/dashboard';} // el cliente va a su portal
function H(){return {'Content-Type':'application/json','Authorization':'Bearer '+TOKEN};}
async function api(p,opt){opt=opt||{};opt.headers=H();var r=await fetch(p,opt);if(r.status===401){localStorage.clear();location.href='/login';return null;}return await r.json();}
function money(n){return '$'+Number(n||0).toLocaleString('es-MX',{minimumFractionDigits:2,maximumFractionDigits:2});}
function toast(t){var d=document.createElement('div');d.className='toast';d.textContent=t;document.body.appendChild(d);setTimeout(function(){d.remove();},2600);}

var MENU=[
  {id:'dashboard',label:'📊 Dashboard',roles:['admin','gerente','empleado']},
  {id:'clientes',label:'👥 Clientes / CRM',roles:['admin','gerente','empleado']},
  {id:'cotizaciones',label:'🧾 Cotizaciones',roles:['admin','gerente','empleado']},
  {id:'inventario',label:'📦 Inventario',roles:['admin','gerente','empleado']},
  {id:'proyectos',label:'🏗️ Proyectos',roles:['admin','gerente','empleado']},
  {id:'empleados',label:'👷 Empleados',roles:['admin','gerente']},
  {id:'whatsapp',label:'💬 WhatsApp',roles:['admin','gerente','empleado']},
  {id:'reportes',label:'📈 Reportes',roles:['admin','gerente']},
  {id:'config',label:'⚙️ Configuración',roles:['admin']}
];
function renderNav(){
  var nav=document.getElementById('nav');nav.innerHTML='';
  MENU.filter(function(m){return m.roles.indexOf(USER.rol)>=0;}).forEach(function(m){
    var a=document.createElement('a');a.textContent=m.label;a.dataset.id=m.id;
    a.onclick=function(){go(m.id);};nav.appendChild(a);
  });
  document.getElementById('userBox').innerHTML=USER.nombre+'<br><span style="color:var(--gold)">'+USER.rol+'</span> · <a onclick="logout()" style="cursor:pointer">salir</a>';
}
function logout(){localStorage.clear();location.href='/login';}
function setActive(id){var as=document.querySelectorAll('.nav a');as.forEach(function(a){a.classList.toggle('active',a.dataset.id===id);});}

async function go(id){
  setActive(id);document.getElementById('side').classList.remove('open');
  document.getElementById('acciones').innerHTML='';
  var t={dashboard:'Dashboard',clientes:'Clientes / CRM',cotizaciones:'Cotizaciones',inventario:'Inventario',proyectos:'Proyectos',empleados:'Empleados',whatsapp:'WhatsApp',reportes:'Reportes',config:'Configuración'};
  document.getElementById('titulo').textContent=t[id]||id;
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  if(id==='dashboard')return viewDashboard(c);
  if(id==='clientes')return viewClientes(c);
  if(id==='cotizaciones')return viewCotizaciones(c);
  if(id==='inventario')return viewInventario(c);
  if(id==='proyectos')return viewProyectos(c);
  c.innerHTML='<div class="card"><h3 class="serif" style="color:var(--gold);font-size:1.4rem">Módulo en construcción</h3><p class="muted" style="margin-top:.5rem">Esta sección («'+t[id]+'») se está integrando sobre esta misma base. Ya está el backbone, la auth por rol y el esquema de datos completo.</p></div>';
}

async function viewDashboard(c){
  var d=await api('/api/dashboard/stats');if(!d||!d.ok)return;
  var k=d.data.kpis;
  var kpis=[['Clientes activos',k.clientes],['Cotizaciones (mes)',k.cotizMes],['Proyectos en curso',k.proyectos],['Empleados hoy',k.empleadosHoy],['Pipeline',money(k.pipeline)],['Stock crítico',k.stockCritico]];
  var h='<div class="kpis">';
  kpis.forEach(function(x){h+='<div class="card kpi"><div class="n">'+x[1]+'</div><div class="l">'+x[0]+'</div></div>';});
  h+='</div><div class="card"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Cotizaciones recientes</h3><table><thead><tr><th>Folio</th><th>Cliente</th><th>Total</th><th>Estado</th></tr></thead><tbody>';
  (d.data.recientes||[]).forEach(function(r){h+='<tr><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+money(r.total)+'</td><td>'+estadoPill(r.estado)+'</td></tr>';});
  if(!d.data.recientes.length)h+='<tr><td colspan="4" class="muted">Sin cotizaciones aún.</td></tr>';
  h+='</tbody></table></div>';
  c.innerHTML=h;
}
function estadoPill(e){
  var map={aceptada:'var(--ok)',enviada:'var(--gold)',borrador:'#666',rechazada:'var(--err)',expirada:'#888'};
  return '<span class="pill" style="background:'+(map[e]||'#666')+'">'+(e||'—')+'</span>';
}

async function viewClientes(c){
  document.getElementById('acciones').innerHTML='<button class="btn" onclick="nuevoCliente()">+ Nuevo Cliente</button>';
  var d=await api('/api/clientes');if(!d||!d.ok)return;
  var h='<div class="card"><table><thead><tr><th>Nombre</th><th>Empresa</th><th>Tipo</th><th>Etapa</th><th>Ciudad</th><th>Teléfono</th><th>Asesor</th></tr></thead><tbody>';
  d.data.forEach(function(r){h+='<tr><td>'+r.nombre+'</td><td>'+(r.empresa||'—')+'</td><td>'+(r.tipo||'—')+'</td><td><span class="pill" style="background:var(--gold)">'+(r.etapa||'—')+'</span></td><td>'+(r.ciudad||'—')+'</td><td>'+(r.telefono||'—')+'</td><td>'+(r.empleado_nombre||'—')+'</td></tr>';});
  if(!d.data.length)h+='<tr><td colspan="7" class="muted">Sin clientes. Crea el primero.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
async function nuevoCliente(){
  var nombre=prompt('Nombre del cliente:');if(!nombre)return;
  var empresa=prompt('Empresa (opcional):')||'';
  var d=await api('/api/clientes',{method:'POST',body:JSON.stringify({nombre:nombre,empresa:empresa})});
  if(d&&d.ok){toast('Cliente creado');viewClientes(document.getElementById('content'));}
}

var INV_PROD=[];
var INV_PUEDE_EDITAR=false;
async function viewInventario(c){
  INV_PUEDE_EDITAR=(USER.rol==='admin'||USER.rol==='gerente');
  var acc='';
  if(INV_PUEDE_EDITAR)acc+='<button class="btn" onclick="nuevoProducto()">+ Nuevo producto</button> ';
  acc+='<button class="btn sec" onclick="viewAlertas()">Alertas de stock</button> <button class="btn sec" onclick="viewMovimientos()">Movimientos</button> <button class="btn sec" onclick="viewProveedores()">Proveedores</button> <button class="btn sec" onclick="exportarInventarioCSV()">Exportar CSV</button>';
  document.getElementById('acciones').innerHTML=acc;
  var d=await api('/api/productos');if(!d||!d.ok)return;
  INV_PROD=d.data;
  var nota=INV_PUEDE_EDITAR?'<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Doble clic en una celda con borde punteado para editar. El stock se cambia con «Mov» para dejar registro.</p>':'';
  var h=nota+'<div class="card" style="overflow-x:auto"><table><thead><tr><th>SKU</th><th>Material</th><th>Categoría</th><th>Stock</th><th>Mín</th><th>Ubicación</th><th>Costo</th><th>Venta</th><th>Acciones</th></tr></thead><tbody>';
  d.data.forEach(function(r){
    var color=r.stock_actual<=0?'var(--err)':(r.stock_actual<=r.stock_minimo?'var(--warn)':'var(--ok)');
    var ed=INV_PUEDE_EDITAR;
    h+='<tr>'+
      '<td class="muted">'+(r.sku||'—')+'</td>'+
      cell(r,'nombre',r.nombre,ed)+
      '<td>'+(r.categoria||'—')+'</td>'+
      '<td style="color:'+color+';font-weight:600;white-space:nowrap">'+r.stock_actual+' '+r.unidad+'</td>'+
      cell(r,'stock_minimo',r.stock_minimo,ed)+
      cell(r,'ubicacion_almacen',(r.ubicacion_almacen||''),ed)+
      cell(r,'precio_costo',r.precio_costo,ed,true)+
      cell(r,'precio_venta',r.precio_venta,ed,true)+
      '<td style="white-space:nowrap"><button class="btn sec" style="padding:.25rem .55rem" onclick="movUI('+r.id+')">Mov</button> <button class="btn sec" style="padding:.25rem .55rem" onclick="qrProducto('+r.id+')">QR</button></td>'+
      '</tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="9" class="muted">Sin productos.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
function cell(r,campo,val,editable,money_){
  var disp=money_?money(val):val;
  if(editable)return '<td contenteditable="true" data-id="'+r.id+'" data-campo="'+campo+'" data-num="'+(['stock_minimo','precio_costo','precio_venta'].indexOf(campo)>=0?1:0)+'" onblur="guardarCelda(this)">'+escAttr(String(val))+'</td>';
  return '<td>'+disp+'</td>';
}
async function guardarCelda(el){
  var id=el.dataset.id, campo=el.dataset.campo, num=el.dataset.num==='1';
  var val=el.textContent.trim();
  var body={};body[campo]=num?(parseFloat(val)||0):val;
  var d=await api('/api/productos/'+id,{method:'PUT',body:JSON.stringify(body)});
  if(d&&d.ok)toast('Guardado');else if(d){toast(d.error);}
}
async function nuevoProducto(){
  var cats=['Mármol Importado','Mármol Nacional','Cuarzo','Cuarcita','Porcelanato','Madera de Ingeniería','Granito','Otros'];
  var catOpts=cats.map(function(x){return '<option>'+x+'</option>';}).join('');
  var ac=['Pulido','Hone','Cepillado','Flameado','Natural','Otro'].map(function(x){return '<option>'+x+'</option>';}).join('');
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.6rem">Nuevo producto</h3>'+
    '<label>Nombre</label><input id="npNom">'+
    '<label>Categoría</label><select id="npCat">'+catOpts+'</select>'+
    '<label>Acabado</label><select id="npAcab">'+ac+'</select>'+
    '<div style="display:grid;grid-template-columns:1fr 1fr;gap:.5rem"><div><label>Stock inicial</label><input id="npStock" type="number" value="0"></div><div><label>Stock mínimo</label><input id="npMin" type="number" value="0"></div><div><label>Unidad</label><input id="npUni" value="m2"></div><div><label>Ubicación</label><input id="npUbi"></div><div><label>Precio costo</label><input id="npCosto" type="number" value="0"></div><div><label>Precio venta</label><input id="npVenta" type="number" value="0"></div></div>'+
    '<label>Dimensiones</label><input id="npDim" placeholder="300x180x2 cm">'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="guardarProducto()">Guardar</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
}
async function guardarProducto(){
  var b={nombre:val('npNom'),categoria:val('npCat'),acabado:val('npAcab'),stock_actual:val('npStock'),stock_minimo:val('npMin'),unidad:val('npUni'),ubicacion_almacen:val('npUbi'),precio_costo:val('npCosto'),precio_venta:val('npVenta'),dimensiones:val('npDim')};
  if(!b.nombre){toast('Falta el nombre');return;}
  var d=await api('/api/productos',{method:'POST',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Producto '+d.data.sku+' creado');viewInventario(document.getElementById('content'));}else if(d){toast(d.error);}
}
function val(id){var e=document.getElementById(id);return e?e.value:'';}

function movUI(prodId){
  var p=INV_PROD.find(function(x){return x.id===prodId;})||{};
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.3rem">Movimiento de inventario</h3>'+
    '<p class="muted" style="font-size:.85rem;margin-bottom:.5rem">'+escAttr(p.nombre||'')+' · stock actual: '+(p.stock_actual||0)+' '+(p.unidad||'')+'</p>'+
    '<label>Tipo</label><select id="mvTipo"><option value="entrada">Entrada (+ suma)</option><option value="salida">Salida (− resta)</option><option value="devolucion">Devolución (+ suma)</option><option value="ajuste">Ajuste (fija el stock)</option><option value="reserva">Reserva (no afecta stock)</option></select>'+
    '<label>Cantidad</label><input id="mvCant" type="number" step="0.01" value="1">'+
    '<label>Motivo</label><input id="mvMotivo" placeholder="Ej: compra, merma, venta">'+
    '<label>Referencia (cotización/proyecto)</label><input id="mvRef">'+
    '<label>Notas</label><textarea id="mvNotas" rows="2"></textarea>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="enviarMov('+prodId+')">Registrar</button><button class="btn sec" onclick="historialProd('+prodId+')">Ver historial</button><button class="btn sec" onclick="closeModal()">Cerrar</button></div>'+
    '<div id="mvHist" style="margin-top:.7rem"></div>');
}
async function enviarMov(prodId){
  var b={tipo:val('mvTipo'),cantidad:val('mvCant'),motivo:val('mvMotivo'),referencia:val('mvRef'),notas:val('mvNotas')};
  var d=await api('/api/productos/'+prodId+'/movimiento',{method:'POST',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Movimiento registrado · stock: '+d.data.stock_actual+(d.data.bajo_minimo?' (¡bajo mínimo!)':''));viewInventario(document.getElementById('content'));}else if(d){toast(d.error);}
}
async function historialProd(prodId){
  var d=await api('/api/productos/'+prodId+'/movimientos');if(!d||!d.ok)return;
  var h='<div style="max-height:200px;overflow:auto;border-top:1px solid var(--bd);padding-top:.5rem"><table><thead><tr><th>Fecha</th><th>Tipo</th><th>Cant.</th><th>Motivo</th></tr></thead><tbody>';
  d.data.forEach(function(m){h+='<tr><td class="muted" style="font-size:.78rem">'+(m.created_at||'')+'</td><td>'+m.tipo+'</td><td>'+m.cantidad+'</td><td>'+(m.motivo||'—')+'</td></tr>';});
  if(!d.data.length)h+='<tr><td colspan="4" class="muted">Sin movimientos.</td></tr>';
  h+='</tbody></table></div>';
  document.getElementById('mvHist').innerHTML=h;
}
function qrProducto(prodId){
  var p=INV_PROD.find(function(x){return x.id===prodId;})||{};
  if(typeof qrcode==='undefined'){toast('Generador de QR no cargó, reintenta');return;}
  var texto=(p.sku||'')+' · '+(p.nombre||'');
  var qr=qrcode(0,'M');qr.addData(texto);qr.make();
  var url=qr.createDataURL(6,8);
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.5rem">Etiqueta QR</h3>'+
    '<div style="text-align:center"><img id="qrImg" src="'+url+'" style="background:#fff;padding:8px;border-radius:6px;max-width:220px"><p style="margin-top:.5rem"><strong>'+escAttr(p.sku||'')+'</strong></p><p class="muted" style="font-size:.85rem">'+escAttr(p.nombre||'')+'</p></div>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="descargarQR('+JSON.stringify(p.sku||'qr')+')">Descargar PNG</button><button class="btn sec" onclick="closeModal()">Cerrar</button></div>');
}
function descargarQR(sku){
  var img=document.getElementById('qrImg');if(!img)return;
  var cv=document.createElement('canvas');cv.width=img.naturalWidth;cv.height=img.naturalHeight;
  cv.getContext('2d').drawImage(img,0,0);
  var a=document.createElement('a');a.href=cv.toDataURL('image/png');a.download='QR-'+sku+'.png';a.click();
}
async function viewMovimientos(){
  document.getElementById('acciones').innerHTML='<button class="btn sec" onclick="go(\\'inventario\\')">‹ Volver al catálogo</button>';
  document.getElementById('titulo').textContent='Movimientos de inventario';
  var c=document.getElementById('content');var d=await api('/api/movimientos');if(!d||!d.ok)return;
  var h='<div class="card" style="overflow-x:auto"><table><thead><tr><th>Fecha</th><th>Producto</th><th>Tipo</th><th>Cant.</th><th>Motivo</th><th>Ref.</th><th>Usuario</th></tr></thead><tbody>';
  d.data.forEach(function(m){h+='<tr><td class="muted" style="font-size:.78rem;white-space:nowrap">'+(m.created_at||'')+'</td><td>'+(m.producto||'—')+'</td><td>'+m.tipo+'</td><td>'+m.cantidad+'</td><td>'+(m.motivo||'—')+'</td><td>'+(m.referencia||'—')+'</td><td class="muted">'+(m.usuario||'—')+'</td></tr>';});
  if(!d.data.length)h+='<tr><td colspan="7" class="muted">Sin movimientos registrados.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
async function viewAlertas(){
  document.getElementById('acciones').innerHTML='<button class="btn sec" onclick="go(\\'inventario\\')">‹ Volver al catálogo</button>';
  document.getElementById('titulo').textContent='Alertas de stock';
  var c=document.getElementById('content');var d=await api('/api/productos');if(!d||!d.ok)return;
  INV_PROD=d.data;
  var bajos=d.data.filter(function(p){return p.stock_actual<=p.stock_minimo;});
  var h='<div class="card"><table><thead><tr><th>SKU</th><th>Material</th><th>Stock</th><th>Mín</th><th></th></tr></thead><tbody>';
  bajos.forEach(function(p){
    var color=p.stock_actual<=0?'var(--err)':'var(--warn)';
    h+='<tr><td class="muted">'+(p.sku||'—')+'</td><td>'+p.nombre+'</td><td style="color:'+color+';font-weight:600">'+p.stock_actual+' '+p.unidad+'</td><td class="muted">'+p.stock_minimo+'</td><td><button class="btn sec" style="padding:.25rem .55rem" onclick="movUI('+p.id+')">Registrar entrada</button></td></tr>';
  });
  if(!bajos.length)h+='<tr><td colspan="5" class="muted">Todo el inventario está por encima del mínimo. ✓</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
async function viewProveedores(){
  document.getElementById('acciones').innerHTML=(USER.rol==='admin'||USER.rol==='gerente'?'<button class="btn" onclick="nuevoProveedor()">+ Nuevo proveedor</button> ':'')+'<button class="btn sec" onclick="go(\\'inventario\\')">‹ Volver al catálogo</button>';
  document.getElementById('titulo').textContent='Proveedores';
  var c=document.getElementById('content');var d=await api('/api/proveedores');if(!d||!d.ok)return;
  var h='<div class="card" style="overflow-x:auto"><table><thead><tr><th>Nombre</th><th>País</th><th>Contacto</th><th>Teléfono</th><th>Email</th><th>Entrega (días)</th></tr></thead><tbody>';
  d.data.forEach(function(p){h+='<tr><td>'+p.nombre+'</td><td>'+(p.pais||'—')+'</td><td>'+(p.contacto||'—')+'</td><td>'+(p.telefono||'—')+'</td><td>'+(p.email||'—')+'</td><td>'+(p.tiempo_entrega_dias||'—')+'</td></tr>';});
  if(!d.data.length)h+='<tr><td colspan="6" class="muted">Sin proveedores.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
function nuevoProveedor(){
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.6rem">Nuevo proveedor</h3>'+
    '<label>Nombre</label><input id="pvNom"><label>País</label><input id="pvPais"><label>Contacto</label><input id="pvCont"><label>Teléfono</label><input id="pvTel"><label>Email</label><input id="pvMail"><label>Tiempo de entrega (días)</label><input id="pvDias" type="number">'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="guardarProveedor()">Guardar</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
}
async function guardarProveedor(){
  var b={nombre:val('pvNom'),pais:val('pvPais'),contacto:val('pvCont'),telefono:val('pvTel'),email:val('pvMail'),tiempo_entrega_dias:val('pvDias')};
  if(!b.nombre){toast('Falta el nombre');return;}
  var d=await api('/api/proveedores',{method:'POST',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Proveedor agregado');viewProveedores();}else if(d){toast(d.error);}
}
function exportarInventarioCSV(){
  if(!INV_PROD.length){toast('Carga el catálogo primero');return;}
  var cols=['sku','nombre','categoria','acabado','dimensiones','procedencia','stock_actual','stock_minimo','unidad','ubicacion_almacen','precio_costo','precio_venta','estado'];
  var lines=[cols.join(',')];
  INV_PROD.forEach(function(p){lines.push(cols.map(function(k){var v=p[k]==null?'':String(p[k]);return '"'+v.replace(/"/g,'""')+'"';}).join(','));});
  var blob=new Blob(['\\ufeff'+lines.join('\\n')],{type:'text/csv;charset=utf-8'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='inventario_aslan.csv';a.click();
}

async function viewProyectos(c){
  var d=await api('/api/proyectos');if(!d||!d.ok)return;
  var h='<p class="muted" style="font-size:.82rem;margin-bottom:.6rem">Haz clic en un proyecto para gestionar su Portal del Cliente.</p>';
  h+='<div class="card"><table><thead><tr><th>Folio</th><th>Cliente</th><th>Descripción</th><th>Estado</th><th>Portal</th><th>Avance</th></tr></thead><tbody>';
  d.data.forEach(function(r){
    var portal=r.portal_activo?'<span class="pill" style="background:var(--ok)">activo</span>':'<span class="pill" style="background:#555">inactivo</span>';
    h+='<tr style="cursor:pointer" onclick="abrirProyecto('+r.id+')"><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+(r.descripcion||'—')+'</td><td>'+(r.estado||'—')+'</td><td>'+portal+'</td><td>'+(r.avance_pct||0)+'%</td></tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="6" class="muted">Sin proyectos.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}

// ---- Panel de gestión del PORTAL para un proyecto (admin/gerente) ----
async function abrirProyecto(id){
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  document.getElementById('titulo').textContent='Proyecto · Portal del Cliente';
  document.getElementById('acciones').innerHTML='';
  var d=await api('/api/admin/proyectos/'+id+'/portal');
  if(!d||!d.ok){c.innerHTML='<div class="card">'+((d&&d.error)||'Error')+'<br><span class="back" onclick="go(\\'proyectos\\')">‹ Volver</span></div>';return;}
  var p=d.data.proyecto, cli=d.data.cliente||{}, acc=d.data.acceso||{};
  var puede=(USER.rol==='admin'||USER.rol==='gerente');
  var h='<span class="back" onclick="go(\\'proyectos\\')" style="cursor:pointer;color:var(--gold2)">‹ Volver a proyectos</span>';
  h+='<div class="hd" style="margin-top:.4rem"><h2 style="font-size:1.6rem">'+(p.folio||'')+'</h2></div>';
  h+='<p class="muted" style="margin-top:-.6rem;margin-bottom:1rem">'+(p.descripcion||'')+' · Cliente: '+(cli.nombre||'—')+(cli.empresa?(' ('+cli.empresa+')'):'')+'</p>';

  if(!puede){c.innerHTML=h+'<div class="card muted">Solo administración o gerencia puede gestionar el portal. Tú puedes consultar el proyecto.</div>';return;}

  // Acceso al portal
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Acceso al portal</h3>';
  h+='<div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">';
  h+='<button class="btn '+(p.portal_activo?'':'sec')+'" onclick="togglePortal('+id+','+(p.portal_activo?0:1)+')">'+(p.portal_activo?'● Portal ACTIVO — desactivar':'○ Portal inactivo — activar')+'</button>';
  h+='<button class="btn sec" onclick="invitarPortal('+id+')">Invitar cliente por correo/WhatsApp</button></div>';
  h+='<div id="inviteRes" style="margin-top:.7rem"></div>';
  if(acc&&acc.ultimo_acceso)h+='<p class="muted" style="font-size:.78rem;margin-top:.5rem">Último acceso del cliente: '+acc.ultimo_acceso+'</p>';
  h+='</div>';

  // Etapa visible
  var opts='';
  d.data.etapas.forEach(function(e){opts+='<option value="'+e.clave+'"'+(p.etapa_portal===e.clave?' selected':'')+'>'+e.icono+' '+e.nombre+'</option>';});
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Etapa visible para el cliente</h3>';
  h+='<label>Etapa</label><select id="etapaSel">'+opts+'</select>';
  h+='<label>Nota para el cliente (opcional)</label><textarea id="etapaNota" rows="2" placeholder="Ej: Comenzamos el corte de tus cubiertas."></textarea>';
  h+='<label>Avance % (opcional)</label><input id="etapaAvance" type="number" min="0" max="100" placeholder="'+(p.avance_pct||0)+'">';
  h+='<div style="height:.7rem"></div><button class="btn" onclick="guardarEtapa('+id+')">Actualizar etapa</button></div>';

  // Avance del corte
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Progreso del corte</h3>';
  h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem">';
  h+='<div><label>Avance %</label><input id="avPct" type="number" value="'+(p.avance_pct||0)+'"></div>';
  h+='<div><label>Fecha entrega estimada</label><input id="avFecha" type="date" value="'+(p.fecha_entrega_estimada||'')+'"></div>';
  h+='<div><label>m² procesados</label><input id="avProc" type="number" step="0.1" value="'+(p.m2_procesados||0)+'"></div>';
  h+='<div><label>m² totales</label><input id="avTot" type="number" step="0.1" value="'+(p.m2_totales||0)+'"></div>';
  h+='</div><div style="height:.7rem"></div><button class="btn" onclick="guardarAvance('+id+')">Guardar avance</button></div>';

  // Losas
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Losas para aprobación</h3>';
  (d.data.losas||[]).forEach(function(l){
    var col=l.estado==='aprobado'?'var(--ok)':(l.estado==='revision_solicitada'?'var(--warn)':'var(--txt2)');
    h+='<div style="border-bottom:1px solid var(--bd);padding:.4rem 0"><span>'+(l.descripcion_losa||'')+'</span> — <span style="color:'+col+'">'+l.estado+'</span>'+(l.nota_cliente?('<br><span class="muted" style="font-size:.8rem">Nota del cliente: '+l.nota_cliente+'</span>'):'')+'</div>';
  });
  if(!(d.data.losas||[]).length)h+='<p class="muted" style="font-size:.85rem">Aún no agregas losas.</p>';
  h+='<label>Descripción de la losa</label><input id="losaDesc" placeholder="Ej: Calacatta Gold 300x180 · veta central">';
  h+='<label>URL de foto (opcional)</label><input id="losaFoto" placeholder="https://…">';
  h+='<div style="height:.7rem"></div><button class="btn sec" onclick="agregarLosa('+id+')">Agregar losa para aprobar</button></div>';

  // Chat
  h+='<div class="card"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Chat con el cliente (portal)</h3><div style="max-height:240px;overflow:auto;padding:.3rem 0">';
  (d.data.mensajes||[]).forEach(function(m){
    var mine=m.direction==='aslan';
    h+='<div style="max-width:80%;padding:.5rem .8rem;border-radius:10px;margin:.3rem 0;font-size:.86rem;'+(mine?'background:var(--gold);color:#fff;margin-left:auto':'background:#2a2a2a')+'">'+m.mensaje+'</div>';
  });
  if(!(d.data.mensajes||[]).length)h+='<p class="muted" style="font-size:.85rem">Sin mensajes todavía.</p>';
  h+='</div><div style="display:flex;gap:.5rem;margin-top:.6rem"><input id="admMsg" placeholder="Responder al cliente…" onkeydown="if(event.key===\\'Enter\\')responderPortal('+id+')"><button class="btn" onclick="responderPortal('+id+')">Enviar</button></div></div>';

  c.innerHTML=h;
}
async function togglePortal(id,activo){var d=await api('/api/admin/proyectos/'+id+'/portal/toggle',{method:'PUT',body:JSON.stringify({activo:!!activo})});if(d&&d.ok){toast(activo?'Portal activado':'Portal desactivado');abrirProyecto(id);}}
async function guardarEtapa(id){var d=await api('/api/admin/proyectos/'+id+'/portal/etapa',{method:'PUT',body:JSON.stringify({etapa_clave:document.getElementById('etapaSel').value,nota:document.getElementById('etapaNota').value,avance_pct:document.getElementById('etapaAvance').value})});if(d&&d.ok){toast('Etapa actualizada — el cliente fue notificado');abrirProyecto(id);}else if(d){toast(d.error);}}
async function guardarAvance(id){var d=await api('/api/admin/proyectos/'+id+'/portal/avance',{method:'PUT',body:JSON.stringify({avance_pct:document.getElementById('avPct').value,m2_procesados:document.getElementById('avProc').value,m2_totales:document.getElementById('avTot').value,fecha_entrega_estimada:document.getElementById('avFecha').value})});if(d&&d.ok){toast('Avance guardado');abrirProyecto(id);}}
async function agregarLosa(id){var desc=document.getElementById('losaDesc').value;if(!desc){toast('Describe la losa');return;}var d=await api('/api/admin/proyectos/'+id+'/portal/losa',{method:'POST',body:JSON.stringify({descripcion_losa:desc,foto_url_losa:document.getElementById('losaFoto').value})});if(d&&d.ok){toast('Losa agregada para aprobación');abrirProyecto(id);}}
async function responderPortal(id){var inp=document.getElementById('admMsg');if(!inp.value.trim())return;var d=await api('/api/admin/proyectos/'+id+'/portal/mensaje',{method:'POST',body:JSON.stringify({mensaje:inp.value})});if(d&&d.ok){inp.value='';abrirProyecto(id);}}
async function invitarPortal(id){
  var d=await api('/api/admin/proyectos/'+id+'/portal/invitar',{method:'POST',body:JSON.stringify({})});
  var box=document.getElementById('inviteRes');if(!box)return;
  if(!d||!d.ok){box.innerHTML='<span style="color:var(--err)">'+((d&&d.error)||'Error')+'</span>';return;}
  var msg=d.data.mensaje_whatsapp||'';
  var h='<div style="background:#111;border:1px solid var(--bd);border-radius:6px;padding:.7rem;font-size:.85rem">';
  if(d.data.ya_existia){h+='<p style="color:var(--ok)">El cliente ya tiene acceso. Acceso por: <strong>'+d.data.url+'</strong> · Usuario: '+d.data.email+'</p>';}
  else{h+='<p style="color:var(--ok)">✓ Acceso creado.</p><p>Acceso: <strong>'+d.data.url+'</strong></p><p>Usuario: '+d.data.email+'</p><p>Contraseña temporal: <strong style="color:var(--gold)">'+d.data.password_temporal+'</strong></p>';}
  h+='<div style="display:flex;gap:.5rem;margin-top:.5rem"><button class="btn sec" onclick="navigator.clipboard.writeText('+JSON.stringify(msg)+');toast(\\'Mensaje copiado\\')">Copiar mensaje para el cliente</button></div></div>';
  box.innerHTML=h;
}

// ====================== COTIZACIONES ======================
function volverCot(){go('cotizaciones');}
async function viewCotizaciones(c){
  document.getElementById('acciones').innerHTML='<button class="btn" onclick="nuevaCotizacion()">+ Nueva cotización</button>';
  var d=await api('/api/cotizaciones');if(!d||!d.ok)return;
  var h='<div class="card"><table><thead><tr><th>Folio</th><th>Cliente</th><th>Total</th><th>Estado</th><th>Vendedor</th><th>Acciones</th></tr></thead><tbody>';
  d.data.forEach(function(r){
    var conv=(r.estado==='aceptada')?' <button class="btn" style="padding:.3rem .6rem" onclick="convertirCot('+r.id+')">→ Proyecto</button>':'';
    h+='<tr><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+money(r.total)+'</td><td>'+estadoCotSel(r.estado,r.id)+'</td><td>'+(r.vendedor||'—')+'</td>'+
       '<td style="white-space:nowrap"><button class="btn sec" style="padding:.3rem .6rem" onclick="pdfCotizacion('+r.id+')">PDF</button>'+conv+'</td></tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="6" class="muted">Sin cotizaciones. Crea la primera.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
function estadoCotSel(e,id){
  var ops=['borrador','enviada','aceptada','rechazada','expirada'].map(function(s){return '<option value="'+s+'"'+(s===e?' selected':'')+'>'+s+'</option>';}).join('');
  return '<select style="width:auto;padding:.25rem .4rem;font-size:.78rem" onchange="cambiarEstadoCot('+id+',this.value)">'+ops+'</select>';
}
async function cambiarEstadoCot(id,estado){var d=await api('/api/cotizaciones/'+id,{method:'PUT',body:JSON.stringify({estado:estado})});if(d&&d.ok)toast('Estado: '+estado);}
async function convertirCot(id){if(!confirm('¿Convertir esta cotización en proyecto?'))return;var d=await api('/api/cotizaciones/'+id+'/convertir',{method:'POST',body:JSON.stringify({})});if(d&&d.ok){toast('Proyecto '+d.data.folio+' creado');go('proyectos');}else if(d){toast(d.error);}}

var COT_PROD=[];var cotSeq=0;
async function nuevaCotizacion(){
  document.getElementById('acciones').innerHTML='';
  document.getElementById('titulo').textContent='Nueva cotización';
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  var dc=await api('/api/clientes');var dp=await api('/api/productos');
  if(!dc||!dp)return;
  COT_PROD=dp.data;
  var cliOpts='<option value="">— Selecciona cliente —</option>';
  dc.data.forEach(function(cl){cliOpts+='<option value="'+cl.id+'">'+escAttr(cl.nombre)+(cl.empresa?(' · '+escAttr(cl.empresa)):'')+'</option>';});
  var h='<span class="back" onclick="volverCot()" style="cursor:pointer;color:var(--gold2)">‹ Volver</span>';
  h+='<div class="card" style="margin-top:.5rem">';
  h+='<label>Cliente</label><select id="cotCliente">'+cliOpts+'</select>';
  h+='<div style="overflow-x:auto;margin-top:1rem"><table><thead><tr><th>Material</th><th>Descripción</th><th>Cant.</th><th>Unidad</th><th>P. Unit.</th><th>Desc%</th><th>Importe</th><th></th></tr></thead><tbody id="cotBody"></tbody></table></div>';
  h+='<button class="btn sec" style="margin-top:.6rem" onclick="agregarFila()">+ Agregar línea</button>';
  h+='<div style="display:grid;grid-template-columns:1fr 1fr;gap:.6rem;margin-top:1rem;max-width:430px;margin-left:auto"><div><label>Descuento global %</label><input id="cotDescG" type="number" value="0" oninput="recalcCot()"></div><div><label>IVA %</label><input id="cotIva" type="number" value="16" oninput="recalcCot()"></div><div><label>Vigencia (días)</label><input id="cotVig" type="number" value="15"></div></div>';
  h+='<div style="text-align:right;margin-top:1rem"><div>Subtotal: <strong id="cotSub">$0.00</strong></div><div>IVA: <strong id="cotIvaM">$0.00</strong></div><div style="font-size:1.3rem;color:var(--gold);margin-top:.3rem">TOTAL: <strong id="cotTotal">$0.00</strong></div></div>';
  h+='<label style="margin-top:1rem">Notas</label><textarea id="cotNotas" rows="2" placeholder="Ej: Suministro y corte de cubiertas."></textarea>';
  h+='<label>Condiciones</label><textarea id="cotCond" rows="2">Precios en MXN. Sujeto a disponibilidad de material. Tiempo de entrega a confirmar.</textarea>';
  h+='<div style="height:.8rem"></div><button class="btn" onclick="guardarCotizacion()">Guardar cotización</button></div>';
  c.innerHTML=h;
  agregarFila();
}
function agregarFila(){
  cotSeq++;
  var po='<option value="">— libre —</option>';
  COT_PROD.forEach(function(p){po+='<option value="'+p.id+'" data-precio="'+(p.precio_venta||0)+'" data-unidad="'+(p.unidad||'m2')+'" data-nombre="'+escAttr(p.nombre)+'">'+escAttr(p.nombre)+'</option>';});
  var tr=document.createElement('tr');tr.className='cotlin';
  tr.innerHTML='<td><select onchange="autoProd(this)" style="min-width:150px">'+po+'</select></td>'+
    '<td><input class="c-desc" placeholder="Descripción" style="min-width:150px"></td>'+
    '<td><input class="c-cant" type="number" step="0.01" value="1" oninput="recalcCot()" style="width:70px"></td>'+
    '<td><input class="c-uni" value="m2" style="width:60px"></td>'+
    '<td><input class="c-pu" type="number" step="0.01" value="0" oninput="recalcCot()" style="width:95px"></td>'+
    '<td><input class="c-dl" type="number" step="0.01" value="0" oninput="recalcCot()" style="width:55px"></td>'+
    '<td class="c-sl" style="white-space:nowrap">$0.00</td>'+
    '<td><button class="btn err" style="padding:.25rem .55rem" onclick="this.closest(\\'tr\\').remove();recalcCot()">×</button></td>';
  document.getElementById('cotBody').appendChild(tr);
}
function autoProd(sel){
  var o=sel.options[sel.selectedIndex];var tr=sel.closest('tr');
  if(o&&o.value){tr.querySelector('.c-pu').value=o.getAttribute('data-precio')||0;tr.querySelector('.c-uni').value=o.getAttribute('data-unidad')||'m2';var dsc=tr.querySelector('.c-desc');if(!dsc.value)dsc.value=o.getAttribute('data-nombre')||'';}
  recalcCot();
}
function recalcCot(){
  var sub=0;
  document.querySelectorAll('#cotBody tr.cotlin').forEach(function(tr){
    var cant=parseFloat(tr.querySelector('.c-cant').value)||0;
    var pu=parseFloat(tr.querySelector('.c-pu').value)||0;
    var dl=parseFloat(tr.querySelector('.c-dl').value)||0;
    var sl=cant*pu*(1-dl/100);
    tr.querySelector('.c-sl').textContent=money(sl);
    sub+=sl;
  });
  var dg=parseFloat(document.getElementById('cotDescG').value)||0;
  var iva=parseFloat(document.getElementById('cotIva').value)||0;
  var base=sub*(1-dg/100),ivaM=base*iva/100,total=base+ivaM;
  document.getElementById('cotSub').textContent=money(sub);
  document.getElementById('cotIvaM').textContent=money(ivaM);
  document.getElementById('cotTotal').textContent=money(total);
}
function recogerLineas(){
  var items=[];
  document.querySelectorAll('#cotBody tr.cotlin').forEach(function(tr){
    var sel=tr.querySelector('select');
    items.push({producto_id:sel.value||null,descripcion:tr.querySelector('.c-desc').value,cantidad:tr.querySelector('.c-cant').value,unidad:tr.querySelector('.c-uni').value,precio_unitario:tr.querySelector('.c-pu').value,descuento_linea_pct:tr.querySelector('.c-dl').value});
  });
  return items.filter(function(it){return it.descripcion||it.producto_id;});
}
async function guardarCotizacion(){
  var cliente=document.getElementById('cotCliente').value;
  if(!cliente){toast('Selecciona un cliente');return;}
  var items=recogerLineas();
  if(!items.length){toast('Agrega al menos una línea');return;}
  var body={cliente_id:cliente,items:items,descuento_global_pct:document.getElementById('cotDescG').value,iva_pct:document.getElementById('cotIva').value,vigencia_dias:document.getElementById('cotVig').value,notas:document.getElementById('cotNotas').value,condiciones:document.getElementById('cotCond').value};
  var d=await api('/api/cotizaciones',{method:'POST',body:JSON.stringify(body)});
  if(d&&d.ok){toast('Cotización '+d.data.folio+' creada');go('cotizaciones');}else if(d){toast(d.error);}
}
function escAttr(s){return String(s==null?'':s).replace(/"/g,'&quot;');}

async function pdfCotizacion(id){
  var d=await api('/api/cotizaciones/'+id);if(!d||!d.ok){toast('No se pudo cargar la cotización');return;}
  if(!window.jspdf||!window.jspdf.jsPDF){toast('Generador de PDF no cargó, reintenta');return;}
  var c=d.data;var gold=[139,109,63];
  var doc=new window.jspdf.jsPDF();
  doc.setFontSize(26);doc.setTextColor(gold[0],gold[1],gold[2]);doc.text('ASLAN',14,20);
  doc.setFontSize(8);doc.setTextColor(90);
  doc.text(${JSON.stringify(EMPRESA.direccion)},14,26);
  doc.text('RFC: '+${JSON.stringify(EMPRESA.rfc)}+'    Tel: '+${JSON.stringify(EMPRESA.telefono)},14,30);
  doc.text(${JSON.stringify(EMPRESA.email)},14,34);
  doc.setFontSize(16);doc.setTextColor(40);doc.text('COTIZACIÓN',196,18,{align:'right'});
  doc.setFontSize(9);
  doc.text('Folio: '+(c.folio||''),196,25,{align:'right'});
  doc.text('Fecha: '+new Date().toLocaleDateString('es-MX'),196,30,{align:'right'});
  doc.text('Vigencia: '+(c.vigencia_dias||15)+' dias',196,35,{align:'right'});
  doc.setDrawColor(gold[0],gold[1],gold[2]);doc.line(14,39,196,39);
  doc.setFontSize(10);doc.setTextColor(40);
  doc.text('Cliente: '+(c.cliente||''),14,47);
  if(c.cliente_empresa)doc.text('Empresa: '+c.cliente_empresa,14,52);
  if(c.cliente_rfc)doc.text('RFC: '+c.cliente_rfc,120,52);
  var body=(c.items||[]).map(function(it){return [it.descripcion||'',String(it.cantidad),it.unidad||'',money(it.precio_unitario),(it.descuento_linea_pct||0)+'%',money(it.subtotal_linea)];});
  doc.autoTable({startY:58,head:[['Material / Descripción','Cant.','Unidad','P. Unit.','Desc.','Importe']],body:body,theme:'grid',headStyles:{fillColor:gold,textColor:255,fontSize:8},styles:{fontSize:8,textColor:40},columnStyles:{0:{cellWidth:64}}});
  var y=(doc.lastAutoTable?doc.lastAutoTable.finalY:64)+8;
  var base=c.subtotal*(1-(c.descuento_global_pct||0)/100);var ivaM=c.total-base;
  doc.setFontSize(10);doc.setTextColor(40);
  doc.text('Subtotal: '+money(c.subtotal),196,y,{align:'right'});
  if(c.descuento_global_pct){doc.text('Descuento '+c.descuento_global_pct+'%: -'+money(c.subtotal-base),196,y+5,{align:'right'});y+=5;}
  doc.text('IVA '+(c.iva_pct||16)+'%: '+money(ivaM),196,y+5,{align:'right'});
  doc.setFontSize(13);doc.setTextColor(gold[0],gold[1],gold[2]);
  doc.text('TOTAL: '+money(c.total),196,y+13,{align:'right'});
  if(c.condiciones){doc.setFontSize(7);doc.setTextColor(120);doc.text(doc.splitTextToSize(c.condiciones,180),14,y+26);}
  doc.save((c.folio||'cotizacion')+'.pdf');
}

renderNav();
if(USER.debe_cambiar){toast('Recuerda cambiar tu contraseña en Configuración');}
go('dashboard');
</script></body></html>`;
}

// ============================================================================
//  FRONTEND — CHECK-IN GPS (standalone móvil)
// ============================================================================
function renderCheckin() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Check-in</title>${FONTS}<style>${baseStyles(false)}
.wrap{min-height:100vh;display:flex;flex-direction:column;align-items:center;justify-content:center;padding:1.5rem;text-align:center}
.big{width:200px;height:200px;border-radius:50%;font-size:1.4rem;font-weight:700;border:none;color:#fff;cursor:pointer;box-shadow:0 8px 40px rgba(0,0,0,.5)}
.in{background:var(--ok)} .out{background:var(--err)}
.clock{font-size:3rem;font-family:'Cormorant Garamond',serif;color:var(--gold);margin:1rem 0}
</style></head><body>
<div class="wrap">
<h1 style="color:var(--gold);letter-spacing:.3em">ASLAN</h1>
<div class="clock" id="clock">--:--</div>
<button class="big in" id="btn" onclick="accion()">CHECK-IN</button>
<p class="muted" id="estado" style="margin-top:1.4rem">Pulsa para registrar tu entrada</p>
</div>
<script>
var TOKEN=localStorage.getItem('aslan_token');
if(!TOKEN)location.href='/login';
setInterval(function(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('es-MX',{hour:'2-digit',minute:'2-digit'});},1000);
function accion(){
  document.getElementById('estado').textContent='Obteniendo ubicación…';
  navigator.geolocation.getCurrentPosition(function(pos){
    document.getElementById('estado').textContent='Ubicación registrada · '+pos.coords.latitude.toFixed(4)+', '+pos.coords.longitude.toFixed(4)+' (demo — envío al API en la siguiente capa)';
  },function(){document.getElementById('estado').textContent='No se pudo obtener tu ubicación. Activa el GPS.';});
}
</script></body></html>`;
}

// ============================================================================
//  (El login del portal se eliminó: ahora el acceso es ÚNICO vía renderLogin)
// ============================================================================

// ============================================================================
//  FRONTEND — SPA DEL PORTAL CLIENTE
// ============================================================================
function renderPortalApp() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Mi Portal</title>${FONTS}<style>${baseStyles(true)}
.nav{display:flex;justify-content:space-between;align-items:center;padding:1rem 1.4rem;border-bottom:1px solid var(--bd);position:sticky;top:0;background:rgba(15,15,15,.92);backdrop-filter:blur(8px);z-index:10}
.nav h1{color:var(--gold);font-size:1.7rem;letter-spacing:.28em}
.nav .right{display:flex;align-items:center;gap:1rem;font-size:.85rem}
.avatar{width:36px;height:36px;border-radius:50%;background:var(--gold);color:#fff;display:flex;align-items:center;justify-content:center;font-weight:700}
.container{max-width:840px;margin:0 auto;padding:1.4rem}
.serif-title{font-family:'Cormorant Garamond',serif;font-size:2rem;color:var(--txt);margin:.4rem 0 1rem}
.proj-card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:1.2rem;margin-bottom:1rem;cursor:pointer;transition:.15s}
.proj-card:hover{border-color:var(--gold);transform:translateY(-2px)}
.bar{height:8px;background:#2a2a2a;border-radius:99px;overflow:hidden;margin:.6rem 0}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--gold),var(--gold2))}
.etapa-pill{display:inline-block;padding:.25rem .8rem;border-radius:99px;font-size:.74rem;background:rgba(139,109,63,.18);color:var(--gold2);border:1px solid var(--bd)}
.tracker{display:flex;gap:.4rem;overflow-x:auto;padding:1rem 0}
.step{flex:0 0 auto;text-align:center;width:92px;opacity:.4}
.step.done{opacity:1} .step.current{opacity:1}
.step .dot{width:46px;height:46px;border-radius:50%;background:#222;border:2px solid var(--bd);display:flex;align-items:center;justify-content:center;font-size:1.3rem;margin:0 auto .4rem}
.step.done .dot{border-color:var(--ok);background:rgba(76,175,80,.12)}
.step.current .dot{border-color:var(--gold);background:rgba(139,109,63,.2);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(139,109,63,.5)}50%{box-shadow:0 0 0 8px rgba(139,109,63,0)}}
.step .nm{font-size:.66rem;color:var(--txt2);line-height:1.2}
.chat{max-height:300px;overflow-y:auto;padding:.5rem 0}
.msg{max-width:78%;padding:.6rem .9rem;border-radius:12px;margin:.4rem 0;font-size:.88rem}
.msg.aslan{background:#222;border:1px solid var(--bd)}
.msg.cliente{background:var(--gold);color:#fff;margin-left:auto}
.back{cursor:pointer;color:var(--gold2);font-size:.85rem;margin-bottom:.6rem;display:inline-block}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:99;padding:1rem}
.modal.open{display:flex}
.modal .inner{background:var(--card);border:1px solid var(--gold);border-radius:10px;padding:1.4rem;max-width:380px;width:100%}
</style></head><body>
<div class="nav"><h1>ASLAN</h1><div class="right"><span id="nombreCli" class="muted"></span><div class="avatar" id="avatar">·</div><a onclick="logout()" style="cursor:pointer">salir</a></div></div>
<div class="container" id="app">Cargando…</div>

<div class="modal" id="calcModal"><div class="inner">
<h3 class="serif" style="color:var(--gold);font-size:1.5rem">¿Cuánto material necesitas?</h3>
<label>Largo (m)</label><input id="cLargo" type="number" step="0.1">
<label>Ancho (m)</label><input id="cAncho" type="number" step="0.1">
<label>Tipo de espacio</label><select id="cTipo"><option value="1.10">Piso (+10%)</option><option value="1.10">Barra de cocina (+10%)</option><option value="1.15">Escaleras (+15%)</option><option value="1.12">Baño (+12%)</option><option value="1.10">Fachada (+10%)</option></select>
<div style="height:.8rem"></div><button class="btn block" onclick="calcular()">Calcular</button>
<div id="calcRes" style="margin-top:.9rem;text-align:center"></div>
<button class="btn sec block" style="margin-top:.6rem" onclick="document.getElementById('calcModal').classList.remove('open')">Cerrar</button>
</div></div>
<script>
var TOKEN=localStorage.getItem('aslan_token');
var USER=JSON.parse(localStorage.getItem('aslan_user')||'null');
if(!TOKEN||!USER){location.href='/login';}
else if(USER.rol!=='cliente'){location.href='/dashboard';} // el equipo va al sistema interno
function H(){return {'Content-Type':'application/json','Authorization':'Bearer '+TOKEN};}
async function api(p,opt){opt=opt||{};opt.headers=H();var r=await fetch(p,opt);if(r.status===401){localStorage.clear();location.href='/login';return null;}return await r.json();}
function logout(){localStorage.clear();location.href='/login';}
function fecha(s){if(!s)return '—';try{return new Date(s.replace(' ','T')+'Z').toLocaleDateString('es-MX',{day:'2-digit',month:'short',year:'numeric'});}catch(e){return s;}}
function dias(s){if(!s)return 0;var d=Math.floor((Date.now()-new Date(s.replace(' ','T')).getTime())/86400000);return d>0?d:0;}
var ETAPAS=[];

function route(){
  var m=location.pathname.match(/\\/portal\\/proyecto\\/(\\d+)/);
  if(m)return detalle(m[1]);
  dashboard();
}
async function dashboard(){
  var d=await api('/api/portal/dashboard');if(!d||!d.ok){document.getElementById('app').innerHTML='<div class="card">'+(d?d.error:'Error')+'</div>';return;}
  ETAPAS=d.data.etapas;
  var cli=d.data.cliente||{};
  document.getElementById('nombreCli').textContent=cli.empresa||cli.nombre||'';
  document.getElementById('avatar').textContent=(cli.nombre||'C').substring(0,1).toUpperCase();
  var h='<div class="serif-title">Bienvenido, '+(cli.nombre||'')+'</div>';
  if(cli.empresa)h+='<p class="muted" style="margin-top:-.8rem;margin-bottom:1rem">'+cli.empresa+'</p>';
  h+='<h3 style="color:var(--gold);font-size:1.2rem;margin:.6rem 0">Proyectos activos</h3>';
  if(!d.data.activos.length)h+='<div class="card muted">Aún no tienes proyectos activos. El equipo ASLAN los habilitará pronto.</div>';
  d.data.activos.forEach(function(p){
    var et=ETAPAS.find(function(e){return e.clave===p.etapa_portal;})||{nombre:'—',icono:''};
    h+='<div class="proj-card" onclick="location.href=\\'/portal/proyecto/'+p.id+'\\'">'+
       '<div style="display:flex;justify-content:space-between;align-items:start"><div><strong>'+(p.folio||'')+'</strong><br><span class="muted" style="font-size:.85rem">'+(p.descripcion||'')+'</span></div><span class="etapa-pill">'+et.icono+' '+et.nombre+'</span></div>'+
       '<div class="bar"><i style="width:'+(p.avance_pct||0)+'%"></i></div>'+
       '<div style="display:flex;justify-content:space-between;font-size:.78rem" class="muted"><span>'+(p.material_principal||'')+'</span><span>'+(p.avance_pct||0)+'% · entrega '+fecha(p.fecha_entrega_estimada)+'</span></div>'+
       '</div>';
  });
  if(d.data.anteriores.length){
    h+='<h3 style="color:var(--gold);font-size:1.2rem;margin:1.2rem 0 .6rem">Proyectos anteriores</h3>';
    d.data.anteriores.forEach(function(p){h+='<div class="card" style="margin-bottom:.5rem;display:flex;justify-content:space-between"><span>'+(p.folio||'')+' · '+(p.material_principal||'')+'</span><span class="muted">'+fecha(p.fecha_entrega_real)+'</span></div>';});
  }
  h+='<h3 style="color:var(--gold);font-size:1.2rem;margin:1.2rem 0 .6rem">Acciones rápidas</h3><div style="display:flex;gap:.6rem;flex-wrap:wrap">'+
     '<a class="btn" href="https://wa.me/${EMPRESA.whatsapp}?text=Hola%20ASLAN%2C%20quiero%20una%20cotizaci%C3%B3n" target="_blank">Nueva cotización</a>'+
     '<button class="btn sec" onclick="document.getElementById(\\'calcModal\\').classList.add(\\'open\\')">Calculadora m²</button>';
  if(d.data.asesor)h+='<a class="btn sec" href="https://wa.me/${EMPRESA.whatsapp}?text=Hola%20'+encodeURIComponent(d.data.asesor.nombre)+'" target="_blank">Contactar asesor</a>';
  h+='</div>';
  document.getElementById('app').innerHTML=h;
}

async function detalle(id){
  var d=await api('/api/portal/proyectos/'+id);if(!d||!d.ok){document.getElementById('app').innerHTML='<div class="card">'+(d?d.error:'Error')+'</div>';return;}
  ETAPAS=d.data.etapas;var p=d.data.proyecto;
  var idxActual=ETAPAS.findIndex(function(e){return e.clave===p.etapa_portal;});
  var h='<span class="back" onclick="history.back()">‹ Volver a mis proyectos</span>';
  h+='<div class="serif-title">'+(p.folio||'')+'</div><p class="muted" style="margin-top:-.8rem;margin-bottom:.4rem">'+(p.descripcion||'')+'</p>';
  // Tracker
  h+='<div class="card"><div class="tracker">';
  ETAPAS.forEach(function(e,i){
    var cls=i<idxActual?'done':(i===idxActual?'current':'');
    h+='<div class="step '+cls+'"><div class="dot">'+e.icono+'</div><div class="nm">'+e.nombre+'</div></div>';
  });
  h+='</div></div>';
  // Progreso de corte
  if(p.etapa_portal==='en_corte'||p.etapa_portal==='control_calidad'){
    var pct=p.m2_totales>0?Math.round(p.m2_procesados/p.m2_totales*100):p.avance_pct;
    h+='<div class="card" style="margin-top:1rem;text-align:center"><div class="muted" style="font-size:.8rem;text-transform:uppercase;letter-spacing:.05em">Progreso del corte</div>'+
       '<div style="font-size:3rem;color:var(--gold);font-family:\\'Cormorant Garamond\\',serif;font-weight:700">'+pct+'%</div>'+
       '<div class="bar" style="max-width:300px;margin:.4rem auto"><i style="width:'+pct+'%"></i></div>'+
       '<div class="muted">'+p.m2_procesados+' de '+p.m2_totales+' m² procesados · '+dias(p.fecha_inicio)+' días en proceso</div></div>';
  }
  // Losa
  if(d.data.losas.length){
    h+='<div class="card" style="margin-top:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Tu material</h3>';
    d.data.losas.forEach(function(l){
      h+='<div style="border-bottom:1px solid var(--bd);padding:.6rem 0"><p>'+(l.descripcion_losa||'')+'</p>';
      if(l.estado==='pendiente'){
        h+='<p class="muted" style="font-size:.85rem;margin:.4rem 0">Revisa y aprueba para que comencemos el corte.</p>'+
           '<div style="display:flex;gap:.5rem;flex-wrap:wrap"><button class="btn ok" onclick="aprobar('+id+','+l.id+',true)">✓ Aprobar este material</button>'+
           '<button class="btn sec" onclick="aprobar('+id+','+l.id+',false)">Solicitar revisión</button></div>';
      }else if(l.estado==='aprobado'){
        h+='<p style="color:var(--ok);font-size:.88rem;margin-top:.3rem">✓ Material aprobado'+(l.respondido_en?' el '+fecha(l.respondido_en):'')+'</p>';
      }else{
        h+='<p style="color:var(--warn);font-size:.88rem;margin-top:.3rem">Revisión solicitada — el equipo ASLAN se pondrá en contacto.</p>';
      }
      h+='</div>';
    });
    h+='</div>';
  }
  // Documentos
  h+='<div class="card" style="margin-top:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Documentos</h3>'+
     '<div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--bd)"><span>📄 Cotización</span><span class="muted">Disponible</span></div>'+
     '<div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--bd)"><span>📋 Orden de trabajo</span><span class="muted">Disponible</span></div>'+
     '<div style="display:flex;justify-content:space-between;padding:.4rem 0"><span>🧾 Remisión</span><span class="muted">Próximamente</span></div>'+
     '<p class="muted" style="font-size:.78rem;margin-top:.5rem">La descarga en PDF se habilita en la siguiente capa.</p></div>';
  // Chat
  h+='<div class="card" style="margin-top:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Chat con el equipo ASLAN</h3><div class="chat" id="chat">';
  d.data.mensajes.forEach(function(m){h+='<div class="msg '+(m.direction==='cliente'?'cliente':'aslan')+'">'+m.mensaje+'</div>';});
  if(!d.data.mensajes.length)h+='<p class="muted">Escríbenos cualquier duda sobre tu proyecto.</p>';
  h+='</div><div style="display:flex;gap:.5rem;margin-top:.6rem"><input id="msgInput" placeholder="Escribe un mensaje…" onkeydown="if(event.key===\\'Enter\\')enviar('+id+')"><button class="btn" onclick="enviar('+id+')">Enviar</button></div></div>';
  // Asesor
  if(d.data.asesor){
    h+='<div class="card" style="margin-top:1rem;display:flex;align-items:center;gap:1rem"><div class="avatar" style="width:48px;height:48px">'+(d.data.asesor.nombre||'A').substring(0,1)+'</div><div><strong>'+d.data.asesor.nombre+'</strong><br><span class="muted" style="font-size:.82rem">'+(d.data.asesor.cargo||'Asesor ASLAN')+'</span></div><a class="btn sec" style="margin-left:auto" href="https://wa.me/${EMPRESA.whatsapp}?text=Hola%2C%20pregunta%20sobre%20'+(p.folio||'')+'" target="_blank">WhatsApp</a></div>';
  }
  document.getElementById('app').innerHTML=h;
  var ch=document.getElementById('chat');if(ch)ch.scrollTop=ch.scrollHeight;
}
async function aprobar(proy,losa,ap){
  if(!ap){var nota=prompt('¿Qué te gustaría revisar?');if(nota===null)return;var d=await api('/api/portal/proyectos/'+proy+'/losa/aprobar',{method:'POST',body:JSON.stringify({losa_id:losa,aprobado:false,nota:nota})});}
  else{var d=await api('/api/portal/proyectos/'+proy+'/losa/aprobar',{method:'POST',body:JSON.stringify({losa_id:losa,aprobado:true})});}
  if(d&&d.ok){toast(ap?'¡Material aprobado!':'Revisión solicitada');detalle(proy);}
}
async function enviar(id){
  var inp=document.getElementById('msgInput');if(!inp.value.trim())return;
  var d=await api('/api/portal/proyectos/'+id+'/mensajes',{method:'POST',body:JSON.stringify({mensaje:inp.value})});
  if(d&&d.ok){inp.value='';detalle(id);}
}
function toast(t){var x=document.createElement('div');x.style.cssText='position:fixed;top:1rem;right:1rem;background:#181818;border:1px solid var(--gold);padding:.8rem 1.1rem;border-radius:6px;z-index:9999';x.textContent=t;document.body.appendChild(x);setTimeout(function(){x.remove();},2600);}
function calcular(){
  var l=parseFloat(document.getElementById('cLargo').value)||0,a=parseFloat(document.getElementById('cAncho').value)||0,f=parseFloat(document.getElementById('cTipo').value)||1.1;
  var m2=(l*a*f);var r=document.getElementById('calcRes');
  if(m2<=0){r.innerHTML='<span class="muted">Ingresa medidas válidas.</span>';return;}
  r.innerHTML='<div style="font-size:1.8rem;color:var(--gold);font-family:\\'Cormorant Garamond\\',serif">Necesitas ≈ '+m2.toFixed(2)+' m²</div><a class="btn block" style="margin-top:.6rem" href="https://wa.me/${EMPRESA.whatsapp}?text=Hola%20ASLAN%2C%20necesito%20cotizaci%C3%B3n%20para%20'+m2.toFixed(2)+'%20m2" target="_blank">Solicitar cotización</a>';
}
window.addEventListener('popstate',route);
route();
</script></body></html>`;
}
