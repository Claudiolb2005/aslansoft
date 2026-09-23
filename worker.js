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
  { clave: "cotizacion_aceptada", nombre: "Cotización Aceptada", icono: "<path d='M6 2h9l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z'/><path d='M14 2v6h6'/><path d='M9 15l2 2 4-4'/>", desc: "El proyecto fue confirmado" },
  { clave: "material_confirmado", nombre: "Material en Almacén", icono: "<path d='M21 8l-9 4-9-4 9-4 9 4z'/><path d='M3 8v8l9 4 9-4V8'/><path d='M12 12v8'/>", desc: "Tu material está en nuestro almacén" },
  { clave: "pendiente_aprobacion", nombre: "Losa Lista para Aprobar", icono: "<path d='M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z'/><circle cx='12' cy='12' r='3'/>", desc: "Requiere tu aprobación" },
  { clave: "en_corte", nombre: "En Proceso de Corte", icono: "<circle cx='12' cy='12' r='3.2'/><path d='M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'/>", desc: "Tu mármol está siendo procesado" },
  { clave: "control_calidad", nombre: "Control de Calidad", icono: "<circle cx='11' cy='11' r='7'/><path d='M21 21l-4.3-4.3'/>", desc: "Revisión y acabados finales" },
  { clave: "listo_entrega", nombre: "Listo para Entrega", icono: "<path d='M21 8l-9 4-9-4 9-4 9 4z'/><path d='M3 8v8l9 4 9-4V8'/><path d='M9 12l2 2 4-4'/>", desc: "Tu pedido está listo" },
  { clave: "en_camino", nombre: "En Camino", icono: "<path d='M3 6h11v9H3z'/><path d='M14 9h4l3 3v3h-7z'/><circle cx='7' cy='18' r='1.6'/><circle cx='17' cy='18' r='1.6'/>", desc: "Tu pedido está en ruta" },
  { clave: "entregado", nombre: "Entregado", icono: "<circle cx='12' cy='12' r='9'/><path d='M8.5 12.5l2.5 2.5 5-5'/>", desc: "Proyecto completado" },
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
  return new Response(body, { status, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store, must-revalidate", ...CORS } });
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
  fecha_lead TEXT, origen TEXT, validacion TEXT, estatus_final TEXT,
  asesor TEXT, estatus_nota TEXT, fecha_contacto TEXT, propuesta_factura TEXT,
  notas_vero TEXT, notas_actualizacion TEXT, notas_seguimiento TEXT,
  material TEXT, propuesta_antes_iva REAL, moneda TEXT, facturado REAL,
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
  vigencia_dias INTEGER DEFAULT 7, notas TEXT, condiciones TEXT,
  entrega_direccion TEXT, entrega_referencias TEXT, entrega_telefono TEXT,
  cond_pago TEXT, cond_entrega TEXT, cond_no_incluye TEXT, moneda TEXT,
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
CREATE TABLE IF NOT EXISTS cortes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  folio TEXT,
  producto_id INTEGER, cotizacion_id INTEGER, proyecto_id INTEGER,
  cliente_id INTEGER, empleado_id INTEGER,
  cantidad REAL, unidad TEXT DEFAULT 'm2', medidas TEXT,
  estado TEXT DEFAULT 'pendiente',
  descuenta_inventario INTEGER DEFAULT 0, movimiento_id INTEGER,
  notas TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  deleted_at DATETIME
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
CREATE TABLE IF NOT EXISTS cliente_archivos (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cliente_id INTEGER NOT NULL, url_r2 TEXT NOT NULL,
  nombre TEXT NOT NULL, categoria TEXT, content_type TEXT, tamano INTEGER,
  usuario_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME
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
CREATE TABLE IF NOT EXISTS app_config (
  clave TEXT PRIMARY KEY, valor TEXT,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
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
// ============================================================================
//  MIGRACIÓN AUTOMÁTICA V3 — columnas del CRM (registro de prospectos)
//  + carga inicial de los registros de ejemplo. Idempotente y autoejecutable.
// ============================================================================
let MIGRADO_V3 = false;
async function migrarV3(env) {
  if (MIGRADO_V3) return;
  // ¿ya se aplicó? (flag en app_config). Si app_config aún no existe, salir sin tocar nada.
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v3_crm'").first();
    if (f && f.valor === "ok") { MIGRADO_V3 = true; return; }
  } catch (e) { return; }

  // Agregar columnas nuevas a la tabla clientes (idempotente: si ya existen, SQLite lanza y se ignora)
  const nuevas = [
    "ALTER TABLE clientes ADD COLUMN fecha_lead TEXT",
    "ALTER TABLE clientes ADD COLUMN origen TEXT",
    "ALTER TABLE clientes ADD COLUMN validacion TEXT",
    "ALTER TABLE clientes ADD COLUMN estatus_final TEXT",
    "ALTER TABLE clientes ADD COLUMN asesor TEXT",
    "ALTER TABLE clientes ADD COLUMN estatus_nota TEXT",
    "ALTER TABLE clientes ADD COLUMN fecha_contacto TEXT",
    "ALTER TABLE clientes ADD COLUMN propuesta_factura TEXT",
    "ALTER TABLE clientes ADD COLUMN notas_vero TEXT",
    "ALTER TABLE clientes ADD COLUMN notas_actualizacion TEXT",
    "ALTER TABLE clientes ADD COLUMN notas_seguimiento TEXT",
    "ALTER TABLE clientes ADD COLUMN material TEXT",
    "ALTER TABLE clientes ADD COLUMN acabado TEXT",
    "ALTER TABLE clientes ADD COLUMN formato TEXT",
    "ALTER TABLE clientes ADD COLUMN cantidad TEXT",
    "ALTER TABLE clientes ADD COLUMN propuesta_antes_iva REAL",
    "ALTER TABLE clientes ADD COLUMN moneda TEXT",
    "ALTER TABLE clientes ADD COLUMN facturado REAL",
    "ALTER TABLE clientes ADD COLUMN propuesta_inicial REAL",
    "ALTER TABLE clientes ADD COLUMN propuesta_updated_at TEXT"
  ];
  for (const sql of nuevas) { try { await env.DB.prepare(sql).run(); } catch (e) {} }

  // Carga inicial de los registros de ejemplo (solo si todavía no hay ninguno con origen)
  try {
    const n = await env.DB.prepare("SELECT COUNT(*) AS n FROM clientes WHERE origen IS NOT NULL AND deleted_at IS NULL").first();
    if (!n || n.n === 0) {
      const seed = [
    ["MARIANA SANJURJO",null,null,"prospecto","1-434-144-8444",null,"2026-06-01","IB WHATSAPP","VIABLE","NV","ALEJANDRO","SIN RESPUESTA",null,null,"QUIERE SABER ACERCA DE LOS MATERIALES EN PROMOCIÓN, LE ENVIÉ EL FLYER","9 JUN, S/R   , LE MARCO Y ME DICE QUE NO RECUERDA LA INFO DE ALE, PERO QUE LA REVISA MAS TARDE Y LE COMENTA POR MENSAJE / 19 JUN LE MARCÓ ALE Y NUNCA LE RESPONDIÓ","SE LE MANDAN LAS OPCIONES DE PIEDRA DE PROMOCION Y COMENTA QUE SOLO ESTA COTIZANDO DE MOMENTO , SE LE HA SEGUIDO DANDO SEGUIMIENTO SIN EXITO","MYKONOS",null,"MXN",null],
    ["CHRISTIAN ARROYO",null,null,"prospecto","222-803-0359",null,"2026-06-01","IB WHATSAPP","VIABLE",null,"ALEJANDRO","SEGUIMIENTO",null,null,"MARMOL LISBOA, 300M 60X40X1.5 PARA LOS CABOS","9 JUN, ENE SPERA DE PRECIO POR PARTE DE LA CANTERA, SE ENVIA COTIZACION/ 19 JUN, EN SEG, PROYECTO LOS CABOS, BUSCANDO TRANSPORTE",null,"CREMA LISBOA",null,"MXN",null],
    ["GERARDO ANDRES LOPEZ LOPEZ","ING. OBRA CIVIL E INSTALACIONES",null,"prospecto","241100-4229",null,"2026-06-02","IB MAIL","VIABLE","NV","ALEJANDRO","PRECIO",null,"PROPUESTA","GRANITO SN GABRIEL PARA BARRA DE COMEDOR","9 JUN, EN ESPERA DE LAS MEDIDAS HOY","SE TIENEN DUDAS EN LOS PLANOS QUE SE LE PREGUNTAN AL CLIENTE","NEGRO SAN GABRIEL",19546.0,"MXN",null],
    ["ELENA REYES",null,null,"prospecto","552398-6114",null,"2026-06-02","IB WHATSAPP","VIABLE",null,"ALEJANDRO","SEGUIMIENTO",null,"PROPUESTA","VARIAS CUBIERTAS DE GRANITO SAN GABRIEL, ENVIA PLANO Y DISEÑOS","9 JUN, LICITACION, 210 DEPTOS, EN ESPERA DE ACTUALIZAR PLANO/ 19 JUN, NO HA RESPONDIDO","OBRA EN LICITACION, EN ESPERA DE QUE MANDE PLANOS ACTUALIZADOS","NEGRO SAN GABRIEL",27429.8,"MXN",null],
    ["LUIS IVÁN TORRES",null,null,"prospecto","555167-0258",null,"2026-06-03","IB WHATSAPP","VIABLE",null,"ALEJANDRO",null,null,"FACTURA","21 M2 PANDA WHITE  BOOKMATCH",null,"EL CLIENTE SE LE OFRECE NERO ECLISSE Y SE COMPLETA LA VENTA","NERO ECLISSE",302000.0,"MXN",null],
    ["JORGE REYES",null,null,"prospecto","564139-5452",null,"2026-06-03","IB WHATSAPP","VIABLE",null,"ALEJANDRO","SEGUIMIENTO",null,"PROPUESTA","90 M VIA LACTEA, 1.20 X 60","9 JUN, NO A QUERIDO DAR SU NOMBRE, SE LE VA A COTIZAR, SEGUIMIENTO/ 19 JUN, SEG, NO HA RESPONDIDO","EN ESPERA DE MEDIDAS POR PARTE DEL PROVEEDOR","VIA LACTEA",241634.08,"MXN",null],
    ["CARLOS DIAZ",null,null,"prospecto","552491-3774",null,"2026-06-03","IB LLAMADA","VIABLE",null,"ALEJANDRO","PRECIO",null,"PROPUESTA","CUARCITA MIRASEMA 35 M 40 X40 O 30 X60,","9 JUN, ESPERA DE RESPUESTA DE SU CLIENTE/ 19 JUN, LO CONSIGUIERON EN OTRO LADO","SE LE MANDA EL PRESUPUESTO Y ESTAMOS EN ESPERA DE RESPUESTA","MIRACEMA",76302.0,"MXN",null],
    ["EVELYN JUAREZ",null,null,"prospecto","553783-1561",null,"2026-06-03","IB WHATSAPP","VIABLE","NV","ALEJANDRO","SIN RESPUESTA",null,"PROPUESTA","2 PLACAS DE SINTERIZADA MATE, COMO EN LA FOTO (YA HABIA SIDO ATENDIDA POR JENNIFER EN FEB)","9 JUN, NEMESIO JUAREZ, REVISANDO LA PROPUESTA DE ARGENTA","SE LE MANDA LA OPCION MAS CERCANA QUE REQUIERE EL CLIENTE Y ESTAMOS EN ESPERA DE RESPUESTA/ 19 JUN, NO HA RESPONDIDO","SINTERIZADA ARGENTA",27928.0,"MXN",null],
    ["MICHELL LEON",null,null,"prospecto","557760-7639",null,"2026-06-05","IB WHATSAPP","VIABLE","NV","ALEJANDRO","SIN RESPUESTA",null,"PROPUESTA","piedra volcánica, precio por m2 ,manda foto","9 JUN, PRECIO , PEND LA CANTIDAD DE METROS/ 19 JUN, SE LA HAN MANDADO LOS COSTOS, NO HA RESPONDIDO  NINGUN MENSAJE","SE LE MANDO EL COSTO COLOCADO EN BODEGA Y ESTAMOS EN ESPERA DE METRAJE","RECINTO IRREGULAR",530.0,"MXN",null],
    ["JUAN MANUEL CIMENTAL",null,null,"prospecto","5545922539",null,"2026-06-08","IB LLAMADA","VIABLE",null,"ALEJANDRO","SEGUIMIENTO",null,"PROPUESTA","40 PZAS DE 51X29 Y 20 PZAS. 50X80/ LE URGE TIEMPO DE ENTREGA,","9 JUN, EN ESPERA DE RESPUESTA, SEG/ 19 JUN, LO ESTÁ REVISANDO","SE LE MANDA EL CATALOGO DE PIEDRA SINTERIZADA Y SE LE MANDA LA PROPUESTA","SINTERIZADA NEGRO MARQUINA",53248.0,"MXN",null],
    ["LIZETH ANGELES",null,null,"prospecto","423-101-0274",null,"2026-06-02","IB LLAMADA","VIABLE",null,"SILVIA","SEGUIMIENTO",null,"PROPUESTA","1 PLACA BLANCO CARRARA, QUIERE UN FORMATO PARA UN ESCALON DE 2.30 E INSTALACION","9 JUN, ESTA SEMANA DECIDIA / 15 DE JUN SE ACTUALIZÓ LA COTIZACIÓN /19 JUN, SE LE VISITÓ Y SE LE VUELVE A HACER UN NUEVA PROPUESTA","COMENTA QUE EL PRESUPUESTO YA LO TIENEN SUS JEFES","CARRARA",31912.8,"MXN",null],
    ["ERICK ELORZA","CATARQ",null,"prospecto","552241-1265",null,"2026-06-03","IB WHATSAPP","VIABLE",null,"SILVIA","SEGUIMIENTO","DIC'26","PROPUESTA","120 M2 , OPCIONES PARA PISO MARMOL, RECINTO O CANTERA","9 JUN, SE LE DIO COTIZACIÓN, PERO MENCIONÓ QUE NO POR AHORA, APENAS ESTÁN BARDEANDO EL TERRENO/ SEG DIC'26","EN ESPERA DE COTIZACION POR PARTE DEL PROVEEDOR","RECINTO Y TRAVERTINO",103900.0,"MXN",null],
    ["NOEMI GODINEZ",null,null,"prospecto","558678-5032",null,"2026-06-08","IB LLAMADA","VIABLE","NV","SILVIA","SIN RESPUESTA",null,"PROPUESTA","1 PLACA MARMOL NACIONAL CAFÉ, ENVIA FOTOS,","9 JUN, EN REVISION, POSIBLE VEA LA PLACA/ 15 JUN TERCER CONTACTO Y NO CONTESTA/ 19 JUN, YA NO RESPONDE","SE LE MANDA COTIZACION CON PROPUESTA","EMPERADOR LIGHT",9547.92,"MXN",null],
    ["FERNANDO  HERNANDEZ",null,null,"prospecto","554574-6436",null,"2026-06-08","IB WHATSAPP","VIABLE","NV","SILVIA",null,null,null,"15 M2 PIEDRA GALARZA,  PARK ROYAL EN CANCÚN,","9 JUN, SIN RESPUESTA A LOS MENSAJES / 19 JUN, NV NI PORFAVOR!",null,"PIEDRA GALARZA",null,"MXN",null],
    ["OMAR ROJAS",null,null,"prospecto","443-369-3191",null,"2026-06-15","IB WHATSAPP","VIABLE",null,"SILVIA","SEGUIMIENTO",null,"PROPUESTA","QUIERE SABER EL COSTO DE LA PLACA DE STO TOMAS, NO ME DIJO CUANTOS NECESITA","15 JUN, SE ENVIÓ COTIZACIÓN Y FOTOS DEL MATERIAL/ PROPUESTA, EN SEG DEL SATO TOMAS",null,"SANTO TAMAS Y CALACATTA GOLD",286204.8,"MXN",null],
    ["FELIPE ISLAS",null,null,"prospecto","5510442677",null,"2026-06-15","IB LLAMADA","VIABLE","NV","SILVIA","SEGUIMIENTO",null,"PROPUESTA","CANTERA LAMINADA SIN MAS INFORMACIÓN","19 JUN, EN SEGUIMIENTO",null,"CANTERA BLANCA MEXICANA",12173.6,"MXN",null],
    ["JULIO CÉSAR LÓPEZ",null,null,"prospecto","556070-1753",null,"2026-06-16","IB WHATSAPP","VIABLE","NV","SILVIA","MATERIAL",null,"PROPUESTA","1 PLACA DE GRANITO SN GABRIEL CON MEDIDAS MÍNIMAS DE 2.10X1.50 X2 ESPESOR","17 JUN, NECESITA MEDIA PLACA. . NV",null,"NEGRO SAN GABRIEL",13247.42,"MXN",null],
    ["MARIO PEREZ",null,null,"prospecto","562072-7954",null,"2026-06-17","IB WHATSAPP","VIABLE",null,"SILVIA","SEGUIMIENTO",null,"PROPUESTA","4 PZAS DE RECINTO","19 JUN, PROPUESTA, EN SEG, PRECIO",null,"RECINTO NEGRO",24192.0,"MXN",null],
    ["MARGARITA RAMOS",null,null,"prospecto",null,null,"2026-06-17","IB WHATSAPP","VIABLE",null,"SILVIA","SEGUIMIENTO",null,"PROPUESTA","17 PLACAS, 8 PLACAS DE MARMOL VERDE SINTRA Y 9 MARMOL VERMONT BEIGE","19 JUN,EN ESPERA DEL ENVÍO, EN SEG",null,"VERDE SINTRA Y VERMONT BEIGE",203040.0,"MXN",null],
    ["VALERIA CORTES",null,null,"prospecto","553910-1947",null,"2026-05-15","IB WHATSAPP","VIABLE","NV","SILVIA","OTRO","2026-05-19","PROPUESTA","30m2, MARMOL SANTO TOMAS 40X10cm / 10 JUN Ya no tienen el proyecto","19 MAY,  MANDAR FOTO DEL MATERIAL Y LO ESTÁ REVISANDO / 10 JUN YA NO TIENEN EL PROYECTO, PERDIDO",null,"MARMOL SANTO TOMAS",29071.0,"MXN",null]
  ];
      for (const v of seed) {
        await env.DB.prepare(
          "INSERT INTO clientes (nombre,empresa,tipo,etapa,telefono,email,fecha_lead,origen,validacion,estatus_final,asesor,estatus_nota,fecha_contacto,propuesta_factura,notas_vero,notas_actualizacion,notas_seguimiento,material,propuesta_antes_iva,moneda,facturado) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
        ).bind(...v).run();
      }
    }
  } catch (e) {}

  try {
    await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v3_crm','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run();
  } catch (e) {}
  MIGRADO_V3 = true;
}

let MIGRADO_V4 = false;
async function migrarV4(env) {
  if (MIGRADO_V4) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v4_cortes'").first();
    if (f && f.valor === "ok") { MIGRADO_V4 = true; return; }
  } catch (e) { return; }
  try {
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS cortes (id INTEGER PRIMARY KEY AUTOINCREMENT, folio TEXT, producto_id INTEGER, cotizacion_id INTEGER, proyecto_id INTEGER, cliente_id INTEGER, empleado_id INTEGER, cantidad REAL, unidad TEXT DEFAULT 'm2', medidas TEXT, estado TEXT DEFAULT 'pendiente', descuenta_inventario INTEGER DEFAULT 0, movimiento_id INTEGER, notas TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME)"
    ).run();
  } catch (e) {}
  try {
    await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v4_cortes','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run();
  } catch (e) {}
  MIGRADO_V4 = true;
}


let MIGRADO_V6 = false;
async function migrarV6(env) {
  if (MIGRADO_V6) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v6_seguimiento'").first();
    if (f && f.valor === "ok") { MIGRADO_V6 = true; return; }
  } catch (e) { return; }
  const cols6 = [
    "ALTER TABLE clientes ADD COLUMN tipo_seguimiento TEXT"
  ];
  for (const sql of cols6) { try { await env.DB.prepare(sql).run(); } catch (e) {} }
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v6_seguimiento','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V6 = true;
}

let MIGRADO_V8 = false;
async function migrarV8(env) {
  if (MIGRADO_V8) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v8_archivos'").first();
    if (f && f.valor === "ok") { MIGRADO_V8 = true; return; }
  } catch (e) { return; }
  try {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS cliente_archivos (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER NOT NULL, url_r2 TEXT NOT NULL, nombre TEXT NOT NULL, categoria TEXT, content_type TEXT, tamano INTEGER, usuario_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME)").run();
    await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_cliente_archivos_cli ON cliente_archivos(cliente_id)").run();
  } catch (e) {}
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v8_archivos','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V8 = true;
}

let MIGRADO_V9 = false;
async function migrarV9(env) {
  if (MIGRADO_V9) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v9_fiscal'").first();
    if (f && f.valor === "ok") { MIGRADO_V9 = true; return; }
  } catch (e) { return; }
  try { await env.DB.prepare("ALTER TABLE clientes ADD COLUMN razon_social TEXT").run(); } catch (e) {}
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v9_fiscal','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V9 = true;
}

let MIGRADO_V10 = false;
async function migrarV10(env) {
  if (MIGRADO_V10) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v10_pagos'").first();
    if (f && f.valor === "ok") { MIGRADO_V10 = true; return; }
  } catch (e) { return; }
  try {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS cliente_pagos (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER NOT NULL, fecha TEXT NOT NULL, monto REAL NOT NULL, tipo TEXT, metodo TEXT, referencia TEXT, notas TEXT, usuario_id INTEGER, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, deleted_at DATETIME)").run();
    await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_cliente_pagos_cli ON cliente_pagos(cliente_id)").run();
  } catch (e) {}
  try { await env.DB.prepare("ALTER TABLE cotizaciones ADD COLUMN propuesta_final INTEGER DEFAULT 0").run(); } catch (e) {}
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v10_pagos','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V10 = true;
}

let MIGRADO_V11 = false;
async function migrarV11(env) {
  if (MIGRADO_V11) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v11_comprobantes'").first();
    if (f && f.valor === "ok") { MIGRADO_V11 = true; return; }
  } catch (e) { return; }
  try { await env.DB.prepare("ALTER TABLE cliente_pagos ADD COLUMN archivo_id INTEGER").run(); } catch (e) {}
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v11_comprobantes','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V11 = true;
}

let MIGRADO_V12 = false;
async function migrarV12(env) {
  if (MIGRADO_V12) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v12_cot_moneda'").first();
    if (f && f.valor === "ok") { MIGRADO_V12 = true; return; }
  } catch (e) { return; }
  try {
    const c = await env.DB.prepare("SELECT name FROM pragma_table_info('cotizaciones') WHERE name='moneda'").first();
    if (!c) await env.DB.prepare("ALTER TABLE cotizaciones ADD COLUMN moneda TEXT").run();
  } catch (e) {}
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v12_cot_moneda','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V12 = true;
}

let MIGRADO_V7 = false;
async function migrarV7(env) {
  if (MIGRADO_V7) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v7_cotizaciones'").first();
    if (f && f.valor === "ok") { MIGRADO_V7 = true; return; }
  } catch (e) { return; }
  const cols7 = [
    "ALTER TABLE cotizaciones ADD COLUMN entrega_direccion TEXT",
    "ALTER TABLE cotizaciones ADD COLUMN entrega_referencias TEXT",
    "ALTER TABLE cotizaciones ADD COLUMN entrega_telefono TEXT",
    "ALTER TABLE cotizaciones ADD COLUMN cond_pago TEXT",
    "ALTER TABLE cotizaciones ADD COLUMN cond_entrega TEXT",
    "ALTER TABLE cotizaciones ADD COLUMN cond_no_incluye TEXT"
  ];
  for (const sql of cols7) { try { await env.DB.prepare(sql).run(); } catch (e) {} }
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v7_cotizaciones','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V7 = true;
}

let MIGRADO_V5 = false;
async function migrarV5(env) {
  if (MIGRADO_V5) return;
  try {
    const f = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='schema_v5_ficha360'").first();
    if (f && f.valor === "ok") { MIGRADO_V5 = true; return; }
  } catch (e) { return; }
  // Campos nuevos de la MATRIZ CRM (idempotente: si ya existen, SQLite lanza y se ignora)
  const cols = [
    "ALTER TABLE clientes ADD COLUMN telefono_alt TEXT",
    "ALTER TABLE clientes ADD COLUMN sitio_web TEXT",
    "ALTER TABLE clientes ADD COLUMN industria TEXT",
    "ALTER TABLE clientes ADD COLUMN tipo_origen_lead TEXT",
    "ALTER TABLE clientes ADD COLUMN proximo_seguimiento TEXT",
    "ALTER TABLE clientes ADD COLUMN condiciones_pago TEXT",
    "ALTER TABLE clientes ADD COLUMN linea_credito REAL",
    "ALTER TABLE clientes ADD COLUMN saldo_actual REAL",
    "ALTER TABLE clientes ADD COLUMN riesgo_credito TEXT",
    "ALTER TABLE clientes ADD COLUMN probabilidad_cierre TEXT",
    "ALTER TABLE clientes ADD COLUMN fecha_cierre_estimada TEXT",
    "ALTER TABLE clientes ADD COLUMN proxima_accion TEXT",
    "ALTER TABLE clientes ADD COLUMN cumpleanos TEXT",
    "ALTER TABLE clientes ADD COLUMN referido_por TEXT"
  ];
  for (const sql of cols) { try { await env.DB.prepare(sql).run(); } catch (e) {} }
  // Tablas de apoyo de la ficha (autocurativo si la BD es previa al esquema completo)
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS notas_crm (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER NOT NULL, usuario_id INTEGER, nota TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").run(); } catch (e) {}
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS contactos_cliente (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER NOT NULL, nombre TEXT, cargo TEXT, telefono TEXT, email TEXT, whatsapp TEXT, preferencia_contacto TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").run(); } catch (e) {}
  try { await env.DB.prepare("CREATE INDEX IF NOT EXISTS idx_notas_crm_cli ON notas_crm(cliente_id)").run(); } catch (e) {}
  try { await env.DB.prepare("INSERT INTO app_config (clave,valor) VALUES ('schema_v5_ficha360','ok') ON CONFLICT(clave) DO UPDATE SET valor='ok'").run(); } catch (e) {}
  MIGRADO_V5 = true;
}

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

  // Geocerca por defecto (taller ASLAN, Benito Juárez CDMX) + check-in demo
  const gcN = await env.DB.prepare("SELECT COUNT(*) AS n FROM geofencing_config").first();
  if (!gcN || gcN.n === 0) {
    await env.DB.prepare("INSERT INTO geofencing_config (nombre,lat_centro,lon_centro,radio_metros,activo) VALUES (?,?,?,?,1)")
      .bind("Taller ASLAN — Luis Carracci 50", 19.37241, -99.16830, 150).run();
  }
  const empU = await env.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind("empleado@aslan.com").first();
  if (empU) {
    await env.DB.prepare("INSERT OR IGNORE INTO empleados_perfil (usuario_id,consentimiento_gps) VALUES (?,1)").bind(empU.id).run();
    const ckN = await env.DB.prepare("SELECT COUNT(*) AS n FROM gps_checkins WHERE usuario_id=?").bind(empU.id).first();
    if (!ckN || ckN.n === 0) {
      await env.DB.prepare("INSERT INTO gps_checkins (usuario_id,tipo,lat,lon,precision_metros) VALUES (?,?,?,?,?)").bind(empU.id, "entrada", 19.37250, -99.16840, 12).run();
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
async function dashboardStats(env, payload) {
  const _sc = asesorScope(payload);
  const _ab = _sc ? [_sc.first, _sc.full] : [];
  const cliCond = _sc ? " AND UPPER(TRIM(IFNULL(asesor,''))) IN (?,?)" : "";
  const subCli = _sc ? " AND cliente_id IN (SELECT id FROM clientes WHERE deleted_at IS NULL AND UPPER(TRIM(IFNULL(asesor,''))) IN (?,?))" : "";
  const q = async (sql, b) => (await env.DB.prepare(sql).bind(...(b || [])).first()).n;
  const clientes = await q("SELECT COUNT(*) AS n FROM clientes WHERE deleted_at IS NULL" + cliCond, _ab);
  const cotizMes = await q("SELECT COUNT(*) AS n FROM cotizaciones WHERE deleted_at IS NULL AND created_at >= date('now','start of month')" + subCli, _ab);
  const proyectos = await q("SELECT COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL AND estado NOT IN ('cerrado','entregado')" + subCli, _ab);
  const stockCritico = await q("SELECT COUNT(*) AS n FROM productos WHERE deleted_at IS NULL AND stock_actual <= stock_minimo");
  const empleadosHoy = await q("SELECT COUNT(DISTINCT usuario_id) AS n FROM gps_checkins WHERE tipo='entrada' AND created_at >= date('now')");
  const pipeline = (await env.DB.prepare("SELECT COALESCE(SUM(total),0) AS n FROM cotizaciones WHERE estado IN ('enviada','borrador','aceptada') AND deleted_at IS NULL" + subCli).bind(..._ab).first()).n;
  const porCategoria = await env.DB.prepare("SELECT categoria, COUNT(*) AS n FROM productos WHERE deleted_at IS NULL GROUP BY categoria").all();
  const recientes = await env.DB.prepare(
    "SELECT c.folio, c.total, c.estado, cl.nombre AS cliente FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id WHERE c.deleted_at IS NULL" + (_sc ? " AND c.cliente_id IN (SELECT id FROM clientes WHERE deleted_at IS NULL AND UPPER(TRIM(IFNULL(asesor,''))) IN (?,?))" : "") + " ORDER BY c.created_at DESC LIMIT 10"
  ).bind(..._ab).all();
  return ok({
    kpis: { clientes, cotizMes, proyectos, stockCritico, empleadosHoy, pipeline },
    porCategoria: porCategoria.results || [],
    recientes: recientes.results || [],
  });
}

async function dashboardCharts(env, payload) {
  const _sc = asesorScope(payload);
  const _ab = _sc ? [_sc.first, _sc.full] : [];
  const cliCond = _sc ? " AND UPPER(TRIM(IFNULL(asesor,''))) IN (?,?)" : "";
  const subCli = _sc ? " AND cliente_id IN (SELECT id FROM clientes WHERE deleted_at IS NULL AND UPPER(TRIM(IFNULL(asesor,''))) IN (?,?))" : "";
  const cotiz = await env.DB.prepare(
    "SELECT strftime('%Y-%m', created_at) AS mes, COUNT(*) AS n, COALESCE(SUM(total),0) AS monto" +
    " FROM cotizaciones WHERE deleted_at IS NULL AND created_at >= date('now','-6 months')" + subCli + " GROUP BY mes ORDER BY mes ASC"
  ).bind(..._ab).all();
  const proyEtapa = await env.DB.prepare(
    "SELECT etapa_portal AS etapa, COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL" + subCli + " GROUP BY etapa_portal"
  ).bind(..._ab).all();
  const nombreEtapa = {};
  for (const e of ETAPAS) nombreEtapa[e.clave] = e.nombre;
  const proyectos_por_etapa = (proyEtapa.results || []).map((r) => ({ etapa: r.etapa, nombre: nombreEtapa[r.etapa] || r.etapa, n: r.n }));
  const cliEtapa = await env.DB.prepare(
    "SELECT COALESCE(etapa,'sin etapa') AS etapa, COUNT(*) AS n FROM clientes WHERE deleted_at IS NULL" + cliCond + " GROUP BY etapa ORDER BY n DESC"
  ).bind(..._ab).all();
  const invCat = await env.DB.prepare(
    "SELECT COALESCE(categoria,'Otros') AS categoria, COALESCE(SUM(stock_actual*precio_venta),0) AS valor, COUNT(*) AS n" +
    " FROM productos WHERE deleted_at IS NULL GROUP BY categoria ORDER BY valor DESC"
  ).all();
  const asistencia = await env.DB.prepare(
    "SELECT date(created_at) AS dia, COUNT(*) AS n FROM gps_checkins WHERE tipo='entrada' AND created_at >= date('now','-7 days') GROUP BY dia ORDER BY dia ASC"
  ).all();
  return ok({
    cotiz_por_mes: cotiz.results || [],
    proyectos_por_etapa,
    clientes_por_etapa: cliEtapa.results || [],
    inventario_por_categoria: invCat.results || [],
    asistencia_7d: asistencia.results || [],
  });
}

// ============================================================================
//  API — CLIENTES (CRM)
// ============================================================================
// Alcance de asesor: admin/gerente ven todo (null). Empleado solo ve SUS leads
// (match por el campo de texto "asesor" contra su nombre/primer nombre).
function asesorScope(payload) {
  if (!payload || payload.rol !== "empleado") return null;
  var full = (payload.nombre || "").trim();
  var first = full.split(/\s+/)[0] || "";
  return { full: full.toUpperCase(), first: first.toUpperCase() };
}
// Restringe a la cartera del asesor por su columna cliente_id. Vacio si admin/gerente.
function scopeClienteSQL(payload, col) {
  const s = asesorScope(payload);
  if (!s) return { cond: "", bind: [] };
  return { cond: " AND " + col + " IN (SELECT id FROM clientes WHERE deleted_at IS NULL AND UPPER(TRIM(IFNULL(asesor,''))) IN (?,?))", bind: [s.first, s.full] };
}
async function handleClientes(request, env, payload, method, id) {
  if (method === "GET" && !id) {
    const _sc = asesorScope(payload);
    let _wh = "WHERE c.deleted_at IS NULL";
    const _bind = [];
    if (_sc) { _wh += " AND UPPER(TRIM(IFNULL(c.asesor,''))) IN (?,?)"; _bind.push(_sc.first, _sc.full); }
    const r = await env.DB.prepare(
      "SELECT c.*, u.nombre AS empleado_nombre, (SELECT COUNT(*) FROM cotizaciones q WHERE q.cliente_id=c.id AND q.deleted_at IS NULL) AS num_cotizaciones FROM clientes c LEFT JOIN usuarios u ON u.id=c.empleado_asignado_id " + _wh + " ORDER BY c.id DESC"
    ).bind(..._bind).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const c = await env.DB.prepare("SELECT * FROM clientes WHERE id=? AND deleted_at IS NULL").bind(id).first();
    if (!c) return fail("Cliente no encontrado.", 404);
    const _sc = asesorScope(payload);
    if (_sc) { var _a = (c.asesor || "").trim().toUpperCase(); if (_a !== _sc.first && _a !== _sc.full) return fail("Sin acceso a este lead.", 403); }
    return ok(c);
  }
  if (method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.nombre) return fail("El nombre es obligatorio.");
    if (payload && payload.rol === "empleado") b.asesor = (payload.nombre || "").trim().split(/\s+/)[0];
    if (!b.force) {
      const dcond = [], dbind = [];
      const dnom = (b.nombre || "").trim();
      if (dnom) { dcond.push("LOWER(TRIM(nombre)) = LOWER(?)"); dbind.push(dnom); }
      const dtel = (b.telefono || "").toString().replace(/[^0-9]/g, "");
      if (dtel) { dcond.push("REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(IFNULL(telefono,''),' ',''),'-',''),'(',''),')',''),'+',''),'.','') = ?"); dbind.push(dtel); }
      const dem = (b.email || "").trim();
      if (dem) { dcond.push("LOWER(TRIM(email)) = LOWER(?)"); dbind.push(dem); }
      if (dcond.length) {
        const _scd = scopeClienteSQL(payload, "id");
        const dup = await env.DB.prepare("SELECT id,nombre,empresa,telefono,email,asesor FROM clientes WHERE deleted_at IS NULL" + _scd.cond + " AND (" + dcond.join(" OR ") + ") LIMIT 10").bind(..._scd.bind, ...dbind).all();
        if ((dup.results || []).length) return ok({ duplicado: true, existentes: dup.results });
      }
    }
    const res = await env.DB.prepare(
      "INSERT INTO clientes (nombre,empresa,tipo,etapa,telefono,email,ciudad,direccion,rfc,notas,empleado_asignado_id,fecha_lead,origen,validacion,estatus_final,asesor,estatus_nota,fecha_contacto,propuesta_factura,notas_vero,notas_actualizacion,notas_seguimiento,material,acabado,formato,cantidad,propuesta_antes_iva,moneda,facturado) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(b.nombre, b.empresa || null, b.tipo || null, b.etapa || "prospecto", b.telefono || null,
           b.email || null, b.ciudad || null, b.direccion || null, b.rfc || null, b.notas || null,
           b.empleado_asignado_id || null,
           b.fecha_lead || null, b.origen || null, b.validacion || null, b.estatus_final || null,
           b.asesor || null, b.estatus_nota || null, b.fecha_contacto || null, b.propuesta_factura || null,
           b.notas_vero || null, b.notas_actualizacion || null, b.notas_seguimiento || null,
           b.material || null, b.acabado || null, b.formato || null, b.cantidad || null, (b.propuesta_antes_iva==null?null:b.propuesta_antes_iva), b.moneda || null,
           (b.facturado==null?null:b.facturado)).run();
    await audit(env, payload.sub, "crear", "clientes", res.meta.last_row_id, b, request);
    return ok({ id: res.meta.last_row_id });
  }
  if (method === "PUT" && id) {
    const b = await request.json().catch(() => ({}));
    const campos = ["nombre", "empresa", "tipo", "etapa", "telefono", "email", "ciudad", "direccion", "rfc", "razon_social", "notas", "empleado_asignado_id", "fecha_lead", "origen", "validacion", "estatus_final", "asesor", "estatus_nota", "fecha_contacto", "propuesta_factura", "notas_vero", "notas_actualizacion", "notas_seguimiento", "material", "acabado", "formato", "cantidad", "propuesta_inicial", "propuesta_antes_iva", "moneda", "facturado", "telefono_alt", "sitio_web", "industria", "tipo_origen_lead", "proximo_seguimiento", "tipo_seguimiento", "condiciones_pago", "linea_credito", "saldo_actual", "riesgo_credito", "probabilidad_cierre", "fecha_cierre_estimada", "proxima_accion", "cumpleanos", "referido_por"];
    const sets = [], vals = [];
    for (const c of campos) if (c in b) { sets.push(c + "=?"); vals.push(b[c]); }
    for (const c of Object.keys(b)) if (RX_COL.test(c) && !campos.includes(c)) { sets.push(c + "=?"); vals.push(b[c]); }
    if (!sets.length) return fail("Nada que actualizar.");
    const stampProp = ("propuesta_antes_iva" in b) ? ", propuesta_updated_at=CURRENT_TIMESTAMP" : "";
    vals.push(id);
    await env.DB.prepare("UPDATE clientes SET " + sets.join(",") + stampProp + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...vals).run();
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
// ============================================================================
//  FICHA 360° — concentra TODO de un prospecto/cliente en una sola consulta
//  Datos + contacto + historial(notas) + cotizaciones + proyectos + trazabilidad
// ============================================================================
async function fichaCliente(env, id, payload) {
  const c = await env.DB.prepare(
    "SELECT cl.*, u.nombre AS empleado_nombre FROM clientes cl LEFT JOIN usuarios u ON u.id=cl.empleado_asignado_id WHERE cl.id=? AND cl.deleted_at IS NULL"
  ).bind(id).first();
  if (!c) return fail("Cliente no encontrado.", 404);
  const _sc = asesorScope(payload);
  if (_sc) { var _a = (c.asesor || "").trim().toUpperCase(); if (_a !== _sc.first && _a !== _sc.full) return fail("Sin acceso a este lead.", 403); }

  let contactos = { results: [] }, notas = { results: [] }, cortes = { results: [] };
  try { contactos = await env.DB.prepare("SELECT * FROM contactos_cliente WHERE cliente_id=? ORDER BY id DESC").bind(id).all(); } catch (e) {}
  try { notas = await env.DB.prepare("SELECT n.*, u.nombre AS usuario FROM notas_crm n LEFT JOIN usuarios u ON u.id=n.usuario_id WHERE n.cliente_id=? ORDER BY n.created_at DESC, n.id DESC").bind(id).all(); } catch (e) {}

  const cotis = await env.DB.prepare(
    "SELECT c.id, c.folio, c.estado, c.subtotal, c.total, c.propuesta_final, c.created_at, u.nombre AS vendedor," +
    " (SELECT p.folio FROM proyectos p WHERE p.cotizacion_id=c.id AND p.deleted_at IS NULL LIMIT 1) AS proyecto_folio" +
    " FROM cotizaciones c LEFT JOIN usuarios u ON u.id=c.usuario_id" +
    " WHERE c.cliente_id=? AND c.deleted_at IS NULL ORDER BY c.created_at DESC, c.id DESC"
  ).bind(id).all();

  const proyectos = await env.DB.prepare(
    "SELECT id, folio, descripcion, estado, etapa_portal, avance_pct, m2_totales, fecha_entrega_estimada" +
    " FROM proyectos WHERE cliente_id=? AND deleted_at IS NULL ORDER BY id DESC"
  ).bind(id).all();

  try {
    cortes = await env.DB.prepare(
      "SELECT c.id, c.folio, c.cantidad, c.unidad, c.medidas, c.estado," +
      " p.nombre AS material, p.sku AS material_sku," +
      " co.folio AS cotizacion_folio, pr.folio AS proyecto_folio, ue.nombre AS cortador" +
      " FROM cortes c" +
      " LEFT JOIN productos p ON p.id=c.producto_id" +
      " LEFT JOIN cotizaciones co ON co.id=c.cotizacion_id" +
      " LEFT JOIN proyectos pr ON pr.id=c.proyecto_id" +
      " LEFT JOIN usuarios ue ON ue.id=c.empleado_id" +
      " WHERE c.cliente_id=? AND c.deleted_at IS NULL ORDER BY c.id DESC"
    ).bind(id).all();
  } catch (e) {}

  let catAses = [], catFin = [];
  try {
    const ra = (await env.DB.prepare("SELECT DISTINCT TRIM(asesor) AS v FROM clientes WHERE deleted_at IS NULL AND asesor IS NOT NULL AND TRIM(asesor)<>'' ORDER BY v COLLATE NOCASE").all()).results || [];
    catAses = ra.map((x) => x.v);
  } catch (e) {}
  try {
    const rf = (await env.DB.prepare("SELECT DISTINCT TRIM(estatus_final) AS v FROM clientes WHERE deleted_at IS NULL AND estatus_final IS NOT NULL AND TRIM(estatus_final)<>'' ORDER BY v COLLATE NOCASE").all()).results || [];
    catFin = rf.map((x) => x.v).filter((x) => x.length <= 25);
  } catch (e) {}

  let cobranza = { pagos: [], total_pagado: 0, base: 0, base_origen: "sin_base", saldo: 0, moneda: "MXN" };
  try { cobranza = await pagosResumen(env, id); } catch (e) {}

  const rc = cotis.results || [];
  const totalCotizado = rc.reduce((s, q) => s + (Number(q.total) || 0), 0);
  const totalAceptado = rc.filter((q) => q.estado === "aceptada").reduce((s, q) => s + (Number(q.total) || 0), 0);
  const m2 = (cortes.results || []).reduce((s, x) => s + (Number(x.cantidad) || 0), 0);

  return ok({
    cliente: c,
    catalogos: { asesores: catAses, finales: catFin },
    pagos: cobranza.pagos,
    cobranza: cobranza,
    contactos: contactos.results || [],
    notas: notas.results || [],
    cotizaciones: rc,
    proyectos: proyectos.results || [],
    cortes: cortes.results || [],
    resumen: {
      num_cotizaciones: rc.length,
      total_cotizado: +totalCotizado.toFixed(2),
      total_aceptado: +totalAceptado.toFixed(2),
      facturado: Number(c.facturado) || 0,
      total_pagado: cobranza.total_pagado,
      saldo: cobranza.pagos.length ? cobranza.saldo : (Number(c.saldo_actual) || 0),
      m2_cortados: +m2.toFixed(2)
    }
  });
}

// Agregar una entrada a la bitácora (historial de interacciones) del cliente
async function agregarNotaCliente(request, env, payload, id) {
  const b = await request.json().catch(() => ({}));
  const nota = (b.nota || "").trim();
  if (!nota) return fail("La nota está vacía.");
  const cli = await env.DB.prepare("SELECT id FROM clientes WHERE id=? AND deleted_at IS NULL").bind(id).first();
  if (!cli) return fail("Cliente no encontrado.", 404);
  try { await env.DB.prepare("CREATE TABLE IF NOT EXISTS notas_crm (id INTEGER PRIMARY KEY AUTOINCREMENT, cliente_id INTEGER NOT NULL, usuario_id INTEGER, nota TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)").run(); } catch (e) {}
  const res = await env.DB.prepare("INSERT INTO notas_crm (cliente_id,usuario_id,nota) VALUES (?,?,?)").bind(id, payload.sub, nota).run();
  await audit(env, payload.sub, "nota", "clientes", id, { nota }, request);
  return ok({ id: res.meta.last_row_id });
}

// Moneda de la cotizacion: solo MXN o USD
function monedaCot(v) { return (String(v || "").trim().toUpperCase() === "USD") ? "USD" : "MXN"; }

// Historial (bitacora) de todos los leads visibles para el usuario: se usa al exportar el CRM
async function historialClientes(env, payload) {
  const _sch = scopeClienteSQL(payload, "n.cliente_id");
  let rows = [];
  try {
    const r = await env.DB.prepare("SELECT n.cliente_id, n.nota, n.created_at, u.nombre AS usuario FROM notas_crm n LEFT JOIN usuarios u ON u.id=n.usuario_id WHERE 1=1" + _sch.cond + " ORDER BY n.cliente_id ASC, n.created_at ASC, n.id ASC").bind(..._sch.bind).all();
    rows = r.results || [];
  } catch (e) { rows = []; }
  return ok(rows);
}

// Detecta posibles duplicados (telefono, correo o nombre) y los agrupa
async function duplicadosClientes(env, payload) {
  const _scq = scopeClienteSQL(payload, "id");
  const r = await env.DB.prepare("SELECT id,nombre,empresa,telefono,email,asesor FROM clientes WHERE deleted_at IS NULL" + _scq.cond).bind(..._scq.bind).all();
  const rows = r.results || [];
  const norm = (s) => (s == null ? "" : String(s)).toLowerCase().trim().replace(/\s+/g, " ");
  const dig = (s) => (s == null ? "" : String(s)).replace(/[^0-9]/g, "");
  function agrupar(keyFn, tipo) {
    const map = {};
    for (const x of rows) { const k = keyFn(x); if (!k) continue; (map[k] = map[k] || []).push(x); }
    return Object.keys(map).filter((k) => map[k].length > 1).map((k) => ({ tipo, clave: k, miembros: map[k] }));
  }
  const grupos = [].concat(
    agrupar((x) => dig(x.telefono), "Teléfono"),
    agrupar((x) => norm(x.email), "Correo"),
    agrupar((x) => norm(x.nombre), "Nombre")
  );
  return ok({ grupos, total: grupos.length });
}

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
    let sql = "SELECT c.*, cl.nombre AS cliente, u.nombre AS vendedor, (SELECT p.folio FROM proyectos p WHERE p.cotizacion_id=c.id AND p.deleted_at IS NULL LIMIT 1) AS proyecto_folio FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id LEFT JOIN usuarios u ON u.id=c.usuario_id WHERE c.deleted_at IS NULL";
    const binds = [];
    const _scc = scopeClienteSQL(payload, "c.cliente_id");
    sql += _scc.cond; if (_scc.bind.length) binds.push(..._scc.bind);
    if (clienteFiltro) { sql += " AND c.cliente_id=?"; binds.push(clienteFiltro); }
    sql += " ORDER BY c.created_at DESC, c.id DESC";
    const r = await env.DB.prepare(sql).bind(...binds).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const c = await env.DB.prepare(
      "SELECT c.*, cl.nombre AS cliente, cl.empresa AS cliente_empresa, cl.rfc AS cliente_rfc, cl.razon_social AS cliente_razon, cl.direccion AS cliente_direccion, cl.telefono AS cliente_telefono, cl.asesor AS _asesor, u.nombre AS vendedor, u.email AS vendedor_email, u.telefono AS vendedor_telefono FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id LEFT JOIN usuarios u ON u.id=c.usuario_id WHERE c.id=? AND c.deleted_at IS NULL"
    ).bind(id).first();
    if (!c) return fail("Cotización no encontrada.", 404);
    const _scv = asesorScope(payload);
    if (_scv) { var _av = (c._asesor || "").trim().toUpperCase(); if (_av !== _scv.first && _av !== _scv.full) return fail("Sin acceso a esta cotización.", 403); }
    delete c._asesor;
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
      "INSERT INTO cotizaciones (folio,cliente_id,usuario_id,estado,subtotal,descuento_global_pct,iva_pct,total,vigencia_dias,notas,condiciones,entrega_direccion,entrega_referencias,entrega_telefono,cond_pago,cond_entrega,cond_no_incluye,moneda) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(folio, b.cliente_id, payload.sub, b.estado || "borrador", subtotal,
           Number(b.descuento_global_pct) || 0, ivaPct, total, Number(b.vigencia_dias) || 7,
           b.notas || null, b.condiciones || null,
           b.entrega_direccion || null, b.entrega_referencias || null, b.entrega_telefono || null,
           b.cond_pago || null, b.cond_entrega || null, b.cond_no_incluye || null, monedaCot(b.moneda)).run();
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
    const cot = await env.DB.prepare("SELECT c.id, c.usuario_id, c.cliente_id, cl.asesor AS _asesor FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id WHERE c.id=? AND c.deleted_at IS NULL").bind(id).first();
    if (!cot) return fail("Cotización no encontrada.", 404);
    const _scp = asesorScope(payload);
    if (_scp) { const _ap = (cot._asesor || "").trim().toUpperCase(); if (_ap !== _scp.first && _ap !== _scp.full) return fail("Sin acceso a esta cotización.", 403); }
    // Marcar / desmarcar la cotizacion como parte de la propuesta final
    if ("propuesta_final" in b && Object.keys(b).length === 1) {
      const pf = (b.propuesta_final === 1 || b.propuesta_final === true || b.propuesta_final === "1") ? 1 : 0;
      await env.DB.prepare("UPDATE cotizaciones SET propuesta_final=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(pf, id).run();
      // La suma s/IVA de las cotizaciones marcadas se copia sola a PROP. S/IVA del CRM.
      // Si no queda ninguna marcada NO se borra el monto capturado a mano.
      let propNueva = null, marcadas = 0;
      if (cot.cliente_id) {
        try {
          const sm = await env.DB.prepare("SELECT COUNT(*) AS n, IFNULL(SUM(subtotal),0) AS s FROM cotizaciones WHERE cliente_id=? AND propuesta_final=1 AND deleted_at IS NULL").bind(cot.cliente_id).first();
          marcadas = Number((sm && sm.n) || 0);
          if (marcadas > 0) {
            propNueva = +Number((sm && sm.s) || 0).toFixed(2);
            await env.DB.prepare("UPDATE clientes SET propuesta_antes_iva=?, propuesta_updated_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(propNueva, cot.cliente_id).run();
            const np = await env.DB.prepare("SELECT COUNT(*) AS n FROM cliente_pagos WHERE cliente_id=? AND deleted_at IS NULL").bind(cot.cliente_id).first();
            if (np && Number(np.n) > 0) await sincronizarSaldo(env, cot.cliente_id);
          }
        } catch (e) {}
      }
      await audit(env, payload.sub, "propuesta_final", "cotizaciones", id, { propuesta_final: pf, marcadas, propuesta_antes_iva: propNueva }, request);
      return ok({ id, propuesta_final: pf, marcadas, propuesta_antes_iva: propNueva });
    }
    // Cambio de estado simple
    if (b.estado && Object.keys(b).length === 1) {
      const validos = ["borrador", "enviada", "aceptada", "rechazada", "expirada"];
      if (!validos.includes(b.estado)) return fail("Estado inválido.");
      await env.DB.prepare("UPDATE cotizaciones SET estado=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(b.estado, id).run();
      await audit(env, payload.sub, "estado", "cotizaciones", id, { estado: b.estado }, request);
      return ok({ id, estado: b.estado });
    }
    // Edición completa: encabezado + reemplazo de líneas
    const items = Array.isArray(b.items) ? b.items.filter((it) => it && (it.descripcion || it.producto_id)) : [];
    if (!items.length) return fail("Agrega al menos una línea de producto.");
    const ivaPct2 = b.iva_pct !== undefined ? Number(b.iva_pct) : 16;
    const { lineas, subtotal, total } = calcularTotales(items, b.descuento_global_pct, ivaPct2);
    await env.DB.prepare(
      "UPDATE cotizaciones SET cliente_id=COALESCE(?,cliente_id), subtotal=?, descuento_global_pct=?, iva_pct=?, total=?, vigencia_dias=?, notas=?, condiciones=?, entrega_direccion=?, entrega_referencias=?, entrega_telefono=?, cond_pago=?, cond_entrega=?, cond_no_incluye=?, moneda=?, updated_at=CURRENT_TIMESTAMP WHERE id=?"
    ).bind(b.cliente_id || null, subtotal, Number(b.descuento_global_pct) || 0, ivaPct2, total,
           Number(b.vigencia_dias) || 7, b.notas || null, b.condiciones || null,
           b.entrega_direccion || null, b.entrega_referencias || null, b.entrega_telefono || null,
           b.cond_pago || null, b.cond_entrega || null, b.cond_no_incluye || null, monedaCot(b.moneda), id).run();
    await env.DB.prepare("DELETE FROM cotizacion_items WHERE cotizacion_id=?").bind(id).run();
    for (const ln of lineas) {
      await env.DB.prepare(
        "INSERT INTO cotizacion_items (cotizacion_id,producto_id,descripcion,cantidad,unidad,precio_unitario,descuento_linea_pct,subtotal_linea) VALUES (?,?,?,?,?,?,?,?)"
      ).bind(id, ln.producto_id || null, ln.descripcion || "", Number(ln.cantidad) || 0,
             ln.unidad || "m2", Number(ln.precio_unitario) || 0, Number(ln.descuento_linea_pct) || 0, ln.subtotal_linea).run();
    }
    await audit(env, payload.sub, "editar", "cotizaciones", id, { subtotal, total }, request);
    return ok({ id, subtotal, total });
  }
  if (method === "DELETE" && id) {
    const cotDel = await env.DB.prepare("SELECT id, usuario_id, folio FROM cotizaciones WHERE id=? AND deleted_at IS NULL").bind(id).first();
    if (!cotDel) return fail("Cotización no encontrada.", 404);
    const propia = Number(cotDel.usuario_id) === Number(payload.sub);
    if (!hasRole(payload, "admin", "gerente") && !propia) return fail("Solo puedes eliminar tus propias cotizaciones.", 403);
    await env.DB.prepare("UPDATE cotizaciones SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    await audit(env, payload.sub, "eliminar", "cotizaciones", id, { folio: cotDel.folio }, request);
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

// ============================================================================
//  CORTES — eslabón físico de la trazabilidad
//  Inventario(material) → Corte → Cotización → Cliente → Asesor/Cortador
// ============================================================================
async function handleCortes(request, env, payload, method, id, url) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
  const SEL = "SELECT c.*, p.nombre AS material, p.sku AS material_sku, p.unidad AS material_unidad, p.stock_actual AS material_stock," +
    " co.folio AS cotizacion_folio, pr.folio AS proyecto_folio," +
    " cl.nombre AS cliente, cl.empresa AS cliente_empresa, cl.asesor AS asesor," +
    " ue.nombre AS cortador" +
    " FROM cortes c" +
    " LEFT JOIN productos p ON p.id=c.producto_id" +
    " LEFT JOIN cotizaciones co ON co.id=c.cotizacion_id" +
    " LEFT JOIN proyectos pr ON pr.id=c.proyecto_id" +
    " LEFT JOIN clientes cl ON cl.id=c.cliente_id" +
    " LEFT JOIN usuarios ue ON ue.id=c.empleado_id";

  if (method === "GET" && id) {
    const r = await env.DB.prepare(SEL + " WHERE c.id=? AND c.deleted_at IS NULL").bind(id).first();
    if (!r) return fail("Corte no encontrado.", 404);
    return ok(r);
  }
  if (method === "GET") {
    let sql = SEL + " WHERE c.deleted_at IS NULL";
    const b = [];
    const fc = url && url.searchParams.get("cotizacion");
    const fp = url && url.searchParams.get("producto");
    const fcl = url && url.searchParams.get("cliente");
    if (fc) { sql += " AND c.cotizacion_id=?"; b.push(fc); }
    if (fp) { sql += " AND c.producto_id=?"; b.push(fp); }
    if (fcl) { sql += " AND c.cliente_id=?"; b.push(fcl); }
    sql += " ORDER BY c.id DESC";
    const r = await env.DB.prepare(sql).bind(...b).all();
    return ok(r.results || []);
  }
  if (method === "POST") {
    const b = await request.json().catch(() => ({}));
    if (!b.producto_id) return fail("Selecciona el material de inventario.");
    const cant = Number(b.cantidad) || 0;
    // Derivar el cliente desde la cotización o el proyecto (trazabilidad automática)
    let clienteId = b.cliente_id || null;
    if (!clienteId && b.cotizacion_id) {
      const co = await env.DB.prepare("SELECT cliente_id FROM cotizaciones WHERE id=?").bind(b.cotizacion_id).first();
      if (co) clienteId = co.cliente_id;
    }
    if (!clienteId && b.proyecto_id) {
      const pr = await env.DB.prepare("SELECT cliente_id FROM proyectos WHERE id=?").bind(b.proyecto_id).first();
      if (pr) clienteId = pr.cliente_id;
    }
    const folio = await siguienteFolio(env, "CORTE", "cortes");
    // Descuento opcional de inventario (genera salida y enlaza el movimiento)
    let movId = null;
    if (b.descuenta_inventario && cant > 0) {
      const prod = await env.DB.prepare("SELECT * FROM productos WHERE id=? AND deleted_at IS NULL").bind(b.producto_id).first();
      if (prod) {
        const nuevo = (Number(prod.stock_actual) || 0) - cant;
        await env.DB.prepare("UPDATE productos SET stock_actual=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(nuevo, b.producto_id).run();
        const mv = await env.DB.prepare(
          "INSERT INTO movimientos_inventario (producto_id,tipo,cantidad,referencia,motivo,usuario_id,notas) VALUES (?,?,?,?,?,?,?)"
        ).bind(b.producto_id, "salida", cant, folio, "Corte " + folio, b.empleado_id || payload.sub, b.medidas || null).run();
        movId = mv.meta ? mv.meta.last_row_id : null;
      }
    }
    const res = await env.DB.prepare(
      "INSERT INTO cortes (folio,producto_id,cotizacion_id,proyecto_id,cliente_id,empleado_id,cantidad,unidad,medidas,estado,descuenta_inventario,movimiento_id,notas) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(folio, b.producto_id, b.cotizacion_id || null, b.proyecto_id || null, clienteId, b.empleado_id || null,
           cant, b.unidad || "m2", b.medidas || null, b.estado || "pendiente",
           b.descuenta_inventario ? 1 : 0, movId, b.notas || null).run();
    await audit(env, payload.sub, "crear", "cortes", res.meta.last_row_id, { folio }, request);
    return ok({ id: res.meta.last_row_id, folio });
  }
  if (method === "PUT" && id) {
    const b = await request.json().catch(() => ({}));
    const campos = ["producto_id", "cotizacion_id", "proyecto_id", "cliente_id", "empleado_id", "cantidad", "unidad", "medidas", "estado", "notas"];
    const sets = [], vals = [];
    for (const k of campos) { if (k in b) { sets.push(k + "=?"); vals.push(b[k]); } }
    if (!sets.length) return fail("Nada que actualizar.");
    vals.push(id);
    await env.DB.prepare("UPDATE cortes SET " + sets.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...vals).run();
    await audit(env, payload.sub, "editar", "cortes", id, b, request);
    return ok({ id });
  }
  if (method === "DELETE" && id) {
    await env.DB.prepare("UPDATE cortes SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    await audit(env, payload.sub, "eliminar", "cortes", id, {}, request);
    return ok({ id });
  }
  return fail("Método no permitido.", 405);
}

async function trazabilidadGlobal(env, url) {
  if (url && url.searchParams.get("scope")) { /* reservado para filtros futuros */ }
  const r = await env.DB.prepare(
    "SELECT c.id, c.folio, c.cantidad, c.unidad, c.medidas, c.estado, c.descuenta_inventario," +
    " p.id AS producto_id, p.nombre AS material, p.sku AS material_sku," +
    " co.id AS cotizacion_id, co.folio AS cotizacion_folio, co.total AS cotizacion_total," +
    " pr.folio AS proyecto_folio," +
    " cl.id AS cliente_id, cl.nombre AS cliente, cl.empresa AS cliente_empresa, cl.asesor AS asesor," +
    " ue.nombre AS cortador" +
    " FROM cortes c" +
    " LEFT JOIN productos p ON p.id=c.producto_id" +
    " LEFT JOIN cotizaciones co ON co.id=c.cotizacion_id" +
    " LEFT JOIN proyectos pr ON pr.id=c.proyecto_id" +
    " LEFT JOIN clientes cl ON cl.id=c.cliente_id" +
    " LEFT JOIN usuarios ue ON ue.id=c.empleado_id" +
    " WHERE c.deleted_at IS NULL ORDER BY c.id DESC"
  ).all();
  const tot = await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(cantidad),0) AS m2 FROM cortes WHERE deleted_at IS NULL").first();
  const sinLink = await env.DB.prepare("SELECT COUNT(*) AS n FROM cortes WHERE deleted_at IS NULL AND cotizacion_id IS NULL").first();
  return ok({ cadena: r.results || [], metricas: { cortes: (tot && tot.n) || 0, m2: (tot && tot.m2) || 0, sin_cotizacion: (sinLink && sinLink.n) || 0 } });
}
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
    const _scp = scopeClienteSQL(payload, "p.cliente_id");
    const r = await env.DB.prepare(
      "SELECT p.*, cl.nombre AS cliente FROM proyectos p LEFT JOIN clientes cl ON cl.id=p.cliente_id WHERE p.deleted_at IS NULL" + _scp.cond + " ORDER BY p.updated_at DESC"
    ).bind(..._scp.bind).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const p = await env.DB.prepare(
      "SELECT p.*, cl.nombre AS cliente, cl.asesor AS _asesor FROM proyectos p LEFT JOIN clientes cl ON cl.id=p.cliente_id WHERE p.id=? AND p.deleted_at IS NULL"
    ).bind(id).first();
    if (!p) return fail("Proyecto no encontrado.", 404);
    const _scp2 = asesorScope(payload);
    if (_scp2) { var _ap = (p._asesor || "").trim().toUpperCase(); if (_ap !== _scp2.first && _ap !== _scp2.full) return fail("Sin acceso a este proyecto.", 403); }
    delete p._asesor;
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
  const secretFc = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  const fcli = await env.DB.prepare("SELECT id,etapa,descripcion,created_at FROM proyecto_fotos WHERE proyecto_id=? ORDER BY created_at DESC, id DESC").bind(id).all();
  const fotos_proyecto = [];
  for (const f of (fcli.results || [])) fotos_proyecto.push({ id: f.id, etapa: f.etapa, descripcion: f.descripcion, created_at: f.created_at, url: await fotoUrl(f.id, secretFc) });
  return ok({
    proyecto: p, etapas: ETAPAS, historial: historial.results || [],
    fotos: fotos.results || [], losas: losas.results || [], mensajes: mensajes.results || [],
    fotos_proyecto,
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
    const secretF = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
    const fr = await env.DB.prepare("SELECT id,etapa,descripcion,created_at FROM proyecto_fotos WHERE proyecto_id=? ORDER BY created_at DESC, id DESC").bind(id).all();
    const fotos = [];
    for (const f of (fr.results || [])) fotos.push({ id: f.id, etapa: f.etapa, descripcion: f.descripcion, created_at: f.created_at, url: await fotoUrl(f.id, secretF) });
    return ok({
      proyecto: proy, etapas: ETAPAS, cliente, acceso,
      losas: losas.results || [], mensajes: mensajes.results || [], historial: historial.results || [], fotos,
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
// ============================================================================
//  EMPLEADOS · CHECK-IN GPS · GEOCERCA
// ============================================================================
function distanciaMetros(lat1, lon1, lat2, lon2) {
  const R = 6371000, toRad = (d) => (d * Math.PI) / 180;
  const dLat = toRad(lat2 - lat1), dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2 + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return Math.round(2 * R * Math.asin(Math.sqrt(a)));
}
function passwordTemporal() {
  const cs = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const a = crypto.getRandomValues(new Uint8Array(8));
  let s = "";
  for (const x of a) s += cs[x % cs.length];
  return "Aslan-" + s;
}
async function geocercaActiva(env) {
  return await env.DB.prepare("SELECT * FROM geofencing_config ORDER BY activo DESC, id ASC LIMIT 1").first();
}

async function handleEmpleados(request, env, payload, method, id) {
  if (method === "GET" && !id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
    const r = await env.DB.prepare(
      "SELECT u.id,u.nombre,u.email,u.rol,u.cargo,u.area,u.telefono,u.activo,ep.consentimiento_gps," +
      " (SELECT g.created_at FROM gps_checkins g WHERE g.usuario_id=u.id ORDER BY g.created_at DESC, g.id DESC LIMIT 1) AS ultimo_checkin," +
      " (SELECT g.tipo FROM gps_checkins g WHERE g.usuario_id=u.id ORDER BY g.created_at DESC, g.id DESC LIMIT 1) AS ultimo_tipo" +
      " FROM usuarios u LEFT JOIN empleados_perfil ep ON ep.usuario_id=u.id" +
      " WHERE u.rol IN ('empleado','gerente','admin') AND u.deleted_at IS NULL" +
      " ORDER BY u.nombre, u.id"
    ).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
    const e = await env.DB.prepare(
      "SELECT u.id,u.nombre,u.email,u.rol,u.cargo,u.area,u.telefono,u.activo,u.ultimo_acceso," +
      " ep.curp,ep.rfc,ep.fecha_nacimiento,ep.fecha_ingreso,ep.salario,ep.tipo_contrato,ep.consentimiento_gps" +
      " FROM usuarios u LEFT JOIN empleados_perfil ep ON ep.usuario_id=u.id WHERE u.id=? AND u.deleted_at IS NULL"
    ).bind(id).first();
    if (!e) return fail("Empleado no encontrado.", 404);
    const ch = await env.DB.prepare(
      "SELECT id,tipo,lat,lon,precision_metros,created_at FROM gps_checkins WHERE usuario_id=? ORDER BY created_at DESC, id DESC LIMIT 30"
    ).bind(id).all();
    return ok({ empleado: e, checkins: ch.results || [] });
  }
  if (method === "POST") {
    if (!hasRole(payload, "admin")) return fail("Solo admin da de alta empleados.", 403);
    const b = await request.json().catch(() => ({}));
    if (!b.nombre || !b.email) return fail("Nombre y correo son obligatorios.");
    const existe = await env.DB.prepare("SELECT id, deleted_at FROM usuarios WHERE email=?").bind(b.email).first();
    if (existe && !existe.deleted_at) return fail("Ya existe un usuario con ese correo.");
    const rol = (b.rol === "gerente" || b.rol === "empleado") ? b.rol : "empleado";
    const pw = passwordTemporal();
    const ph = await hashPassword(pw);
    if (existe && existe.deleted_at) {
      const uid = existe.id;
      await env.DB.prepare(
        "UPDATE usuarios SET nombre=?, password_hash=?, rol=?, cargo=?, area=?, telefono=?, activo=1, password_debe_cambiar=1, deleted_at=NULL, updated_at=CURRENT_TIMESTAMP WHERE id=?"
      ).bind(b.nombre, ph, rol, b.cargo || null, b.area || null, b.telefono || null, uid).run();
      await env.DB.prepare("INSERT OR IGNORE INTO empleados_perfil (usuario_id) VALUES (?)").bind(uid).run();
      await env.DB.prepare(
        "UPDATE empleados_perfil SET curp=?, rfc=?, fecha_ingreso=?, salario=?, tipo_contrato=?, consentimiento_gps=?, updated_at=CURRENT_TIMESTAMP WHERE usuario_id=?"
      ).bind(b.curp || null, b.rfc || null, b.fecha_ingreso || null, (b.salario != null && b.salario !== "") ? Number(b.salario) : null, b.tipo_contrato || null, b.consentimiento_gps ? 1 : 0, uid).run();
      await audit(env, payload.sub, "reactivar", "empleados", uid, { email: b.email, rol }, request);
      return ok({ id: uid, email: b.email, password_temporal: pw, reactivado: true });
    }
    const res = await env.DB.prepare(
      "INSERT INTO usuarios (nombre,email,password_hash,rol,cargo,area,telefono,password_debe_cambiar) VALUES (?,?,?,?,?,?,?,1)"
    ).bind(b.nombre, b.email, ph, rol, b.cargo || null, b.area || null, b.telefono || null).run();
    const uid = res.meta.last_row_id;
    await env.DB.prepare(
      "INSERT INTO empleados_perfil (usuario_id,curp,rfc,fecha_ingreso,salario,tipo_contrato,consentimiento_gps) VALUES (?,?,?,?,?,?,?)"
    ).bind(uid, b.curp || null, b.rfc || null, b.fecha_ingreso || null, (b.salario != null && b.salario !== "") ? Number(b.salario) : null, b.tipo_contrato || null, b.consentimiento_gps ? 1 : 0).run();
    await audit(env, payload.sub, "crear", "empleados", uid, { email: b.email, rol }, request);
    return ok({ id: uid, email: b.email, password_temporal: pw });
  }
  if (method === "PUT" && id) {
    if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
    const b = await request.json().catch(() => ({}));
    const camposU = ["nombre", "cargo", "area", "telefono", "activo", "rol"];
    const setsU = [], valsU = [];
    for (const c of camposU) if (c in b) { setsU.push(c + "=?"); valsU.push(c === "activo" ? (b[c] ? 1 : 0) : b[c]); }
    if (setsU.length) { valsU.push(id); await env.DB.prepare("UPDATE usuarios SET " + setsU.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(...valsU).run(); }
    const camposP = ["curp", "rfc", "fecha_nacimiento", "fecha_ingreso", "salario", "tipo_contrato", "consentimiento_gps"];
    const setsP = [], valsP = [];
    for (const c of camposP) if (c in b) { setsP.push(c + "=?"); valsP.push(c === "consentimiento_gps" ? (b[c] ? 1 : 0) : (c === "salario" ? (Number(b[c]) || 0) : b[c])); }
    if (setsP.length) {
      await env.DB.prepare("INSERT OR IGNORE INTO empleados_perfil (usuario_id) VALUES (?)").bind(id).run();
      valsP.push(id);
      await env.DB.prepare("UPDATE empleados_perfil SET " + setsP.join(",") + ", updated_at=CURRENT_TIMESTAMP WHERE usuario_id=?").bind(...valsP).run();
    }
    if (!setsU.length && !setsP.length) return fail("Nada que actualizar.");
    await audit(env, payload.sub, "editar", "empleados", id, b, request);
    return ok({ id });
  }
  if (method === "DELETE" && id) {
    if (!hasRole(payload, "admin")) return fail("Solo admin.", 403);
    if (String(payload.sub) === String(id)) return fail("No puedes desactivar tu propia cuenta.");
    await env.DB.prepare("UPDATE usuarios SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
    await audit(env, payload.sub, "eliminar", "empleados", id, null, request);
    return ok({ id });
  }
  return fail("Método no soportado.", 405);
}

async function registrarCheckin(request, env, payload) {
  const b = await request.json().catch(() => ({}));
  const tipo = (b.tipo === "salida") ? "salida" : "entrada";
  const lat = Number(b.lat), lon = Number(b.lon);
  if (!isFinite(lat) || !isFinite(lon)) return fail("Ubicación inválida.");
  const prec = (b.precision != null && isFinite(Number(b.precision))) ? Number(b.precision) : null;
  const res = await env.DB.prepare(
    "INSERT INTO gps_checkins (usuario_id,tipo,lat,lon,precision_metros) VALUES (?,?,?,?,?)"
  ).bind(payload.sub, tipo, lat, lon, prec).run();
  let dentro = null, distancia = null, geo = null;
  const g = await geocercaActiva(env);
  if (g) {
    distancia = distanciaMetros(lat, lon, g.lat_centro, g.lon_centro);
    dentro = distancia <= g.radio_metros;
    geo = { nombre: g.nombre, radio: g.radio_metros };
    if (!dentro) {
      await env.DB.prepare("INSERT INTO geofencing_alertas (usuario_id,lat,lon,distancia_metros) VALUES (?,?,?,?)").bind(payload.sub, lat, lon, distancia).run();
    }
  }
  await audit(env, payload.sub, tipo, "gps_checkins", res.meta.last_row_id, { lat, lon, dentro }, request);
  return ok({ id: res.meta.last_row_id, tipo, dentro, distancia, geocerca: geo });
}

async function checkinEstado(env, payload) {
  const u = await env.DB.prepare("SELECT tipo,created_at FROM gps_checkins WHERE usuario_id=? ORDER BY created_at DESC, id DESC LIMIT 1").bind(payload.sub).first();
  const g = await geocercaActiva(env);
  return ok({
    ultimo_tipo: u ? u.tipo : null,
    ultimo_checkin: u ? u.created_at : null,
    geocerca: g ? { nombre: g.nombre, lat: g.lat_centro, lon: g.lon_centro, radio: g.radio_metros } : null
  });
}

async function checkinsRecientes(env, payload) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
  const r = await env.DB.prepare(
    "SELECT g.id,g.usuario_id,g.tipo,g.lat,g.lon,g.precision_metros,g.created_at,u.nombre" +
    " FROM gps_checkins g LEFT JOIN usuarios u ON u.id=g.usuario_id" +
    " ORDER BY g.created_at DESC, g.id DESC LIMIT 100"
  ).all();
  return ok(r.results || []);
}

async function handleGeofencing(request, env, payload, method) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
  if (method === "GET") {
    const g = await geocercaActiva(env);
    return ok(g || null);
  }
  if (method === "POST") {
    const b = await request.json().catch(() => ({}));
    const lat = Number(b.lat_centro), lon = Number(b.lon_centro), radio = Number(b.radio_metros);
    if (!isFinite(lat) || !isFinite(lon) || !isFinite(radio) || radio <= 0) return fail("Datos de geocerca inválidos.");
    const ex = await env.DB.prepare("SELECT id FROM geofencing_config ORDER BY id ASC LIMIT 1").first();
    if (ex) {
      await env.DB.prepare("UPDATE geofencing_config SET nombre=?, lat_centro=?, lon_centro=?, radio_metros=?, activo=1, updated_at=CURRENT_TIMESTAMP WHERE id=?")
        .bind(b.nombre || "Sitio ASLAN", lat, lon, radio, ex.id).run();
      await audit(env, payload.sub, "editar", "geofencing", ex.id, { radio }, request);
      return ok({ id: ex.id });
    }
    const res = await env.DB.prepare("INSERT INTO geofencing_config (nombre,lat_centro,lon_centro,radio_metros,activo) VALUES (?,?,?,?,1)")
      .bind(b.nombre || "Sitio ASLAN", lat, lon, radio).run();
    await audit(env, payload.sub, "crear", "geofencing", res.meta.last_row_id, { radio }, request);
    return ok({ id: res.meta.last_row_id });
  }
  return fail("Método no soportado.", 405);
}

async function alertasGeofencing(env, payload) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
  const r = await env.DB.prepare(
    "SELECT a.id,a.usuario_id,a.lat,a.lon,a.distancia_metros,a.revisada,a.created_at,u.nombre" +
    " FROM geofencing_alertas a LEFT JOIN usuarios u ON u.id=a.usuario_id" +
    " ORDER BY a.revisada ASC, a.created_at DESC, a.id DESC LIMIT 50"
  ).all();
  return ok(r.results || []);
}

async function revisarAlerta(request, env, payload, id) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo admin o gerente.", 403);
  await env.DB.prepare("UPDATE geofencing_alertas SET revisada=1 WHERE id=?").bind(id).run();
  return ok({ id });
}

// ============================================================================
//  FOTOS DE PROYECTO POR ETAPA  (R2: binding FILES)
// ============================================================================
async function fotoUrl(fotoId, secret) {
  const tk = await createJWT({ t: "foto", fid: fotoId }, secret, 12);
  return "/media/foto/" + fotoId + "?k=" + tk;
}
async function listarFotosProyecto(env, payload, proyectoId) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
  const r = await env.DB.prepare("SELECT id,etapa,descripcion,created_at FROM proyecto_fotos WHERE proyecto_id=? ORDER BY created_at DESC, id DESC").bind(proyectoId).all();
  const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  const out = [];
  for (const f of (r.results || [])) out.push({ id: f.id, etapa: f.etapa, descripcion: f.descripcion, created_at: f.created_at, url: await fotoUrl(f.id, secret) });
  return ok(out);
}
async function subirFotoProyecto(request, env, payload, proyectoId) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
  if (!env.FILES) return fail("Almacenamiento de fotos no configurado (falta el binding R2 'FILES').", 500);
  const proy = await env.DB.prepare("SELECT id FROM proyectos WHERE id=? AND deleted_at IS NULL").bind(proyectoId).first();
  if (!proy) return fail("Proyecto no encontrado.", 404);
  const b = await request.json().catch(() => ({}));
  if (!b.data) return fail("Falta la imagen.");
  let b64 = String(b.data), ct = b.contentType || "image/jpeg";
  const m = /^data:([^;]+);base64,(.*)$/s.exec(b64);
  if (m) { ct = m[1]; b64 = m[2]; }
  let bytes;
  try { bytes = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0)); } catch (e) { return fail("Imagen inválida."); }
  if (bytes.length > 8 * 1024 * 1024) return fail("La imagen supera 8 MB.");
  const ext = ct.includes("png") ? "png" : (ct.includes("webp") ? "webp" : "jpg");
  const key = "proyectos/" + proyectoId + "/" + (b.etapa || "general") + "/" + crypto.randomUUID() + "." + ext;
  await env.FILES.put(key, bytes, { httpMetadata: { contentType: ct } });
  const res = await env.DB.prepare("INSERT INTO proyecto_fotos (proyecto_id,url_r2,etapa,descripcion) VALUES (?,?,?,?)").bind(proyectoId, key, b.etapa || null, b.descripcion || null).run();
  await audit(env, payload.sub, "subir_foto", "proyecto_fotos", res.meta.last_row_id, { etapa: b.etapa || null }, request);
  return ok({ id: res.meta.last_row_id });
}
async function borrarFotoProyecto(request, env, payload, proyectoId, fotoId) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Sin permiso.", 403);
  const f = await env.DB.prepare("SELECT url_r2 FROM proyecto_fotos WHERE id=? AND proyecto_id=?").bind(fotoId, proyectoId).first();
  if (!f) return fail("Foto no encontrada.", 404);
  if (env.FILES && f.url_r2) { try { await env.FILES.delete(f.url_r2); } catch (e) { /* noop */ } }
  await env.DB.prepare("DELETE FROM proyecto_fotos WHERE id=?").bind(fotoId).run();
  await audit(env, payload.sub, "borrar_foto", "proyecto_fotos", fotoId, null, request);
  return ok({ id: fotoId });
}
// ============================================================================
//  ARCHIVOS Y DOCUMENTOS POR LEAD / CLIENTE  (R2: binding FILES)
//  Comprobantes de pago, fotos del cliente, material compartido, etc.
// ============================================================================
const ARCH_CATEGORIAS = ["Comprobante de pago", "Foto del cliente", "Material compartido", "Cotizacion", "Contrato", "Otro"];
async function clienteAccesible(env, payload, clienteId) {
  const c = await env.DB.prepare("SELECT id, asesor FROM clientes WHERE id=? AND deleted_at IS NULL").bind(clienteId).first();
  if (!c) return null;
  const _sc = asesorScope(payload);
  if (_sc) { const _a = (c.asesor || "").trim().toUpperCase(); if (_a !== _sc.first && _a !== _sc.full) return null; }
  return c;
}
async function archivoUrl(archivoId, secret) {
  const tk = await createJWT({ t: "archivo", aid: archivoId }, secret, 12);
  return "/media/archivo/" + archivoId + "?k=" + tk;
}
async function listarArchivosCliente(env, payload, clienteId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const r = await env.DB.prepare("SELECT a.id,a.nombre,a.categoria,a.content_type,a.tamano,a.usuario_id,a.created_at,u.nombre AS usuario FROM cliente_archivos a LEFT JOIN usuarios u ON u.id=a.usuario_id WHERE a.cliente_id=? AND a.deleted_at IS NULL ORDER BY a.created_at DESC, a.id DESC").bind(clienteId).all();
  const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  const out = [];
  for (const f of (r.results || [])) out.push({ id: f.id, nombre: f.nombre, categoria: f.categoria, content_type: f.content_type, tamano: f.tamano, usuario: f.usuario, usuario_id: f.usuario_id, created_at: f.created_at, url: await archivoUrl(f.id, secret) });
  return ok(out);
}
async function subirArchivoCliente(request, env, payload, clienteId) {
  if (!env.FILES) return fail("Almacenamiento de archivos no configurado (falta el binding R2 'FILES').", 500);
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const b = await request.json().catch(() => ({}));
  if (!b.data) return fail("Falta el archivo.");
  let b64 = String(b.data), ct = b.contentType || "application/octet-stream";
  const m = /^data:([^;]+);base64,(.*)$/s.exec(b64);
  if (m) { ct = m[1]; b64 = m[2]; }
  let bytes;
  try { bytes = Uint8Array.from(atob(b64), (ch) => ch.charCodeAt(0)); } catch (e) { return fail("Archivo inválido."); }
  if (!bytes.length) return fail("El archivo está vacío.");
  if (bytes.length > 10 * 1024 * 1024) return fail("El archivo supera 10 MB.");
  let nombre = String(b.nombre || "archivo").replace(/[\\/:*?"<>|]+/g, "_").slice(0, 160);
  const extM = /\.([A-Za-z0-9]{1,8})$/.exec(nombre);
  const ext = extM ? extM[1].toLowerCase() : "bin";
  const categoria = ARCH_CATEGORIAS.includes(b.categoria) ? b.categoria : "Otro";
  const key = "clientes/" + clienteId + "/" + crypto.randomUUID() + "." + ext;
  await env.FILES.put(key, bytes, { httpMetadata: { contentType: ct } });
  const res = await env.DB.prepare("INSERT INTO cliente_archivos (cliente_id,url_r2,nombre,categoria,content_type,tamano,usuario_id) VALUES (?,?,?,?,?,?,?)").bind(clienteId, key, nombre, categoria, ct, bytes.length, payload.sub).run();
  await audit(env, payload.sub, "subir_archivo", "cliente_archivos", res.meta.last_row_id, { cliente_id: clienteId, nombre, categoria }, request);
  return ok({ id: res.meta.last_row_id });
}
async function borrarArchivoCliente(request, env, payload, clienteId, archivoId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const f = await env.DB.prepare("SELECT id, usuario_id FROM cliente_archivos WHERE id=? AND cliente_id=? AND deleted_at IS NULL").bind(archivoId, clienteId).first();
  if (!f) return fail("Archivo no encontrado.", 404);
  if (!hasRole(payload, "admin", "gerente") && String(f.usuario_id) !== String(payload.sub)) return fail("Solo quien subió el archivo, gerencia o administración pueden eliminarlo.", 403);
  // Baja logica: el objeto permanece en R2 y el registro conserva su historial.
  await env.DB.prepare("UPDATE cliente_archivos SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(archivoId).run();
  await audit(env, payload.sub, "borrar_archivo", "cliente_archivos", archivoId, { cliente_id: clienteId }, request);
  return ok({ id: archivoId });
}
// ============================================================================
//  PAGOS DEL CLIENTE - historico de abonos con fecha (el cliente paga en partes)
// ============================================================================
const PAGO_TIPOS = ["Anticipo", "Pago parcial", "Liquidacion", "Reembolso", "Ajuste"];
const PAGO_METODOS = ["Transferencia", "Efectivo", "Cheque", "Tarjeta", "Deposito", "Otro"];
// Monto de referencia contra el que se mide la cobranza: lo facturado y, si no
// hay factura todavia, la propuesta comercial vigente.
function baseCobranza(c) {
  const fact = Number(c && c.facturado) || 0;
  if (fact > 0) return { base: fact, origen: "facturado" };
  const prop = Number(c && c.propuesta_antes_iva) || 0;
  return { base: prop, origen: prop > 0 ? "propuesta" : "sin_base" };
}
async function pagosResumen(env, clienteId) {
  const c = await env.DB.prepare("SELECT id, facturado, propuesta_antes_iva, saldo_actual, moneda FROM clientes WHERE id=?").bind(clienteId).first();
  let pagos = [];
  try {
    const r = await env.DB.prepare("SELECT p.id,p.fecha,p.monto,p.tipo,p.metodo,p.referencia,p.notas,p.usuario_id,p.archivo_id,p.created_at,u.nombre AS usuario,a.nombre AS archivo_nombre FROM cliente_pagos p LEFT JOIN usuarios u ON u.id=p.usuario_id LEFT JOIN cliente_archivos a ON a.id=p.archivo_id AND a.deleted_at IS NULL WHERE p.cliente_id=? AND p.deleted_at IS NULL ORDER BY p.fecha DESC, p.id DESC").bind(clienteId).all();
    pagos = r.results || [];
    const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
    for (const p of pagos) {
      if (p.archivo_id && p.archivo_nombre) { try { p.archivo_url = await archivoUrl(p.archivo_id, secret); } catch (e) {} }
    }
  } catch (e) {}
  const pagado = pagos.reduce((t, p) => t + (Number(p.monto) || 0), 0);
  const bc = baseCobranza(c || {});
  return {
    pagos: pagos,
    total_pagado: +pagado.toFixed(2),
    base: +bc.base.toFixed(2),
    base_origen: bc.origen,
    saldo: +(bc.base - pagado).toFixed(2),
    moneda: (c && c.moneda) || "MXN"
  };
}
// Deja clientes.saldo_actual alineado con el historico de pagos.
async function sincronizarSaldo(env, clienteId) {
  const res = await pagosResumen(env, clienteId);
  try { await env.DB.prepare("UPDATE clientes SET saldo_actual=?, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(res.saldo, clienteId).run(); } catch (e) {}
  return res;
}
async function listarPagosCliente(env, payload, clienteId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  return ok(await pagosResumen(env, clienteId));
}
// Valida que el comprobante exista y sea de ESTE cliente antes de ligarlo al pago.
async function archivoDelCliente(env, clienteId, archivoId) {
  if (!archivoId) return null;
  try {
    const a = await env.DB.prepare("SELECT id FROM cliente_archivos WHERE id=? AND cliente_id=? AND deleted_at IS NULL").bind(archivoId, clienteId).first();
    return a ? a.id : null;
  } catch (e) { return null; }
}
async function ligarComprobantePago(request, env, payload, clienteId, pagoId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const p = await env.DB.prepare("SELECT id FROM cliente_pagos WHERE id=? AND cliente_id=? AND deleted_at IS NULL").bind(pagoId, clienteId).first();
  if (!p) return fail("Pago no encontrado.", 404);
  const b = await request.json().catch(() => ({}));
  const archivoId = await archivoDelCliente(env, clienteId, b.archivo_id);
  if (!archivoId) return fail("El comprobante no es valido para este cliente.");
  await env.DB.prepare("UPDATE cliente_pagos SET archivo_id=? WHERE id=?").bind(archivoId, pagoId).run();
  await audit(env, payload.sub, "comprobante_pago", "cliente_pagos", pagoId, { cliente_id: clienteId, archivo_id: archivoId }, request);
  return ok({ id: pagoId, resumen: await pagosResumen(env, clienteId) });
}
async function agregarPagoCliente(request, env, payload, clienteId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const b = await request.json().catch(() => ({}));
  const monto = Number(b.monto);
  if (!isFinite(monto) || monto === 0) return fail("Captura el monto del pago.");
  const fecha = String(b.fecha || "").trim().slice(0, 10);
  if (!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(fecha)) return fail("La fecha del pago no es valida.");
  const tipo = PAGO_TIPOS.includes(b.tipo) ? b.tipo : "Pago parcial";
  const metodo = PAGO_METODOS.includes(b.metodo) ? b.metodo : "Transferencia";
  const referencia = String(b.referencia || "").trim().slice(0, 120) || null;
  const notas = String(b.notas || "").trim().slice(0, 400) || null;
  const archivoId = await archivoDelCliente(env, clienteId, b.archivo_id);
  const res = await env.DB.prepare("INSERT INTO cliente_pagos (cliente_id,fecha,monto,tipo,metodo,referencia,notas,usuario_id,archivo_id) VALUES (?,?,?,?,?,?,?,?,?)")
    .bind(clienteId, fecha, +monto.toFixed(2), tipo, metodo, referencia, notas, payload.sub, archivoId).run();
  const resumen = await sincronizarSaldo(env, clienteId);
  await audit(env, payload.sub, "pago", "cliente_pagos", res.meta.last_row_id, { cliente_id: clienteId, fecha, monto, tipo, metodo }, request);
  return ok({ id: res.meta.last_row_id, resumen });
}
async function borrarPagoCliente(request, env, payload, clienteId, pagoId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const p = await env.DB.prepare("SELECT id, usuario_id FROM cliente_pagos WHERE id=? AND cliente_id=? AND deleted_at IS NULL").bind(pagoId, clienteId).first();
  if (!p) return fail("Pago no encontrado.", 404);
  if (!hasRole(payload, "admin", "gerente") && String(p.usuario_id) !== String(payload.sub)) return fail("Solo quien registro el pago, gerencia o administracion pueden eliminarlo.", 403);
  await env.DB.prepare("UPDATE cliente_pagos SET deleted_at=CURRENT_TIMESTAMP WHERE id=?").bind(pagoId).run();
  const resumen = await sincronizarSaldo(env, clienteId);
  await audit(env, payload.sub, "borrar_pago", "cliente_pagos", pagoId, { cliente_id: clienteId }, request);
  return ok({ id: pagoId, resumen });
}
async function recalcularSaldoCliente(env, payload, clienteId) {
  const c = await clienteAccesible(env, payload, clienteId);
  if (!c) return fail("Sin acceso a este lead.", 403);
  const resumen = await sincronizarSaldo(env, clienteId);
  return ok({ resumen });
}
async function serveArchivo(request, env, path, url) {
  const m = /^\/media\/archivo\/(\d+)$/.exec(path);
  if (!m) return new Response("No encontrado", { status: 404 });
  const id = m[1];
  const k = url.searchParams.get("k");
  const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  const pl = k ? await verifyJWT(k, secret) : null;
  if (!pl || pl.t !== "archivo" || String(pl.aid) !== String(id)) return new Response("No autorizado", { status: 401 });
  const f = await env.DB.prepare("SELECT url_r2, nombre, content_type FROM cliente_archivos WHERE id=? AND deleted_at IS NULL").bind(id).first();
  if (!f || !f.url_r2) return new Response("No encontrado", { status: 404 });
  if (!env.FILES) return new Response("Almacenamiento no configurado", { status: 500 });
  const obj = await env.FILES.get(f.url_r2);
  if (!obj) return new Response("No encontrado", { status: 404 });
  const headers = new Headers();
  const ct = (obj.httpMetadata && obj.httpMetadata.contentType) || f.content_type || "application/octet-stream";
  headers.set("content-type", ct);
  const inline = /^(image\/|application\/pdf|text\/)/.test(ct);
  headers.set("content-disposition", (inline ? "inline" : "attachment") + "; filename=\"" + encodeURIComponent(f.nombre || "archivo") + "\"");
  headers.set("cache-control", "private, max-age=3600");
  return new Response(obj.body, { headers });
}

async function serveFoto(request, env, path, url) {
  const m = /^\/media\/foto\/(\d+)$/.exec(path);
  if (!m) return new Response("No encontrado", { status: 404 });
  const id = m[1];
  const k = url.searchParams.get("k");
  const secret = env.JWT_SECRET || "DEV_INSECURE_SECRET_CHANGE_ME";
  const pl = k ? await verifyJWT(k, secret) : null;
  if (!pl || pl.t !== "foto" || String(pl.fid) !== String(id)) return new Response("No autorizado", { status: 401 });
  const f = await env.DB.prepare("SELECT url_r2 FROM proyecto_fotos WHERE id=?").bind(id).first();
  if (!f || !f.url_r2) return new Response("No encontrado", { status: 404 });
  if (!env.FILES) return new Response("Almacenamiento no configurado", { status: 500 });
  const obj = await env.FILES.get(f.url_r2);
  if (!obj) return new Response("No encontrado", { status: 404 });
  const headers = new Headers();
  headers.set("content-type", (obj.httpMetadata && obj.httpMetadata.contentType) || "image/jpeg");
  headers.set("cache-control", "private, max-age=3600");
  return new Response(obj.body, { headers });
}

// ============================================================================
//  WHATSAPP  (Meta WhatsApp Cloud API · webhook + bandeja + envío)
//  Variables del Worker: WA_TOKEN, WA_PHONE_ID, WA_VERIFY_TOKEN
// ============================================================================
async function waUpsertConversacion(env, numero, nombre) {
  const c = await env.DB.prepare("SELECT id FROM wa_conversaciones WHERE numero_wa=?").bind(numero).first();
  if (c) return c.id;
  let clienteId = null;
  try {
    const cl = await env.DB.prepare("SELECT id FROM clientes WHERE telefono=? AND deleted_at IS NULL LIMIT 1").bind(numero).first();
    if (cl) clienteId = cl.id;
  } catch (e) { /* noop */ }
  const res = await env.DB.prepare("INSERT INTO wa_conversaciones (numero_wa,cliente_id,ultimo_mensaje_en,no_leidos) VALUES (?,?,CURRENT_TIMESTAMP,0)").bind(numero, clienteId).run();
  return res.meta.last_row_id;
}
async function whatsappWebhook(request, env, url) {
  if (request.method === "GET") {
    const mode = url.searchParams.get("hub.mode");
    const token = url.searchParams.get("hub.verify_token");
    const challenge = url.searchParams.get("hub.challenge");
    const verify = env.WA_VERIFY_TOKEN || "aslan-verify";
    if (mode === "subscribe" && token === verify) return new Response(challenge || "", { status: 200, headers: { "content-type": "text/plain" } });
    return new Response("Forbidden", { status: 403 });
  }
  if (request.method === "POST") {
    let body = {};
    try { body = await request.json(); } catch (e) { return new Response("EVENT_RECEIVED", { status: 200 }); }
    try {
      for (const en of (body.entry || [])) {
        for (const ch of (en.changes || [])) {
          const value = ch.value || {};
          const contactos = value.contacts || [];
          const nombre = (contactos[0] && contactos[0].profile && contactos[0].profile.name) || null;
          for (const msg of (value.messages || [])) {
            const numero = msg.from;
            if (!numero) continue;
            const convId = await waUpsertConversacion(env, numero, nombre);
            const tipo = msg.type || "text";
            const contenido = (tipo === "text") ? ((msg.text && msg.text.body) || "") : ("[" + tipo + "]");
            await env.DB.prepare("INSERT INTO wa_mensajes (conversacion_id,direction,tipo,contenido,wa_message_id,leido) VALUES (?,?,?,?,?,0)").bind(convId, "in", tipo, contenido, msg.id || null).run();
            await env.DB.prepare("UPDATE wa_conversaciones SET ultimo_mensaje_en=CURRENT_TIMESTAMP, no_leidos=no_leidos+1, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(convId).run();
          }
        }
      }
    } catch (e) { /* Meta siempre espera 200 */ }
    return new Response("EVENT_RECEIVED", { status: 200 });
  }
  return new Response("Método no soportado", { status: 405 });
}
async function waEnviarMeta(env, telefono, texto) {
  const token = env.WA_TOKEN, phoneId = env.WA_PHONE_ID;
  if (!token || !phoneId) return { ok: false, motivo: "no_config" };
  try {
    const r = await fetch("https://graph.facebook.com/v21.0/" + phoneId + "/messages", {
      method: "POST",
      headers: { "Authorization": "Bearer " + token, "Content-Type": "application/json" },
      body: JSON.stringify({ messaging_product: "whatsapp", to: telefono, type: "text", text: { body: texto } }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok && d.messages && d.messages[0]) return { ok: true, wamid: d.messages[0].id };
    return { ok: false, motivo: "meta_error" };
  } catch (e) { return { ok: false, motivo: "fetch_error" }; }
}
async function waEstado(env, payload) {
  return ok({ configurado: !!(env.WA_TOKEN && env.WA_PHONE_ID), verify_token: !!env.WA_VERIFY_TOKEN });
}
async function waListarConversaciones(env, payload) {
  const _scw = scopeClienteSQL(payload, "w.cliente_id");
  const r = await env.DB.prepare(
    "SELECT w.id,w.numero_wa,w.no_leidos,w.ultimo_mensaje_en,cl.nombre AS cliente," +
    " (SELECT m.contenido FROM wa_mensajes m WHERE m.conversacion_id=w.id ORDER BY m.created_at DESC, m.id DESC LIMIT 1) AS ultimo," +
    " (SELECT m.direction FROM wa_mensajes m WHERE m.conversacion_id=w.id ORDER BY m.created_at DESC, m.id DESC LIMIT 1) AS ultimo_dir" +
    " FROM wa_conversaciones w LEFT JOIN clientes cl ON cl.id=w.cliente_id" +
    " WHERE 1=1" + _scw.cond +
    " ORDER BY w.ultimo_mensaje_en DESC, w.id DESC LIMIT 100"
  ).bind(..._scw.bind).all();
  return ok(r.results || []);
}
async function waVerConversacion(env, payload, id) {
  const conv = await env.DB.prepare("SELECT w.id,w.numero_wa,w.cliente_id,cl.nombre AS cliente,cl.asesor AS _asesor FROM wa_conversaciones w LEFT JOIN clientes cl ON cl.id=w.cliente_id WHERE w.id=?").bind(id).first();
  if (!conv) return fail("Conversación no encontrada.", 404);
  const _scw = asesorScope(payload);
  if (_scw) { var _aw = (conv._asesor || "").trim().toUpperCase(); if (_aw !== _scw.first && _aw !== _scw.full) return fail("Sin acceso a esta conversación.", 403); }
  delete conv._asesor;
  const msgs = await env.DB.prepare("SELECT id,direction,tipo,contenido,wa_message_id,created_at FROM wa_mensajes WHERE conversacion_id=? ORDER BY created_at ASC, id ASC LIMIT 300").bind(id).all();
  await env.DB.prepare("UPDATE wa_conversaciones SET no_leidos=0 WHERE id=?").bind(id).run();
  return ok({ conversacion: conv, mensajes: msgs.results || [] });
}
async function waNuevaConversacion(request, env, payload) {
  const b = await request.json().catch(() => ({}));
  const numero = (b.numero || "").replace(/[^0-9]/g, "");
  if (numero.length < 10) return fail("Número inválido (incluye la lada, solo dígitos).");
  const id = await waUpsertConversacion(env, numero, b.nombre || null);
  return ok({ id, numero_wa: numero });
}
async function waEnviar(request, env, payload, id) {
  const conv = await env.DB.prepare("SELECT w.id,w.numero_wa,cl.asesor AS _asesor FROM wa_conversaciones w LEFT JOIN clientes cl ON cl.id=w.cliente_id WHERE w.id=?").bind(id).first();
  if (!conv) return fail("Conversación no encontrada.", 404);
  const _scw = asesorScope(payload);
  if (_scw) { var _aw = (conv._asesor || "").trim().toUpperCase(); if (_aw !== _scw.first && _aw !== _scw.full) return fail("Sin acceso a esta conversación.", 403); }
  const b = await request.json().catch(() => ({}));
  const texto = (b.mensaje || "").trim();
  if (!texto) return fail("Mensaje vacío.");
  const res = await env.DB.prepare("INSERT INTO wa_mensajes (conversacion_id,direction,tipo,contenido,usuario_enviador_id,leido) VALUES (?,?,?,?,?,1)").bind(id, "out", "text", texto, payload.sub).run();
  const msgId = res.meta.last_row_id;
  await env.DB.prepare("UPDATE wa_conversaciones SET ultimo_mensaje_en=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?").bind(id).run();
  const r = await waEnviarMeta(env, conv.numero_wa, texto);
  let estado = "pendiente";
  if (r.ok) { estado = "enviado"; await env.DB.prepare("UPDATE wa_mensajes SET wa_message_id=? WHERE id=?").bind(r.wamid || null, msgId).run(); }
  else if (r.motivo === "meta_error" || r.motivo === "fetch_error") estado = "error";
  await audit(env, payload.sub, "wa_enviar", "whatsapp", id, { estado }, request);
  return ok({ id: msgId, estado, enviado: !!r.ok, motivo: r.motivo || null });
}

// ============================================================================
//  CONFIGURACIÓN (datos de empresa, IVA por defecto) + REPORTES
// ============================================================================
const CAT_NOTA_DEF = ["SEGUIMIENTO", "SIN RESPUESTA", "PRECIO", "MATERIAL", "PROVEEDOR", "PRESUPUESTO", "EXISTENCIA", "TIEMPO DE ENTREGA", "VISITA", "CONTACTAR", "STAND BY", "OTRO"];
const CAT_FINAL_DEF = ["VIABLE", "NV"];
function parseCat(v) {
  try { const a = JSON.parse(v || "null"); if (Array.isArray(a) && a.length) return a.map((x) => String(x)); } catch (e) {}
  return null;
}
async function getConfig(env) {
  const r = await env.DB.prepare("SELECT clave,valor FROM app_config").all();
  const map = {};
  for (const row of (r.results || [])) map[row.clave] = row.valor;
  // Asesores: se arman solos con los usuarios activos y con los que ya traen leads.
  const catAsesores = [];
  try {
    const vis = {};
    const ru = (await env.DB.prepare("SELECT DISTINCT TRIM(nombre) AS v FROM usuarios WHERE deleted_at IS NULL AND IFNULL(activo,1)=1 AND rol IN ('empleado','gerente') AND nombre IS NOT NULL AND TRIM(nombre)<>''").all()).results || [];
    for (const x of ru) { const n = String(x.v).split(/\s+/)[0].toUpperCase().slice(0, 40); if (n && !vis[n]) { vis[n] = 1; catAsesores.push(n); } }
    const rl = (await env.DB.prepare("SELECT DISTINCT UPPER(TRIM(asesor)) AS v FROM clientes WHERE deleted_at IS NULL AND asesor IS NOT NULL AND TRIM(asesor)<>''").all()).results || [];
    for (const x of rl) { const n = String(x.v).slice(0, 40); if (n && !vis[n]) { vis[n] = 1; catAsesores.push(n); } }
    catAsesores.sort();
  } catch (e) {}
  return {
    cat_estatus_nota: parseCat(map.cat_estatus_nota) || CAT_NOTA_DEF,
    cat_estatus_final: parseCat(map.cat_estatus_final) || CAT_FINAL_DEF,
    cat_asesores: catAsesores,
    nombre: map.nombre || EMPRESA.nombre || "ASLAN",
    direccion: map.direccion || EMPRESA.direccion || "",
    rfc: map.rfc || EMPRESA.rfc || "",
    telefono: map.telefono || EMPRESA.telefono || "",
    whatsapp: map.whatsapp || EMPRESA.whatsapp || "",
    email: map.email || EMPRESA.email || "",
    iva: map.iva != null ? Number(map.iva) : 16,
    crm_titulos: map.crm_titulos || "",
    crm_cols: map.crm_cols || "",
    crm_layout: map.crm_layout || "",
    logo_data: map.logo_data || "",
  };
}
const RX_COL = /^col_[a-z0-9_]{1,24}$/;
function slugColumna(t) {
  const s = String(t || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "")
    .toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+/, "").replace(/_+$/, "").slice(0, 24).replace(/_+$/, "");
  return s ? "col_" + s : "";
}
async function crmColsList(env) {
  const r = await env.DB.prepare("SELECT valor FROM app_config WHERE clave='crm_cols'").first();
  if (!r || !r.valor) return [];
  try {
    const a = JSON.parse(r.valor);
    return Array.isArray(a) ? a.filter((x) => x && typeof x.c === "string" && RX_COL.test(x.c)) : [];
  } catch (e) { return []; }
}
async function crmColsSave(env, lista) {
  await env.DB.prepare("INSERT INTO app_config (clave,valor,updated_at) VALUES ('crm_cols',?,CURRENT_TIMESTAMP) ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor, updated_at=CURRENT_TIMESTAMP").bind(JSON.stringify(lista)).run();
}
async function handleCrmColumnas(request, env, payload) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo administracion o gerencia puede cambiar las columnas.", 403);
  const b = await request.json().catch(() => ({}));
  let lista = await crmColsList(env);
  if (b.quitar) {
    if (!RX_COL.test(String(b.quitar))) return fail("Columna no valida.");
    lista = lista.filter((x) => x.c !== String(b.quitar));
    await crmColsSave(env, lista);
    await audit(env, payload.sub, "crm_columna_quitar", "config", null, String(b.quitar), request);
    return ok(lista);
  }
  const titulo = String(b.titulo || "").replace(/[<>]/g, "").trim().slice(0, 28);
  if (!titulo) return fail("Escribe el nombre de la columna.");
  const col = slugColumna(titulo);
  if (!RX_COL.test(col)) return fail("El nombre debe llevar al menos una letra o numero.");
  if (lista.some((x) => x.c === col)) return fail("Ya existe una columna con ese nombre.");
  if (lista.length >= 20) return fail("Maximo 20 columnas adicionales.");
  const info = await env.DB.prepare("SELECT name FROM pragma_table_info('clientes') WHERE name=?").bind(col).first();
  if (!info) {
    try { await env.DB.prepare("ALTER TABLE clientes ADD COLUMN " + col + " TEXT").run(); }
    catch (e) { return fail("No se pudo crear la columna: " + (e && e.message ? e.message : "error")); }
  }
  lista.push({ c: col, t: titulo.toUpperCase() });
  await crmColsSave(env, lista);
  await audit(env, payload.sub, "crm_columna_agregar", "config", null, col, request);
  return ok(lista);
}
async function handleConfig(request, env, payload, method) {
  if (method === "GET") {
    const cfg = await getConfig(env);
    cfg.sistema = { whatsapp: !!(env.WA_TOKEN && env.WA_PHONE_ID), fotos_r2: !!env.FILES, verify_token: !!env.WA_VERIFY_TOKEN };
    return ok(cfg);
  }
  const b = await request.json().catch(() => ({}));
  const _kcfg = Object.keys(b || {});
  const _soloTitulos = _kcfg.length > 0 && _kcfg.every((k) => k === "crm_titulos" || k === "crm_layout");
  if (!hasRole(payload, "admin") && !(_soloTitulos && hasRole(payload, "gerente"))) return fail("Solo administración puede cambiar la configuración.", 403);
  if ("logo_data" in b) {
    const ld = b.logo_data == null ? "" : String(b.logo_data);
    if (ld && !/^data:image\/(png|jpeg);base64,[A-Za-z0-9+\/=]+$/.test(ld)) return fail("El logo debe ser una imagen PNG o JPG.");
    if (ld.length > 420000) return fail("El logo supera 300 KB. Usa una imagen más ligera.");
    await env.DB.prepare("INSERT INTO app_config (clave,valor,updated_at) VALUES ('logo_data',?,CURRENT_TIMESTAMP) ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor, updated_at=CURRENT_TIMESTAMP").bind(ld).run();
    delete b.logo_data;
  }
  // Listas de opciones del CRM (estatus y estatus final). Se guardan normalizadas.
  for (const k of ["cat_estatus_nota", "cat_estatus_final"]) {
    if (k in b) {
      let arr = b[k];
      if (typeof arr === "string") arr = arr.split(",");
      if (!Array.isArray(arr)) return fail("La lista de opciones no es valida.");
      const vis = {}, out = [];
      for (const x of arr) {
        const v = String(x == null ? "" : x).replace(/[<>"]/g, "").trim().toUpperCase().slice(0, 40);
        if (v && !vis[v]) { vis[v] = 1; out.push(v); }
      }
      if (!out.length) return fail("La lista debe tener al menos una opcion.");
      if (out.length > 40) return fail("Maximo 40 opciones por lista.");
      await env.DB.prepare("INSERT INTO app_config (clave,valor,updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor, updated_at=CURRENT_TIMESTAMP").bind(k, JSON.stringify(out)).run();
      delete b[k];
    }
  }
  const campos = ["nombre", "direccion", "rfc", "telefono", "whatsapp", "email", "iva", "crm_titulos", "crm_layout"];
  for (const k of campos) {
    if (k in b && b[k] !== undefined && b[k] !== null) {
      const v = (k === "iva") ? String(Number(b[k]) || 0) : String(b[k]);
      await env.DB.prepare("INSERT INTO app_config (clave,valor,updated_at) VALUES (?,?,CURRENT_TIMESTAMP) ON CONFLICT(clave) DO UPDATE SET valor=excluded.valor, updated_at=CURRENT_TIMESTAMP").bind(k, v).run();
    }
  }
  await audit(env, payload.sub, "config_update", "config", null, Object.keys(b), request);
  const cfg = await getConfig(env);
  cfg.sistema = { whatsapp: !!(env.WA_TOKEN && env.WA_PHONE_ID), fotos_r2: !!env.FILES, verify_token: !!env.WA_VERIFY_TOKEN };
  return ok(cfg);
}
function rangoFecha(prefix, desde, hasta) {
  const cond = [prefix + "deleted_at IS NULL"]; const args = [];
  if (desde) { cond.push("date(" + prefix + "created_at) >= ?"); args.push(desde); }
  if (hasta) { cond.push("date(" + prefix + "created_at) <= ?"); args.push(hasta); }
  return { where: cond.join(" AND "), args };
}
async function handleReportes(request, env, payload, url) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo administración o gerencia.", 403);
  const desde = url.searchParams.get("desde") || null;
  const hasta = url.searchParams.get("hasta") || null;
  const fC = rangoFecha("", desde, hasta);
  const fCJ = rangoFecha("c.", desde, hasta);

  const porEstado = (await env.DB.prepare("SELECT estado, COUNT(*) AS n, COALESCE(SUM(total),0) AS monto FROM cotizaciones WHERE " + fC.where + " GROUP BY estado ORDER BY monto DESC").bind(...fC.args).all()).results || [];
  const tot = await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(total),0) AS monto FROM cotizaciones WHERE " + fC.where).bind(...fC.args).first();
  const acep = await env.DB.prepare("SELECT COUNT(*) AS n, COALESCE(SUM(total),0) AS monto FROM cotizaciones WHERE " + fC.where + " AND estado IN ('aceptada','convertida')").bind(...fC.args).first();
  const topClientes = (await env.DB.prepare("SELECT COALESCE(cl.nombre,'—') AS cliente, cl.empresa AS empresa, COUNT(*) AS n, COALESCE(SUM(c.total),0) AS monto FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id WHERE " + fCJ.where + " GROUP BY c.cliente_id ORDER BY monto DESC LIMIT 10").bind(...fCJ.args).all()).results || [];

  const nombreEtapa = {}; for (const e of ETAPAS) nombreEtapa[e.clave] = e.nombre;
  const proyEtapa = ((await env.DB.prepare("SELECT etapa_portal AS etapa, COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL GROUP BY etapa_portal ORDER BY n DESC").all()).results || []).map((r) => ({ nombre: nombreEtapa[r.etapa] || r.etapa || "—", n: r.n }));
  const proyTot = await env.DB.prepare("SELECT COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL").first();

  const invCat = (await env.DB.prepare("SELECT COALESCE(categoria,'Otros') AS categoria, COUNT(*) AS n, COALESCE(SUM(stock_actual*precio_venta),0) AS valor, SUM(CASE WHEN stock_actual<=stock_minimo THEN 1 ELSE 0 END) AS bajo FROM productos WHERE deleted_at IS NULL GROUP BY categoria ORDER BY valor DESC").all()).results || [];
  const invTot = await env.DB.prepare("SELECT COALESCE(SUM(stock_actual*precio_venta),0) AS valor, COUNT(*) AS n, SUM(CASE WHEN stock_actual<=stock_minimo THEN 1 ELSE 0 END) AS bajo FROM productos WHERE deleted_at IS NULL").first();
  const alertas = (await env.DB.prepare("SELECT sku, nombre, stock_actual, stock_minimo, unidad FROM productos WHERE deleted_at IS NULL AND stock_actual<=stock_minimo ORDER BY (stock_minimo-stock_actual) DESC, id ASC LIMIT 50").all()).results || [];

  const condA = ["g.tipo='entrada'"]; const argsA = [];
  if (desde) { condA.push("date(g.created_at) >= ?"); argsA.push(desde); }
  if (hasta) { condA.push("date(g.created_at) <= ?"); argsA.push(hasta); }
  const asistEmp = (await env.DB.prepare("SELECT COALESCE(u.nombre,'—') AS empleado, COUNT(*) AS entradas FROM gps_checkins g LEFT JOIN usuarios u ON u.id=g.usuario_id WHERE " + condA.join(" AND ") + " GROUP BY g.usuario_id ORDER BY entradas DESC LIMIT 50").bind(...argsA).all()).results || [];

  return ok({
    rango: { desde, hasta },
    resumen: {
      cotizaciones: tot ? tot.n : 0, monto_total: tot ? tot.monto : 0,
      aceptadas: acep ? acep.n : 0, monto_aceptado: acep ? acep.monto : 0,
      proyectos: proyTot ? proyTot.n : 0,
      inventario_valor: invTot ? invTot.valor : 0, inventario_items: invTot ? invTot.n : 0, inventario_bajo: invTot ? invTot.bajo : 0,
    },
    cotizaciones_por_estado: porEstado,
    top_clientes: topClientes,
    proyectos_por_etapa: proyEtapa,
    inventario_por_categoria: invCat,
    alertas_stock: alertas,
    asistencia_por_empleado: asistEmp,
  });
}

async function handleReportesCrmOpciones(request, env, payload) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo administración o gerencia.", 403);
  async function distintos(col) {
    const rows = (await env.DB.prepare("SELECT DISTINCT " + col + " AS v FROM clientes WHERE deleted_at IS NULL AND " + col + " IS NOT NULL AND TRIM(" + col + ")<>'' ORDER BY v COLLATE NOCASE").all()).results || [];
    return rows.map((r) => r.v);
  }
  return ok({
    asesores: await distintos("asesor"),
    tipos: await distintos("tipo"),
    origenes: await distintos("origen"),
    materiales: await distintos("material"),
    ciudades: await distintos("ciudad"),
    monedas: await distintos("moneda"),
    estatus: await distintos("estatus_nota"),
    acabados: await distintos("acabado"),
    formatos: await distintos("formato"),
    validaciones: await distintos("validacion"),
    finales: await distintos("estatus_final"),
  });
}

async function handleReportesCrm(request, env, payload, url) {
  if (!hasRole(payload, "admin", "gerente")) return fail("Solo administración o gerencia.", 403);
  const q = url.searchParams;
  const cond = ["deleted_at IS NULL"]; const args = [];
  const campoAllow = { created_at: "created_at", fecha_lead: "fecha_lead", fecha_contacto: "fecha_contacto" };
  const campo = campoAllow[q.get("campo")] || "created_at";
  const desde = q.get("desde"); const hasta = q.get("hasta");
  if (desde) { cond.push("date(" + campo + ") >= ?"); args.push(desde); }
  if (hasta) { cond.push("date(" + campo + ") <= ?"); args.push(hasta); }
  const fin = q.get("final") || "activos";
  if (fin === "activos") cond.push("(estatus_final IS NULL OR UPPER(TRIM(estatus_final)) <> 'NV')");
  else if (fin === "nv") cond.push("UPPER(TRIM(estatus_final)) = 'NV'");
  function eq(param, col) { const v = q.get(param); if (v) { cond.push(col + " = ?"); args.push(v); } }
  eq("asesor", "asesor"); eq("tipo", "tipo"); eq("origen", "origen");
  eq("ciudad", "ciudad"); eq("moneda", "moneda"); eq("estatus", "estatus_nota");
  eq("acabado", "acabado"); eq("formato", "formato"); eq("validacion", "validacion");
  eq("efinal", "estatus_final");
  const material = q.get("material"); if (material) { cond.push("material LIKE ?"); args.push("%" + material + "%"); }
  const qq = q.get("q"); if (qq) { cond.push("(nombre LIKE ? OR empresa LIKE ?)"); args.push("%" + qq + "%", "%" + qq + "%"); }
  const mn = q.get("min"); if (mn !== null && mn !== "") { cond.push("COALESCE(propuesta_antes_iva,0) >= ?"); args.push(Number(mn)); }
  const mx = q.get("max"); if (mx !== null && mx !== "") { cond.push("COALESCE(propuesta_antes_iva,0) <= ?"); args.push(Number(mx)); }
  const fmn = q.get("fmin"); if (fmn !== null && fmn !== "") { cond.push("COALESCE(facturado,0) >= ?"); args.push(Number(fmn)); }
  const fmx = q.get("fmax"); if (fmx !== null && fmx !== "") { cond.push("COALESCE(facturado,0) <= ?"); args.push(Number(fmx)); }
  if (q.get("facturado") === "1") cond.push("COALESCE(facturado,0) > 0");
  if (q.get("facturado") === "0") cond.push("COALESCE(facturado,0) = 0");
  if (q.get("conprop") === "1") cond.push("COALESCE(propuesta_antes_iva,0) > 0");
  const where = cond.join(" AND ");

  const AGG = "COUNT(*) AS n, COALESCE(SUM(propuesta_inicial),0) AS inicial, COALESCE(SUM(propuesta_antes_iva),0) AS monto, COALESCE(SUM(facturado),0) AS facturado";
  async function grupo(expr, alias, limite) {
    const sql = "SELECT " + expr + " AS " + alias + ", " + AGG + " FROM clientes WHERE " + where + " GROUP BY 1 ORDER BY monto DESC" + (limite ? (" LIMIT " + limite) : "");
    return (await env.DB.prepare(sql).bind(...args).all()).results || [];
  }
  const resumen = await env.DB.prepare("SELECT COUNT(*) AS registros, COALESCE(SUM(propuesta_inicial),0) AS suma_inicial, COALESCE(SUM(propuesta_antes_iva),0) AS suma_propuesta, COALESCE(SUM(facturado),0) AS suma_facturado, COALESCE(AVG(NULLIF(propuesta_antes_iva,0)),0) AS promedio, SUM(CASE WHEN COALESCE(propuesta_antes_iva,0)>0 THEN 1 ELSE 0 END) AS con_propuesta, SUM(CASE WHEN COALESCE(facturado,0)>0 THEN 1 ELSE 0 END) AS con_factura FROM clientes WHERE " + where).bind(...args).first();
  const porAsesor = await grupo("COALESCE(NULLIF(TRIM(asesor),''),'(sin asesor)')", "asesor", 0);
  const porEstatus = await grupo("COALESCE(NULLIF(TRIM(estatus_nota),''),'(sin estatus)')", "estatus", 0);
  const porMaterial = await grupo("COALESCE(NULLIF(TRIM(material),''),'(sin material)')", "material", 30);
  const porAcabado = await grupo("COALESCE(NULLIF(TRIM(acabado),''),'(sin acabado)')", "acabado", 30);
  const porCiudad = await grupo("COALESCE(NULLIF(TRIM(ciudad),''),'(sin ciudad)')", "ciudad", 30);
  const porOrigen = await grupo("COALESCE(NULLIF(TRIM(origen),''),'(sin origen)')", "origen", 30);
  const porMes = (await env.DB.prepare("SELECT COALESCE(substr(date(" + campo + "),1,7),'(sin fecha)') AS mes, " + AGG + " FROM clientes WHERE " + where + " GROUP BY 1 ORDER BY mes DESC LIMIT 36").bind(...args).all()).results || [];
  const LIMITE = 1000;
  const SEL = "id, " + campo + " AS fecha, fecha_lead, origen, validacion, estatus_final, asesor, estatus_nota AS estatus, fecha_contacto, probabilidad_cierre AS propuesta_factura, empresa, nombre, telefono, email, ciudad, material, tipo, acabado, formato, cantidad, moneda, COALESCE(propuesta_inicial,0) AS propuesta_inicial, COALESCE(propuesta_antes_iva,0) AS propuesta, COALESCE(facturado,0) AS facturado, notas_vero, notas_actualizacion, notas_seguimiento";
  const filasRows = (await env.DB.prepare("SELECT " + SEL + " FROM clientes WHERE " + where + " ORDER BY COALESCE(propuesta_antes_iva,0) DESC, id DESC LIMIT " + (LIMITE + 1)).bind(...args).all()).results || [];
  const truncado = filasRows.length > LIMITE;
  const filas = truncado ? filasRows.slice(0, LIMITE) : filasRows;

  return ok({
    resumen: {
      registros: resumen ? resumen.registros : 0,
      suma_inicial: resumen ? resumen.suma_inicial : 0,
      suma_propuesta: resumen ? resumen.suma_propuesta : 0,
      suma_facturado: resumen ? resumen.suma_facturado : 0,
      promedio: resumen ? resumen.promedio : 0,
      con_propuesta: resumen ? resumen.con_propuesta : 0,
      con_factura: resumen ? resumen.con_factura : 0,
    },
    por_asesor: porAsesor, por_estatus: porEstatus, por_material: porMaterial,
    por_acabado: porAcabado, por_ciudad: porCiudad, por_origen: porOrigen, por_mes: porMes,
    filas: filas, truncado: truncado,
  });
}

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") return new Response(null, { headers: CORS });

  await migrarV3(env);
  await migrarV4(env);
  await migrarV5(env);
  await migrarV6(env);
  await migrarV7(env);
  await migrarV8(env);
  await migrarV9(env);
  await migrarV10(env);
  await migrarV11(env);
  await migrarV12(env);

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
    if (path === "/api/dashboard/stats") return await dashboardStats(env, payload);
    if (path === "/api/dashboard/charts") return await dashboardCharts(env, payload);

    let m;
    if (path === "/api/clientes/duplicados" && method === "GET") return await duplicadosClientes(env, payload);
    if (path === "/api/clientes/historial" && method === "GET") return await historialClientes(env, payload);
    m = path.match(/^\/api\/clientes\/(\d+)\/ficha$/);
    if (m && method === "GET") return await fichaCliente(env, m[1], payload);
    m = path.match(/^\/api\/clientes\/(\d+)\/notas$/);
    if (m && method === "POST") return await agregarNotaCliente(request, env, payload, m[1]);
    m = path.match(/^\/api\/clientes\/(\d+)\/archivos$/);
    if (m && method === "GET") return await listarArchivosCliente(env, payload, m[1]);
    if (m && method === "POST") return await subirArchivoCliente(request, env, payload, m[1]);
    m = path.match(/^\/api\/clientes\/(\d+)\/archivos\/(\d+)$/);
    if (m && method === "DELETE") return await borrarArchivoCliente(request, env, payload, m[1], m[2]);
    m = path.match(/^\/api\/clientes\/(\d+)\/pagos$/);
    if (m && method === "GET") return await listarPagosCliente(env, payload, m[1]);
    if (m && method === "POST") return await agregarPagoCliente(request, env, payload, m[1]);
    m = path.match(/^\/api\/clientes\/(\d+)\/pagos\/recalcular$/);
    if (m && method === "POST") return await recalcularSaldoCliente(env, payload, m[1]);
    m = path.match(/^\/api\/clientes\/(\d+)\/pagos\/(\d+)$/);
    if (m && method === "PUT") return await ligarComprobantePago(request, env, payload, m[1], m[2]);
    if (m && method === "DELETE") return await borrarPagoCliente(request, env, payload, m[1], m[2]);
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
    m = path.match(/^\/api\/cortes(?:\/(\d+))?$/);
    if (m) return await handleCortes(request, env, payload, method, m[1], url);
    if (path === "/api/trazabilidad" && method === "GET") return await trazabilidadGlobal(env, url);

    // ----- Empleados · Check-in GPS · Geocerca -----
    if (path === "/api/checkin" && method === "POST") return await registrarCheckin(request, env, payload);
    if (path === "/api/checkin/estado" && method === "GET") return await checkinEstado(env, payload);
    if (path === "/api/checkins" && method === "GET") return await checkinsRecientes(env, payload);
    m = path.match(/^\/api\/geofencing\/alertas\/(\d+)\/revisar$/);
    if (m && method === "POST") return await revisarAlerta(request, env, payload, m[1]);
    if (path === "/api/geofencing/alertas" && method === "GET") return await alertasGeofencing(env, payload);
    if (path === "/api/geofencing") return await handleGeofencing(request, env, payload, method);
    m = path.match(/^\/api\/empleados(?:\/(\d+))?$/);
    if (m) return await handleEmpleados(request, env, payload, method, m[1]);

    // ----- WhatsApp (bandeja interna) -----
    if (path === "/api/whatsapp/estado" && method === "GET") return await waEstado(env, payload);
    if (path === "/api/whatsapp/conversaciones" && method === "GET") return await waListarConversaciones(env, payload);
    if (path === "/api/whatsapp/conversaciones" && method === "POST") return await waNuevaConversacion(request, env, payload);
    m = path.match(/^\/api\/whatsapp\/conversaciones\/(\d+)$/);
    if (m && method === "GET") return await waVerConversacion(env, payload, m[1]);
    m = path.match(/^\/api\/whatsapp\/conversaciones\/(\d+)\/enviar$/);
    if (m && method === "POST") return await waEnviar(request, env, payload, m[1]);

    // ----- Configuración y Reportes -----
    if (path === "/api/crm/columnas" && method === "POST") return await handleCrmColumnas(request, env, payload);
    if (path === "/api/config") return await handleConfig(request, env, payload, method);
    if (path === "/api/reportes/crm/opciones" && method === "GET") return await handleReportesCrmOpciones(request, env, payload);
    if (path === "/api/reportes/crm" && method === "GET") return await handleReportesCrm(request, env, payload, url);
    if (path === "/api/reportes" && method === "GET") return await handleReportes(request, env, payload, url);

    m = path.match(/^\/api\/admin\/proyectos\/(\d+)\/fotos$/);
    if (m && method === "GET") return await listarFotosProyecto(env, payload, m[1]);
    if (m && method === "POST") return await subirFotoProyecto(request, env, payload, m[1]);
    m = path.match(/^\/api\/admin\/proyectos\/(\d+)\/fotos\/(\d+)$/);
    if (m && method === "DELETE") return await borrarFotoProyecto(request, env, payload, m[1], m[2]);

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
  if (path.startsWith("/m/")) return html(matRedirectPage());
  if (path.startsWith("/media/foto/")) return await serveFoto(request, env, path, url);
  if (path.startsWith("/media/archivo/")) return await serveArchivo(request, env, path, url);
  if (path === "/webhook/whatsapp") return await whatsappWebhook(request, env, url);
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
// Ojo para mostrar/ocultar contraseña. Se engancha solo a cualquier
// input[type=password] que exista o que aparezca despues (modales, vistas).
const PWEYE = `<script>
(function(){
var _O="<path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/>";
var _X="<path d='M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94'/><path d='M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19'/><path d='M9.88 9.88a3 3 0 1 0 4.24 4.24'/><line x1='1' y1='1' x2='23' y2='23'/>";
function _svg(p){return "<svg viewBox='0 0 24 24' width='18' height='18' fill='none' stroke='currentColor' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'>"+p+"</svg>";}
function _pin(b,ver){b.innerHTML=_svg(ver?_X:_O);var t=ver?"Ocultar contraseña":"Ver contraseña";b.title=t;b.setAttribute("aria-label",t);}
function verPass(b){
  var w=b.parentNode,i=w?w.querySelector("input"):null;if(!i)return;
  var ver=(i.type==="password");
  i.type=ver?"text":"password";
  _pin(b,ver);
  try{var p=i.value.length;i.focus();i.setSelectionRange(p,p);}catch(e){}
}
function pwWrap(i){
  if(!i||i.getAttribute("data-pwok"))return;
  var p=i.parentNode;if(!p)return;
  i.setAttribute("data-pwok","1");
  var w=document.createElement("span");w.className="pwbox";
  p.insertBefore(w,i);w.appendChild(i);
  var b=document.createElement("button");b.type="button";b.className="pweye";
  _pin(b,false);
  b.onclick=function(){verPass(b);};
  w.appendChild(b);
}
function pwInit(){var l=document.querySelectorAll("input[type=password]");for(var k=0;k<l.length;k++)pwWrap(l[k]);}
var _tp=null;
function pwSoon(){if(_tp)return;_tp=setTimeout(function(){_tp=null;pwInit();},120);}
window.verPass=verPass;window.pwInit=pwInit;
if(document.readyState!=="loading")pwInit();
document.addEventListener("DOMContentLoaded",pwInit);
try{new MutationObserver(pwSoon).observe(document.documentElement,{childList:true,subtree:true});}catch(e){}
})();
</script>`;

// ============================================================================
function baseStyles(portal) {
  const bg = portal ? "#FBF9F4" : "#F4F1EA";
  const card = "#FFFFFF";
  return `
*{margin:0;padding:0;box-sizing:border-box}
:root{--bg:${bg};--card:${card};--gold:#8B6D3F;--gold2:#6E5430;--txt:#2B2519;--txt2:#6B6256;--ok:#2E7D32;--err:#C62828;--warn:#A97400;--bd:rgba(139,109,63,0.32);--inp:#FFFFFF;--inset:#F4F0E7;--side:#FBF9F4;--thead:#EDE6D6;--card2:#F1ECE1;--line:rgba(0,0,0,0.07);--cardsh:rgba(90,70,35,0.10);--wrapbg:radial-gradient(circle at 35% 15%,#FBF8F2,#ECE5D8 62%)}
body{background:var(--bg);color:var(--txt);font-family:'Montserrat',system-ui,sans-serif;line-height:1.5}
h1,h2,h3,.serif{font-family:'Cormorant Garamond',Georgia,serif}
a{color:var(--gold2);text-decoration:none}
.btn{background:var(--gold);color:#fff;border:none;padding:.7rem 1.2rem;border-radius:4px;font-weight:600;cursor:pointer;font-family:inherit;font-size:.92rem;transition:.15s}
.btn:hover{background:var(--gold2)}
.btn.sec{background:transparent;border:1px solid var(--gold);color:var(--gold2)}
.btn.ok{background:var(--ok)} .btn.err{background:var(--err)} .btn.block{width:100%}
.back{cursor:pointer;color:var(--gold2);font-size:.85rem;margin:0 0 .7rem;display:inline-block;background:none;border:none;padding:0;font-family:inherit;text-align:left}
input,select,textarea{background:var(--inp,#111);border:1px solid var(--bd);color:var(--txt);padding:.65rem .8rem;border-radius:4px;font-family:inherit;width:100%;font-size:.92rem}
input:focus,select,textarea:focus{outline:none;border-color:var(--gold)}
.pwbox{position:relative;display:block}
.pwbox>input{padding-right:2.7rem}
.pweye{position:absolute;right:.5rem;top:50%;transform:translateY(-50%);width:auto;background:none;border:none;color:var(--txt2);cursor:pointer;padding:.15rem;line-height:0;display:flex;align-items:center}
.pweye:hover{color:var(--gold)}
label{display:block;font-size:.78rem;color:var(--txt2);margin:.6rem 0 .25rem;text-transform:uppercase;letter-spacing:.04em}
.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:1.2rem;box-shadow:0 4px 20px var(--cardsh,rgba(0,0,0,.4))}
.pill{display:inline-block;padding:.18rem .65rem;border-radius:99px;font-size:.72rem;font-weight:600}
.muted{color:var(--txt2)}
table{width:100%;border-collapse:collapse;font-size:.86rem}
th{text-align:left;color:var(--gold2);font-weight:600;padding:.6rem;border-bottom:1px solid var(--bd);position:sticky;top:0;background:var(--card)}
td{padding:.55rem .6rem;border-bottom:1px solid var(--line,rgba(255,255,255,.05))}
tr:hover td{background:rgba(139,109,63,.06)}
.toast{position:fixed;top:1rem;right:1rem;background:var(--card);border:1px solid var(--gold);padding:.8rem 1.1rem;border-radius:6px;z-index:9999;box-shadow:0 6px 30px rgba(0,0,0,.6)}
svg{vertical-align:middle;flex-shrink:0}
input[type=number]{-moz-appearance:textfield;appearance:textfield}
input[type=number]::-webkit-outer-spin-button,input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
img,canvas,video{max-width:100%}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:.6rem}
@media(max-width:768px){.g2{grid-template-columns:1fr}.btn{min-height:44px;padding:.8rem 1.1rem}}
`;
}

const FONTS = `<link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Cormorant+Garamond:wght@500;600;700&family=Montserrat:wght@300;400;500;600;700&display=swap" rel="stylesheet">`;

// ============================================================================
//  FRONTEND — LOGIN INTERNO
// ============================================================================
function renderLogin() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Acceso</title>${FONTS}<style>${baseStyles(false)}
.wrap{min-height:100vh;display:flex;align-items:center;justify-content:center;padding:1rem;background:var(--wrapbg,radial-gradient(circle at 35% 15%,#252015,#1a1a1a 62%))}
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
</script>${PWEYE}</body></html>`;
}

// ============================================================================
//  FRONTEND — SPA INTERNA
// ============================================================================
function renderApp() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Panel</title>${FONTS}<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"><script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script><style>${baseStyles(false)}
.crmtable{border-collapse:collapse;min-width:1980px;font-size:.8rem}
.crmtable th{position:sticky;top:0;background:var(--thead,#1d1a14);color:var(--gold);font-size:.7rem;letter-spacing:.02em;padding:.5rem .55rem;border:1px solid var(--bd);white-space:nowrap;text-align:left;z-index:2}
.crmtable td{border:1px solid var(--bd);padding:.4rem .55rem;vertical-align:top}
.xls{overflow:auto;max-height:calc(100vh - 240px);max-height:calc(100dvh - 240px);-webkit-overflow-scrolling:touch}
.xls:focus,.xls:focus-visible{box-shadow:inset 0 0 0 2px var(--gold),0 4px 20px var(--cardsh,rgba(0,0,0,.4))}
.xls::-webkit-scrollbar{height:14px;width:14px}
.xls::-webkit-scrollbar-thumb{background:var(--gold);border-radius:8px;border:3px solid var(--card)}
.xls::-webkit-scrollbar-track{background:rgba(139,109,63,.12)}
.crmc{min-width:110px;outline:none;cursor:cell;user-select:none;-webkit-user-select:none}
.crmc.sel{box-shadow:inset 0 0 0 2px var(--gold);background:rgba(139,109,63,.10)}
.crmc.edit{box-shadow:inset 0 0 0 2px var(--gold);background:rgba(139,109,63,.22);cursor:text;user-select:text;-webkit-user-select:text}
.crmtable th.thed{cursor:cell}
.crmtable th.thed:hover{background:rgba(139,109,63,.28)}
.crmtable th.thedit{box-shadow:inset 0 0 0 2px var(--gold);background:rgba(139,109,63,.30);cursor:text;outline:none;color:var(--gold2,#d8b877)}
.crmnum{text-align:right;white-space:nowrap;color:var(--gold);font-weight:600}
.crmlink{color:var(--gold);font-weight:600;cursor:pointer;text-decoration:underline;text-underline-offset:2px}
.crmlink:hover{background:rgba(139,109,63,.16)}
.crmwide{min-width:260px;max-width:360px;white-space:normal;font-size:.76rem;color:var(--txt2)}
.crmcat{cursor:pointer}
.crmcat:after{content:"\\25be";color:var(--txt2);font-size:.7em;margin-left:.35rem;opacity:.7}
.crmcat.selopen:after{content:""}
.crmcat select{width:100%;padding:.15rem .25rem;font-size:.78rem}
.crmcatsel{cursor:default}
.crmcatsel:after{content:""}
.crmcatsel select.crmsel{min-width:120px;cursor:pointer;background:transparent;border:1px solid var(--bd);border-radius:4px}
.crmtable td.fx{position:sticky;z-index:3;background:var(--card)}
.crmtable th.fx{position:sticky;z-index:6;background:var(--thead,#EDE6D6)}
.crmtable th.fxend,.crmtable td.fxend{border-right:2px solid var(--gold)}
.crmtable th.drag{opacity:.45}
.colman td{padding:.3rem .4rem;border-bottom:1px solid var(--bd);vertical-align:middle}
.colman th{position:static;font-size:.68rem;padding:.35rem .4rem;text-transform:uppercase;letter-spacing:.03em}
.ficha-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;border-bottom:1px solid var(--bd);padding-bottom:.8rem;margin-top:.3rem}
.ficha-name{font-family:'Cormorant Garamond',serif;font-size:1.9rem;color:var(--gold);line-height:1.1}
.ficha-actions{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap}
.fsec{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:1rem;margin-top:1rem}
.fsec h3{font-family:'Cormorant Garamond',serif;color:var(--gold);font-size:1.25rem;margin-bottom:.7rem}
.fgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.7rem}
.ffield{display:flex;flex-direction:column;gap:.2rem}
.ffield label,.fwide label{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--txt2)}
.fwide{grid-column:1/-1;display:flex;flex-direction:column;gap:.2rem}
.fedit{background:var(--inset,#0f0f0f);border:1px solid var(--bd);border-radius:8px;padding:.45rem .6rem;font-size:.9rem;color:var(--txt);min-height:1.2rem;outline:none;word-break:break-word}
.fedit:focus{border-color:var(--gold);box-shadow:inset 0 0 0 1px var(--gold)}
.fedit:empty:before{content:attr(data-ph);color:var(--txt2);opacity:.45}
.fnum{font-variant-numeric:tabular-nums;color:var(--gold);font-weight:600}
.ffield select,.ffield input.fdate{background:var(--inset,#0f0f0f);border:1px solid var(--bd);border-radius:8px;padding:.45rem .6rem;font-size:.9rem;color:var(--txt);width:100%;outline:none;font-family:inherit}
.ffield select:focus,.ffield input.fdate:focus{border-color:var(--gold);box-shadow:inset 0 0 0 1px var(--gold)}
.flink{color:var(--gold);cursor:pointer;text-decoration:underline;text-decoration-style:dotted;text-underline-offset:2px}
.tl{display:flex;flex-direction:column;gap:.5rem}
.tl-item{background:var(--inset,#0f0f0f);border-left:2px solid var(--gold);border-radius:6px;padding:.45rem .6rem;font-size:.86rem}
.crmfilt{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;padding:.6rem;margin-bottom:.6rem}
.crmfilt input,.crmfilt select{width:auto;min-width:120px;padding:.4rem .55rem;font-size:.82rem;margin:0}
.crmfilt input[type=number]{min-width:110px}
.crmfilt .filsep{width:1px;align-self:stretch;background:var(--bd);margin:0 .35rem}
.crmfilt .btn{margin:0}
.crmkpis{margin-bottom:.7rem}
.crmkpis .kpi{padding:.5rem .7rem}
.layout{display:flex;min-height:100vh}
.side{width:240px;background:var(--side,#111);border-right:1px solid var(--bd);padding:1.2rem .8rem;flex-shrink:0;position:sticky;top:0;height:100vh;align-self:flex-start;display:flex;flex-direction:column;overflow-y:auto}
.side h1{color:var(--gold);font-size:1.8rem;letter-spacing:.3em;text-align:center;margin-bottom:1.4rem}
.nav a{display:flex;align-items:center;gap:.6rem;padding:.6rem .8rem;border-radius:6px;color:var(--txt);font-size:.9rem;margin-bottom:.2rem;cursor:pointer}
.nav a:hover{background:rgba(139,109,63,.12)}
.nav a.active{background:var(--gold);color:#fff}
.side .user{margin-top:auto;padding-top:1rem;border-top:1px solid var(--bd);font-size:.8rem;color:var(--txt2)}
.main{flex:1;padding:1.6rem;overflow:auto}
.hd{display:flex;justify-content:space-between;align-items:center;margin-bottom:1.2rem}
.hd h2{font-size:2rem;color:var(--gold)}
.kpis{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin-bottom:1.4rem}
.kpi .n{font-size:2.2rem;color:var(--gold);font-family:'Cormorant Garamond',serif;font-weight:700}
.kpi .l{font-size:.78rem;color:var(--txt2);text-transform:uppercase;letter-spacing:.04em}
.kpi-click{cursor:pointer;transition:transform .15s,border-color .15s,box-shadow .15s}
.kpi-click:hover{border-color:var(--gold);transform:translateY(-3px);box-shadow:0 10px 34px rgba(0,0,0,.45)}
.tablero{display:flex;gap:.7rem;overflow:auto;padding:.3rem 0 .8rem;max-height:calc(100vh - 240px);max-height:calc(100dvh - 240px);-webkit-overflow-scrolling:touch}
.tablero::-webkit-scrollbar{height:14px;width:14px}
.tablero::-webkit-scrollbar-thumb{background:var(--gold);border-radius:8px;border:3px solid var(--card)}
.tablero::-webkit-scrollbar-track{background:rgba(139,109,63,.12)}
.tcol{flex:0 0 250px;min-width:250px;background:var(--card2,#181818);border:1px solid var(--bd);border-radius:10px;padding:.5rem;display:flex;flex-direction:column}
.tcol h4{font-size:.74rem;letter-spacing:.04em;text-transform:uppercase;padding:.35rem .4rem;margin-bottom:.4rem;border-bottom:2px solid var(--bd);display:flex;justify-content:space-between;align-items:center}
.tcol .cnt{background:var(--gold);color:#fff;border-radius:99px;font-size:.66rem;padding:.04rem .42rem;font-weight:700}
.tcard{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:.55rem;margin-bottom:.5rem}
.tcard .nm{font-weight:600;font-size:.82rem;color:var(--txt)}
.tcard .mt{font-size:.74rem;color:var(--txt2);margin:.15rem 0}
.tcard select{font-size:.72rem;padding:.22rem .3rem;margin-top:.35rem}
.grid{display:grid;gap:1rem}
.abadge{margin-left:auto;background:#b0413e;color:#fff;border-radius:10px;font-size:.68rem;padding:.05rem .45rem;font-weight:600}
.al-sec{margin-bottom:1.1rem}
.al-item{display:flex;justify-content:space-between;align-items:center;gap:.6rem;padding:.55rem .7rem;border:1px solid var(--bd);border-radius:8px;margin-bottom:.45rem;flex-wrap:wrap}
.al-item.alarma{border-left:3px solid #b0413e}
.al-item.aviso{border-left:3px solid #c4983a}
.al-tag{font-size:.66rem;letter-spacing:.05em;font-weight:700;padding:.14rem .5rem;border-radius:4px;text-transform:uppercase}
.al-tag.alarma{background:rgba(176,65,62,.16);color:#d9534f;border:1px solid rgba(176,65,62,.5)}
.al-tag.aviso{background:rgba(196,152,58,.14);color:#c4983a;border:1px solid rgba(196,152,58,.5)}
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-bottom:1.4rem}
.wa{display:flex;gap:1rem}
.wa-list{width:300px;flex-shrink:0;max-height:72vh;overflow:auto}
.wa-thread{flex:1;display:flex;flex-direction:column;min-height:340px}
.wa-msgs{flex:1;max-height:58vh;overflow:auto;padding:.3rem}
.wa-conv{padding:.55rem .7rem;border:1px solid var(--bd);border-radius:8px;margin-bottom:.4rem;cursor:pointer}
.wa-conv:hover{border-color:var(--gold)}
.wa-conv.active{border-color:var(--gold);background:rgba(139,109,63,.12)}
.wa-b{max-width:80%;padding:.5rem .8rem;border-radius:12px;margin:.3rem 0;font-size:.9rem;word-wrap:break-word}
.wa-b.in{background:var(--card);border:1px solid var(--bd)}
.wa-b.out{background:var(--gold);color:#fff;margin-left:auto}
@media(max-width:768px){.wa{flex-direction:column}.wa-list{width:100%;max-height:40vh}}
@media(max-width:768px){.side{position:fixed;left:-260px;transition:.2s;z-index:50;height:100%}.side.open{left:0}.main{padding:1rem}.menu-btn{display:block!important}}
.menu-btn{display:inline-flex;align-items:center;background:none;border:1px solid var(--bd);color:var(--gold);padding:.4rem .7rem;border-radius:4px;font-size:1.2rem;cursor:pointer;margin-right:.6rem}
@media(min-width:769px){body.side-off .side{display:none}}
.colhd{display:flex;align-items:center;gap:.45rem;cursor:pointer;user-select:none;font-size:.78rem;letter-spacing:.06em;text-transform:uppercase;color:var(--txt2);padding:.25rem .2rem;margin-bottom:.35rem}
.colhd:hover{color:var(--gold)}
.colhd .chev{display:inline-block;transition:transform .15s}
.colhd.closed .chev{transform:rotate(-90deg)}
.hd-l{display:flex;align-items:center;gap:.7rem;min-width:0}
.hd-r{display:flex;align-items:center;gap:.5rem;flex-shrink:0}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:4000;padding:1rem}
.modal.open{display:flex}
.modal .inner{background:var(--card);border:1px solid var(--gold);border-radius:10px;padding:1.4rem;max-width:420px;width:100%;max-height:90vh;overflow:auto}
td[contenteditable]{cursor:text;border-bottom:1px dashed rgba(139,109,63,.4)}
td[contenteditable]:focus{outline:1px solid var(--gold);background:rgba(139,109,63,.08)}
@media(max-width:768px){body{overflow-x:hidden}.layout{max-width:100%}.main{min-width:0}.hd{flex-wrap:wrap;gap:.5rem;align-items:center}.hd-l{flex:1 1 55%;min-width:0}.hd h2{font-size:1.45rem;overflow-wrap:anywhere;line-height:1.12}.hd-r{flex:1 1 auto;flex-wrap:wrap;gap:.4rem;justify-content:flex-start}#acciones{display:flex;flex-wrap:wrap;gap:.4rem;flex:1 1 100%}.hd-r .btn,#acciones .btn{font-size:.78rem;padding:.48rem .7rem;min-height:40px}.kpis{grid-template-columns:1fr 1fr;gap:.6rem}.kpi{padding:.7rem .6rem}.kpi .n{font-size:clamp(1.05rem,4.4vw,1.7rem);line-height:1.15;overflow-wrap:anywhere;font-variant-numeric:tabular-nums}.card{overflow-x:auto}.modal{padding:0;align-items:flex-end}.modal .inner{max-width:none;width:100%;border-radius:14px 14px 0 0;max-height:92vh}.side.open{box-shadow:0 0 40px rgba(0,0,0,.6)}}
</style></head><body>
<div class="layout">
<aside class="side" id="side">
<h1>ASLAN</h1>
<nav class="nav" id="nav"></nav>
<div class="user" id="userBox"></div>
</aside>
<main class="main">
<div class="hd"><div class="hd-l"><button class="menu-btn" onclick="toggleSide()" title="Mostrar/ocultar menú" aria-label="Mostrar/ocultar menú"><svg viewBox='0 0 24 24' width='22' height='22' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round'><line x1='3' y1='6' x2='21' y2='6'/><line x1='3' y1='12' x2='21' y2='12'/><line x1='3' y1='18' x2='21' y2='18'/></svg></button><h2 id="titulo">Dashboard</h2></div><div class="hd-r"><div id="acciones"></div></div></div>
<div id="content">Cargando…</div>
</main></div>
<div class="modal" id="modal"><div class="inner" id="modalInner"></div></div>
<script>
function toggleSide(){if(window.innerWidth<=768){document.getElementById('side').classList.toggle('open');}else{document.body.classList.toggle('side-off');try{localStorage.setItem('aslan_side',document.body.classList.contains('side-off')?'0':'1');}catch(e){}ajustarXls();}}
if(window.innerWidth>768){try{if(localStorage.getItem('aslan_side')==='0')document.body.classList.add('side-off');}catch(e){}}
function ajustarXls(){var e=document.querySelector('#content .xls')||document.querySelector('#content .tablero');if(!e)return;var r=e.getBoundingClientRect();var h=window.innerHeight-r.top-16;if(h>180)e.style.maxHeight=h+'px';}
window.addEventListener('resize',function(){ajustarXls();if(typeof fijarColsCRM==='function')fijarColsCRM();});
var CRM_FIL_OPEN=true,CRM_KPI_OPEN=true;
try{CRM_FIL_OPEN=localStorage.getItem('aslan_crm_fil')!=='0';CRM_KPI_OPEN=localStorage.getItem('aslan_crm_kpi')!=='0';}catch(e){}
function togFiltros(){CRM_FIL_OPEN=!CRM_FIL_OPEN;try{localStorage.setItem('aslan_crm_fil',CRM_FIL_OPEN?'1':'0');}catch(e){}var b=document.getElementById('filBody'),hd=document.getElementById('filHd');if(b)b.style.display=CRM_FIL_OPEN?'':'none';if(hd)hd.classList.toggle('closed',!CRM_FIL_OPEN);ajustarXls();}
function togKpis(){CRM_KPI_OPEN=!CRM_KPI_OPEN;try{localStorage.setItem('aslan_crm_kpi',CRM_KPI_OPEN?'1':'0');}catch(e){}if(typeof filasCRMFiltradas==='function'&&typeof pintarResumen==='function'){pintarResumen(filasCRMFiltradas());}ajustarXls();}
function openModal(h){document.getElementById('modalInner').innerHTML=h;document.getElementById('modal').classList.add('open');}
function closeModal(){document.getElementById('modal').classList.remove('open');}
var TOKEN=localStorage.getItem('aslan_token');
var USER=JSON.parse(localStorage.getItem('aslan_user')||'null');
if(!TOKEN||!USER){location.href='/login';}
else if(USER.rol==='cliente'){location.href='/portal/dashboard';} // el cliente va a su portal
function H(){return {'Content-Type':'application/json','Authorization':'Bearer '+TOKEN};}
async function api(p,opt){opt=opt||{};opt.headers=H();var r=await fetch(p,opt);if(r.status===401){localStorage.clear();location.href='/login';return null;}return await r.json();}
function money(n){return '$'+Number(n||0).toLocaleString('es-MX',{minimumFractionDigits:2,maximumFractionDigits:2});}
function ic(p,s){s=s||18;return "<svg viewBox='0 0 24 24' width='"+s+"' height='"+s+"' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'>"+p+"</svg>";}
var ICONS={
  dashboard:"<rect x='3' y='3' width='7' height='9' rx='1'/><rect x='14' y='3' width='7' height='5' rx='1'/><rect x='14' y='12' width='7' height='9' rx='1'/><rect x='3' y='16' width='7' height='5' rx='1'/>",
  alertas:"<path d='M18 8a6 6 0 0 0-12 0c0 7-3 9-3 9h18s-3-2-3-9'/><path d='M13.73 21a2 2 0 0 1-3.46 0'/>",
  clientes:"<path d='M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'/><circle cx='9' cy='7' r='4'/><path d='M23 21v-2a4 4 0 0 0-3-3.87'/><path d='M16 3.1a4 4 0 0 1 0 7.75'/>",
  cotizaciones:"<path d='M6 2h9l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z'/><path d='M14 2v6h6'/><path d='M9 13h6M9 17h4'/>",
  inventario:"<path d='M21 8l-9 4-9-4 9-4 9 4z'/><path d='M3 8v8l9 4 9-4V8'/><path d='M12 12v8'/>",
  proyectos:"<path d='M12 2l9 5-9 5-9-5 9-5z'/><path d='M3 12l9 5 9-5'/><path d='M3 17l9 5 9-5'/>",
  cortes:"<path d='M6 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'/><path d='M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'/><path d='M8.1 7.1L20 18M8.1 16.9L20 6'/>",
  trazabilidad:"<circle cx='5' cy='6' r='2.4'/><circle cx='19' cy='6' r='2.4'/><circle cx='12' cy='18' r='2.4'/><path d='M7 7l4 9M17 7l-4 9'/>",
  empleados:"<circle cx='12' cy='8' r='4'/><path d='M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1'/>",
  whatsapp:"<path d='M21 11.5a8.4 8.4 0 0 1-8.5 8.5 8.5 8.5 0 0 1-4-1L3 21l1.5-5.5a8.5 8.5 0 1 1 16.5-4z'/>",
  reportes:"<path d='M3 17l6-6 4 4 7-7'/><path d='M17 8h4v4'/>",
  config:"<circle cx='12' cy='12' r='3.2'/><path d='M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'/>",
  ojo:"<path d='M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z'/><circle cx='12' cy='12' r='3'/>"
};
function toast(t){var d=document.createElement('div');d.className='toast';d.textContent=t;document.body.appendChild(d);setTimeout(function(){d.remove();},2600);}

var MENU=[
  {id:'dashboard',label:'Dashboard',roles:['admin','gerente','empleado']},
  {id:'alertas',label:'Alertas de leads',roles:['admin','gerente','empleado']},
  {id:'clientes',label:'Clientes / CRM',roles:['admin','gerente','empleado']},
  {id:'cotizaciones',label:'Cotizaciones',roles:['admin','gerente','empleado']},
  {id:'inventario',label:'Inventario',roles:['admin','gerente','empleado']},
  {id:'proyectos',label:'Proyectos',roles:['admin','gerente','empleado']},
  {id:'cortes',label:'Cortes',roles:['admin','gerente']},
  {id:'trazabilidad',label:'Trazabilidad',roles:['admin','gerente']},
  {id:'empleados',label:'Empleados',roles:['admin','gerente']},
  {id:'whatsapp',label:'WhatsApp',roles:['admin','gerente','empleado']},
  {id:'reportes',label:'Reportes',roles:['admin','gerente']},
  {id:'config',label:'Configuración',roles:['admin']}
];
function renderNav(){
  var nav=document.getElementById('nav');nav.innerHTML='';
  MENU.filter(function(m){return m.roles.indexOf(USER.rol)>=0;}).forEach(function(m){
    var a=document.createElement('a');a.innerHTML=ic(ICONS[m.id]||'')+'<span>'+m.label+'</span>'+(m.id==='alertas'?'<span class="abadge" id="alertBadge" style="display:none"></span>':'');a.dataset.id=m.id;
    a.onclick=function(){go(m.id);};nav.appendChild(a);
  });
  document.getElementById('userBox').innerHTML=USER.nombre+'<br><span style="color:var(--gold)">'+USER.rol+'</span> · <a onclick="logout()" style="cursor:pointer">salir</a><br><a href="/check-in" style="color:var(--gold2);font-size:.8rem">Registrar entrada / salida</a>';
}
function logout(){localStorage.clear();location.href='/login';}
function setActive(id){var as=document.querySelectorAll('.nav a');as.forEach(function(a){a.classList.toggle('active',a.dataset.id===id);});}

async function go(id){
  MAT_CTRL=null;
  setActive(id);document.getElementById('side').classList.remove('open');
  document.getElementById('acciones').innerHTML='';
  var t={dashboard:'Dashboard',alertas:'Alertas de leads',clientes:'Clientes / CRM',cotizaciones:'Cotizaciones',inventario:'Inventario',proyectos:'Proyectos',cortes:'Cortes',trazabilidad:'Trazabilidad',empleados:'Empleados',whatsapp:'WhatsApp',reportes:'Reportes',config:'Configuración'};
  document.getElementById('titulo').textContent=t[id]||id;
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  if(id==='dashboard')return viewDashboard(c);
  if(id==='alertas')return viewAlertas(c);
  if(id==='clientes')return viewClientes(c);
  if(id==='cotizaciones')return viewCotizaciones(c);
  if(id==='inventario')return viewInventario(c);
  if(id==='proyectos')return viewProyectos(c);
  if(id==='cortes')return viewCortes(c);
  if(id==='trazabilidad')return viewTrazabilidad(c);
  if(id==='empleados')return viewEmpleados(c);
  if(id==='whatsapp')return viewWhatsApp(c);
  if(id==='reportes')return viewReportes(c);
  if(id==='config')return viewConfig(c);
  c.innerHTML='<div class="card"><h3 class="serif" style="color:var(--gold);font-size:1.4rem">Módulo en construcción</h3><p class="muted" style="margin-top:.5rem">Esta sección («'+t[id]+'») se está integrando sobre esta misma base. Ya está el backbone, la auth por rol y el esquema de datos completo.</p></div>';
}

var CORTE_ESTADOS=['pendiente','en_proceso','terminado','entregado'];
var CORTE_LISTAS={prod:[],cot:[],emp:[]};
function irTraza(){go('trazabilidad');}
function irCortes(){go('cortes');}
function estadoCorteSel(id,val){
  var o='';CORTE_ESTADOS.forEach(function(s){o+='<option value="'+s+'"'+(val===s?' selected':'')+'>'+s+'</option>';});
  return '<select onchange="cambiarEstadoCorte('+id+',this.value)" style="font-size:.74rem;padding:.2rem .3rem">'+o+'</select>';
}
async function viewCortes(c){
  document.getElementById('acciones').innerHTML='<button class="btn" onclick="nuevoCorte()">+ Nuevo corte</button> <button class="btn sec" onclick="irTraza()">Ver trazabilidad</button>';
  var d=await api('/api/cortes');if(!d||!d.ok)return;
  var nota='<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Cada corte liga un material de inventario con su cotización, cliente y cortador. Si marcas «descontar», genera la salida de inventario automáticamente.</p>';
  var h=nota+'<div class="card" style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th>Folio</th><th>Material</th><th>Cantidad</th><th>Medidas</th><th>Cotización</th><th>Cliente</th><th>Asesor</th><th>Cortador</th><th>Estado</th><th>Inv.</th></tr></thead><tbody>';
  d.data.forEach(function(r){
    var inv=r.descuenta_inventario?'<span class="pill" style="background:var(--ok)">descontado</span>':'<span class="pill" style="background:#555">no</span>';
    var cot=r.cotizacion_folio?('<span class="pill" style="background:var(--gold)">'+r.cotizacion_folio+'</span>'):'—';
    h+='<tr><td>'+(r.folio||'—')+'</td><td>'+escAttr(r.material||'—')+(r.material_sku?(' <span class="muted">'+escAttr(r.material_sku)+'</span>'):'')+'</td><td style="white-space:nowrap">'+(r.cantidad||0)+' '+(r.unidad||'')+'</td><td>'+escAttr(r.medidas||'—')+'</td><td>'+cot+'</td><td>'+escAttr(r.cliente||'—')+'</td><td>'+escAttr(r.asesor||'—')+'</td><td>'+escAttr(r.cortador||'—')+'</td><td>'+estadoCorteSel(r.id,r.estado)+'</td><td>'+inv+'</td></tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="10" class="muted">Sin cortes aún. Crea el primero con «+ Nuevo corte».</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
async function nuevoCorte(){
  var dp=await api('/api/productos');var dc=await api('/api/cotizaciones');var de=await api('/api/empleados');
  CORTE_LISTAS.prod=(dp&&dp.ok)?dp.data:[];
  CORTE_LISTAS.cot=(dc&&dc.ok)?dc.data:[];
  CORTE_LISTAS.emp=(de&&de.ok)?de.data:[];
  var oMat='<option value="">— Material de inventario —</option>';
  CORTE_LISTAS.prod.forEach(function(p){oMat+='<option value="'+p.id+'">'+escAttr(p.nombre)+(p.sku?(' ('+escAttr(p.sku)+')'):'')+' · stock '+(p.stock_actual||0)+' '+(p.unidad||'')+'</option>';});
  var oCot='<option value="">— Sin cotización —</option>';
  CORTE_LISTAS.cot.forEach(function(co){oCot+='<option value="'+co.id+'">'+escAttr(co.folio||'')+(co.cliente?(' · '+escAttr(co.cliente)):'')+'</option>';});
  var oEmp='<option value="">— Cortador —</option>';
  CORTE_LISTAS.emp.forEach(function(e){oEmp+='<option value="'+e.id+'">'+escAttr(e.nombre)+(e.cargo?(' · '+escAttr(e.cargo)):'')+'</option>';});
  var oEst='';CORTE_ESTADOS.forEach(function(s){oEst+='<option value="'+s+'">'+s+'</option>';});
  var h='<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.8rem">Nuevo corte</h3>'+
    '<label>Material</label><select id="coMat">'+oMat+'</select>'+
    '<label>Cotización ligada (define el cliente)</label><select id="coCot">'+oCot+'</select>'+
    '<label>Cortador</label><select id="coEmp">'+oEmp+'</select>'+
    '<div style="display:flex;gap:.6rem"><div style="flex:1"><label>Cantidad (m²)</label><input id="coCant" type="text" inputmode="decimal" placeholder="0"></div>'+
    '<div style="flex:1"><label>Medidas</label><input id="coMed" placeholder="120x60x2 cm"></div></div>'+
    '<label>Estado</label><select id="coEst">'+oEst+'</select>'+
    '<label style="display:flex;align-items:center;gap:.5rem;margin:.7rem 0;font-size:.86rem"><input type="checkbox" id="coInv" style="width:auto"> Descontar este material del inventario (genera salida)</label>'+
    '<label>Notas</label><textarea id="coNotas" rows="2"></textarea>'+
    '<div style="display:flex;gap:.5rem;margin-top:1rem"><button class="btn" onclick="guardarCorte()">Guardar corte</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>';
  openModal(h);
}
async function guardarCorte(){
  var prod=val('coMat');if(!prod){toast('Selecciona el material');return;}
  var body={producto_id:Number(prod),
    cotizacion_id:val('coCot')?Number(val('coCot')):null,
    empleado_id:val('coEmp')?Number(val('coEmp')):null,
    cantidad:parseFloat((val('coCant')||'0').replace(/[^0-9.-]/g,''))||0,
    unidad:'m2',medidas:val('coMed'),estado:val('coEst'),
    descuenta_inventario:document.getElementById('coInv').checked,
    notas:val('coNotas')};
  var d=await api('/api/cortes',{method:'POST',body:JSON.stringify(body)});
  if(d&&d.ok){closeModal();toast('Corte '+d.data.folio+' creado');go('cortes');}else if(d){toast(d.error||'Error al guardar');}
}
async function cambiarEstadoCorte(id,valor){
  var d=await api('/api/cortes/'+id,{method:'PUT',body:JSON.stringify({estado:valor})});
  if(d&&d.ok){toast('Estado actualizado');}else if(d){toast(d.error||'Error');}
}
var TRAZA=[];
async function viewTrazabilidad(c){
  document.getElementById('acciones').innerHTML='<button class="btn sec" onclick="irCortes()">Ir a Cortes</button>';
  var d=await api('/api/trazabilidad');if(!d||!d.ok)return;
  TRAZA=d.data.cadena||[];var mt=d.data.metricas||{};
  var kp='<div class="kpis" style="margin-bottom:1rem">'+
    '<div class="card kpi"><div class="n">'+(mt.cortes||0)+'</div><div class="l">Cortes registrados</div></div>'+
    '<div class="card kpi"><div class="n">'+(mt.m2||0)+'</div><div class="l">m² cortados</div></div>'+
    '<div class="card kpi"><div class="n">'+(mt.sin_cotizacion||0)+'</div><div class="l">Cortes sin cotización</div></div>'+
    '</div>';
  var intro='<p class="muted" style="font-size:.82rem;margin-bottom:.6rem">Cadena completa de trazabilidad: <strong>Material → Corte → Cotización → Cliente → Asesor → Cortador</strong>. Usa el buscador para rastrear cualquier eslabón.</p>'+
    '<input id="trzq" placeholder="Buscar material, folio, cliente, asesor, cortador..." oninput="filtrarTraza()" style="width:100%;max-width:480px;margin-bottom:.7rem;padding:.5rem .7rem">';
  document.getElementById('content').innerHTML=kp+intro+'<div id="trzBox"></div>';
  pintarTraza(TRAZA);
}
function pintarTraza(rows){
  var box=document.getElementById('trzBox');if(!box)return;
  var h='<div class="card" style="overflow-x:auto"><table style="font-size:.8rem"><thead><tr><th>Material</th><th>→ Corte</th><th>Cant.</th><th>Cortador</th><th>→ Cotización</th><th>→ Cliente</th><th>→ Asesor</th><th>Proyecto</th><th>Estado</th></tr></thead><tbody>';
  rows.forEach(function(r){
    var arrow='<span style="color:var(--gold)">→</span> ';
    var cot=r.cotizacion_folio?('<span class="pill" style="background:var(--gold)">'+r.cotizacion_folio+'</span>'):'—';
    var proy=r.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+r.proyecto_folio+'</span>'):'—';
    h+='<tr><td>'+escAttr(r.material||'—')+(r.material_sku?(' <span class="muted">'+escAttr(r.material_sku)+'</span>'):'')+'</td>'+
       '<td>'+(r.folio||'—')+'</td><td style="white-space:nowrap">'+(r.cantidad||0)+' '+(r.unidad||'')+'</td>'+
       '<td>'+escAttr(r.cortador||'—')+'</td><td>'+cot+'</td><td>'+(r.cliente_id?('<span class="flink" onclick="abrirFicha('+r.cliente_id+')">'+escAttr(r.cliente||'')+'</span>'):escAttr(r.cliente||'—'))+(r.cliente_empresa?(' <span class="muted">'+escAttr(r.cliente_empresa)+'</span>'):'')+'</td>'+
       '<td>'+escAttr(r.asesor||'—')+'</td><td>'+proy+'</td><td>'+escAttr(r.estado||'—')+'</td></tr>';
  });
  if(!rows.length)h+='<tr><td colspan="9" class="muted">Sin cortes que mostrar. Registra cortes en el módulo Cortes para construir la cadena.</td></tr>';
  h+='</tbody></table></div>';box.innerHTML=h;
}
function filtrarTraza(){
  var e=document.getElementById('trzq');var q=(e?e.value:'').toLowerCase().trim();
  if(!q){pintarTraza(TRAZA);return;}
  pintarTraza(TRAZA.filter(function(r){return JSON.stringify(r).toLowerCase().indexOf(q)>=0;}));
}
var WA_ACTIVE=null;
function recargarWa(){go('whatsapp');}
async function viewWhatsApp(c){
  document.getElementById('acciones').innerHTML='<button class="btn" onclick="waNueva()">+ Nueva conversación</button> <button class="btn sec" onclick="recargarWa()">Actualizar</button>';
  var est=await api('/api/whatsapp/estado');
  var conf=(est&&est.ok)?est.data.configurado:false;
  var banner=conf?'':'<div class="card" style="border-color:var(--warn);margin-bottom:1rem"><p style="font-size:.85rem;line-height:1.5">WhatsApp en modo demo. Para enviar de verdad, define en tu Worker las variables <strong>WA_TOKEN</strong>, <strong>WA_PHONE_ID</strong> y <strong>WA_VERIFY_TOKEN</strong> (Cloudflare, en tu Worker, sección Settings, Variables). El webhook a registrar en Meta es <strong>/webhook/whatsapp</strong>. Mientras tanto, los mensajes entrantes se guardan y los salientes quedan como «pendientes».</p></div>';
  c.innerHTML=banner+'<div class="wa"><div class="wa-list" id="waList">Cargando…</div><div class="wa-thread card" id="waThread"><p class="muted">Elige una conversación o crea una nueva.</p></div></div>';
  cargarWaLista();
}
async function cargarWaLista(){
  var d=await api('/api/whatsapp/conversaciones');var el=document.getElementById('waList');if(!el)return;
  if(!d||!d.ok){el.innerHTML='<p class="muted">Error al cargar.</p>';return;}
  if(!d.data.length){el.innerHTML='<p class="muted" style="font-size:.85rem">Sin conversaciones aún. Las que lleguen a tu número de WhatsApp aparecerán aquí.</p>';return;}
  var h='';
  d.data.forEach(function(w){
    var nom=w.cliente||('+'+w.numero_wa);
    var prev=(w.ultimo_dir==='out'?'Tú: ':'')+(w.ultimo||'');
    if(prev.length>40)prev=prev.slice(0,40)+'…';
    h+='<div class="wa-conv'+(WA_ACTIVE===w.id?' active':'')+'" onclick="abrirWaConv('+w.id+')"><div style="display:flex;justify-content:space-between;align-items:center;gap:.4rem"><strong style="font-size:.88rem">'+escAttr(nom)+'</strong>'+(w.no_leidos>0?('<span class="pill" style="background:var(--gold);color:#fff">'+w.no_leidos+'</span>'):'')+'</div><div class="muted" style="font-size:.77rem">'+escAttr(prev)+'</div></div>';
  });
  el.innerHTML=h;
}
async function abrirWaConv(id){
  WA_ACTIVE=id;
  var d=await api('/api/whatsapp/conversaciones/'+id);var el=document.getElementById('waThread');if(!el)return;
  if(!d||!d.ok){el.innerHTML='<p class="muted">Error.</p>';return;}
  var conv=d.data.conversacion, nom=conv.cliente||('+'+conv.numero_wa);
  var h='<div style="border-bottom:1px solid var(--bd);padding-bottom:.5rem;margin-bottom:.5rem"><strong>'+escAttr(nom)+'</strong><br><span class="muted" style="font-size:.78rem">+'+escAttr(conv.numero_wa)+'</span></div><div class="wa-msgs" id="waMsgs">';
  d.data.mensajes.forEach(function(m){
    h+='<div class="wa-b '+(m.direction==='out'?'out':'in')+'">'+escAttr(m.contenido||'')+'<div style="font-size:.62rem;opacity:.7;margin-top:.2rem">'+fmtFechaHora(m.created_at)+'</div></div>';
  });
  if(!d.data.mensajes.length)h+='<p class="muted" style="font-size:.85rem">Sin mensajes.</p>';
  h+='</div><div style="display:flex;gap:.5rem;margin-top:.5rem"><input id="waInput" placeholder="Escribe un mensaje…" onkeydown="if(event.keyCode===13)waEnviarMsg('+id+')"><button class="btn" onclick="waEnviarMsg('+id+')">Enviar</button></div>';
  el.innerHTML=h;
  var mm=document.getElementById('waMsgs');if(mm)mm.scrollTop=mm.scrollHeight;
  cargarWaLista();
}
async function waEnviarMsg(id){
  var inp=document.getElementById('waInput');var txt=inp?inp.value.trim():'';if(!txt)return;
  inp.value='';
  var d=await api('/api/whatsapp/conversaciones/'+id+'/enviar',{method:'POST',body:JSON.stringify({mensaje:txt})});
  if(!d)return;
  if(!d.ok){toast(d.error||'No se pudo enviar');return;}
  if(d.data.estado==='pendiente')toast('Guardado (WhatsApp sin configurar)');
  else if(d.data.estado==='error')toast('No se pudo entregar por Meta');
  abrirWaConv(id);
}
function waNueva(){
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.5rem">Nueva conversación</h3><label>Número de WhatsApp (con lada, solo dígitos)</label><input id="waNum" placeholder="5215576098525"><label>Nombre (opcional)</label><input id="waNom"><div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="crearWaConv()">Crear</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
}
async function crearWaConv(){
  var d=await api('/api/whatsapp/conversaciones',{method:'POST',body:JSON.stringify({numero:val('waNum'),nombre:val('waNom')})});
  if(d&&d.ok){closeModal();abrirWaConv(d.data.id);}else if(d){toast(d.error||'Número inválido');}
}
// ----- REPORTES -----
var REP_DATA=null,REP_DESDE=null,REP_HASTA=null;
function fechaISO(d){var m=(d.getMonth()+1),day=d.getDate();return d.getFullYear()+'-'+(m<10?'0':'')+m+'-'+(day<10?'0':'')+day;}
function kpiCard(label,v){return '<div class="card kpi"><div class="n">'+v+'</div><div class="l">'+label+'</div></div>';}
function tablaReporte(titulo,cols,filas){
  var h='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">'+titulo+'</h3>';
  if(!filas.length){h+='<p class="muted" style="font-size:.85rem">Sin datos en el periodo.</p></div>';return h;}
  h+='<div style="overflow-x:auto"><table style="width:100%;border-collapse:collapse"><thead><tr>';
  cols.forEach(function(cn){h+='<th style="text-align:left;padding:.45rem;border-bottom:1px solid var(--bd);color:var(--gold2);font-size:.78rem;text-transform:uppercase;letter-spacing:.03em">'+cn+'</th>';});
  h+='</tr></thead><tbody>';
  filas.forEach(function(f){h+='<tr>';f.forEach(function(cell){h+='<td style="padding:.45rem;border-bottom:1px solid var(--bd);font-size:.86rem">'+escAttr(String(cell))+'</td>';});h+='</tr>';});
  h+='</tbody></table></div></div>';
  return h;
}
function aplicarReporte(){REP_DESDE=val('repDesde');REP_HASTA=val('repHasta');viewReportes(document.getElementById('content'));}
async function viewReportesGeneral(c){
  document.getElementById('acciones').innerHTML='<button class="btn sec" onclick="exportarReporteCSV()">Exportar CSV</button>';
  var hoy=new Date();var d1=REP_DESDE||(hoy.getFullYear()+'-01-01');var d2=REP_HASTA||fechaISO(hoy);
  var d=await api('/api/reportes?desde='+d1+'&hasta='+d2);
  if(!d||!d.ok){c.innerHTML='<div class="card">'+(d?d.error:'Error')+'</div>';return;}
  REP_DATA=d.data;var r=d.data.resumen;
  var h='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.1rem;margin-bottom:.5rem">Periodo</h3><div class="g2" style="max-width:520px"><div><label>Desde</label><input id="repDesde" type="date" value="'+d1+'"></div><div><label>Hasta</label><input id="repHasta" type="date" value="'+d2+'"></div></div><div style="height:.6rem"></div><button class="btn" onclick="aplicarReporte()">Aplicar</button></div>';
  h+='<div class="kpis">';
  h+=kpiCard('Cotizaciones',r.cotizaciones);
  h+=kpiCard('Monto cotizado',money(r.monto_total));
  h+=kpiCard('Aceptadas',r.aceptadas);
  h+=kpiCard('Monto aceptado',money(r.monto_aceptado));
  h+=kpiCard('Valor de inventario',money(r.inventario_valor));
  h+=kpiCard('Bajo stock',r.inventario_bajo);
  h+='</div>';
  h+=tablaReporte('Cotizaciones por estado',['Estado','Cantidad','Monto'],d.data.cotizaciones_por_estado.map(function(x){return [x.estado,x.n,money(x.monto)];}));
  h+=tablaReporte('Clientes con mayor monto cotizado',['Cliente','Empresa','Cotizaciones','Monto'],d.data.top_clientes.map(function(x){return [x.cliente,(x.empresa||'—'),x.n,money(x.monto)];}));
  h+=tablaReporte('Proyectos por etapa',['Etapa','Proyectos'],d.data.proyectos_por_etapa.map(function(x){return [x.nombre,x.n];}));
  h+=tablaReporte('Inventario por categoría',['Categoría','Items','Valor','Bajo stock'],d.data.inventario_por_categoria.map(function(x){return [x.categoria,x.n,money(x.valor),x.bajo];}));
  h+=tablaReporte('Materiales bajo stock',['SKU','Material','Stock','Mínimo'],d.data.alertas_stock.map(function(x){return [x.sku,x.nombre,x.stock_actual+' '+(x.unidad||''),x.stock_minimo];}));
  h+=tablaReporte('Asistencia · entradas por empleado',['Empleado','Entradas'],d.data.asistencia_por_empleado.map(function(x){return [x.empleado,x.entradas];}));
  c.innerHTML=h;
}
function exportarReporteCSV(){
  if(!REP_DATA){toast('Aún no hay datos');return;}
  var nl=String.fromCharCode(10),bom=String.fromCharCode(0xFEFF);
  function q(x){return '"'+String(x==null?'':x).replace(/"/g,'""')+'"';}
  function sec(titulo,cols,filas){var L=[titulo,cols.map(q).join(',')];filas.forEach(function(f){L.push(f.map(q).join(','));});L.push('');return L;}
  var lines=[];
  lines=lines.concat(sec('Cotizaciones por estado',['Estado','Cantidad','Monto'],REP_DATA.cotizaciones_por_estado.map(function(x){return [x.estado,x.n,x.monto];})));
  lines=lines.concat(sec('Clientes con mayor monto',['Cliente','Empresa','Cotizaciones','Monto'],REP_DATA.top_clientes.map(function(x){return [x.cliente,(x.empresa||''),x.n,x.monto];})));
  lines=lines.concat(sec('Proyectos por etapa',['Etapa','Proyectos'],REP_DATA.proyectos_por_etapa.map(function(x){return [x.nombre,x.n];})));
  lines=lines.concat(sec('Inventario por categoria',['Categoria','Items','Valor','BajoStock'],REP_DATA.inventario_por_categoria.map(function(x){return [x.categoria,x.n,x.valor,x.bajo];})));
  lines=lines.concat(sec('Materiales bajo stock',['SKU','Material','Stock','Minimo'],REP_DATA.alertas_stock.map(function(x){return [x.sku,x.nombre,x.stock_actual,x.stock_minimo];})));
  lines=lines.concat(sec('Asistencia por empleado',['Empleado','Entradas'],REP_DATA.asistencia_por_empleado.map(function(x){return [x.empleado,x.entradas];})));
  var blob=new Blob([bom+lines.join(nl)],{type:'text/csv;charset=utf-8'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='reporte_aslan.csv';a.click();
}
var REP_MODE='general',REP_OPC=null,REP_CRM=null;
function repTabs(){
  var g=REP_MODE==='general',k=REP_MODE==='crm';
  return '<div class="card" style="margin-bottom:1rem;display:flex;gap:.5rem;flex-wrap:wrap">'
    +'<button class="btn'+(g?'':' sec')+'" onclick="setRepMode(0)">Resumen general</button>'
    +'<button class="btn'+(k?'':' sec')+'" onclick="setRepMode(1)">Reporte avanzado (CRM)</button>'
    +'</div>';
}
function setRepMode(m){REP_MODE=m?'crm':'general';viewReportes(document.getElementById('content'));}
async function viewReportes(c){
  c.innerHTML=repTabs()+'<div id="repBody">Cargando…</div>';
  var body=document.getElementById('repBody');
  if(REP_MODE==='crm')return viewReportesCRM(body);
  return viewReportesGeneral(body);
}
function repOptEls(arr,sel){
  var s='<option value="">— Todos —</option>';
  (arr||[]).forEach(function(v){if(v==null||v==='')return;s+='<option value="'+escAttr(v)+'"'+(String(v)===String(sel)?' selected':'')+'>'+escAttr(v)+'</option>';});
  return s;
}
async function viewReportesCRM(c){
  document.getElementById('acciones').innerHTML='<button class="btn sec" onclick="exportarCrmCSV()">Exportar CSV</button>';
  if(!REP_OPC){var o=await api('/api/reportes/crm/opciones');REP_OPC=(o&&o.ok)?o.data:{};}
  var O=REP_OPC||{};
  var h='<div class="card" style="margin-bottom:1rem">';
  h+='<h3 style="color:var(--gold);font-size:1.15rem;margin-bottom:.7rem">Filtros del reporte</h3>';
  h+='<div class="g2"><div><label>Desde</label><input id="fDesde" type="date"></div><div><label>Hasta</label><input id="fHasta" type="date"></div></div>';
  h+='<div class="g2"><div><label>Campo de fecha</label><select id="fCampo"><option value="created_at">Fecha de alta</option><option value="fecha_lead">Fecha lead</option><option value="fecha_contacto">Fecha contacto</option></select></div>';
  h+='<div><label>Pipeline</label><select id="fFinal"><option value="activos">Activos (en pipeline)</option><option value="nv">No vendidos (NV)</option><option value="todos">Todos</option></select></div></div>';
  h+='<div class="g2"><div><label>Asesor</label><select id="fAsesor">'+repOptEls(O.asesores)+'</select></div><div><label>Origen del lead</label><select id="fOrigen">'+repOptEls(O.origenes)+'</select></div></div>';
  h+='<div class="g2"><div><label>Validación</label><select id="fValid">'+repOptEls(O.validaciones)+'</select></div><div><label>Estatus final</label><select id="fEFinal">'+repOptEls(O.finales)+'</select></div></div>';
  h+='<div class="g2"><div><label>Estatus / nota</label><select id="fEstatus">'+repOptEls(O.estatus)+'</select></div><div><label>Ciudad</label><select id="fCiudad">'+repOptEls(O.ciudades)+'</select></div></div>';
  h+='<div class="g2"><div><label>Material</label><select id="fMaterial">'+repOptEls(O.materiales)+'</select></div><div><label>Acabado</label><select id="fAcabado">'+repOptEls(O.acabados)+'</select></div></div>';
  h+='<div class="g2"><div><label>Tipo</label><select id="fTipo">'+repOptEls(O.tipos)+'</select></div><div><label>Formato</label><select id="fFormato">'+repOptEls(O.formatos)+'</select></div></div>';
  h+='<div class="g2"><div><label>Moneda</label><select id="fMoneda">'+repOptEls(O.monedas)+'</select></div><div><label>Buscar (nombre / empresa)</label><input id="fQ" type="text" placeholder="texto libre"></div></div>';
  h+='<div class="g2"><div><label>Propuesta mínima (s/IVA)</label><input id="fMin" type="number" step="any" placeholder="0"></div><div><label>Propuesta máxima (s/IVA)</label><input id="fMax" type="number" step="any" placeholder="sin límite"></div></div>';
  h+='<div class="g2"><div><label>Facturado mínimo</label><input id="fFMin" type="number" step="any" placeholder="0"></div><div><label>Facturado máximo</label><input id="fFMax" type="number" step="any" placeholder="sin límite"></div></div>';
  h+='<div class="g2"><div><label>Propuesta</label><select id="fConProp"><option value="">Todas</option><option value="1">Solo con propuesta capturada</option></select></div>';
  h+='<div><label>Facturación</label><select id="fFact"><option value="">Todas</option><option value="1">Solo facturadas</option><option value="0">Solo sin facturar</option></select></div></div>';
  h+='<div style="height:.8rem"></div><button class="btn" onclick="aplicarCrmReporte()">Aplicar filtros</button> <button class="btn sec" onclick="limpiarCrmReporte()">Limpiar</button>';
  h+='</div><div id="crmResultado"><p class="muted" style="font-size:.9rem">Ajusta los filtros y pulsa «Aplicar filtros».</p></div>';
  c.innerHTML=h;
}
function limpiarCrmReporte(){REP_CRM=null;viewReportesCRM(document.getElementById('repBody'));}
function crmQS(){
  var p=[];
  function add(k,v){if(v!==''&&v!=null)p.push(k+'='+encodeURIComponent(v));}
  add('desde',val('fDesde'));add('hasta',val('fHasta'));add('campo',val('fCampo'));
  add('final',val('fFinal'));add('asesor',val('fAsesor'));add('tipo',val('fTipo'));
  add('origen',val('fOrigen'));add('ciudad',val('fCiudad'));add('material',val('fMaterial'));
  add('acabado',val('fAcabado'));add('formato',val('fFormato'));add('validacion',val('fValid'));
  add('efinal',val('fEFinal'));add('moneda',val('fMoneda'));add('estatus',val('fEstatus'));
  add('q',val('fQ'));add('min',val('fMin'));add('max',val('fMax'));
  add('fmin',val('fFMin'));add('fmax',val('fFMax'));
  add('conprop',val('fConProp'));add('facturado',val('fFact'));
  return p.join('&');
}
function repFilaGrupo(x,etq){return [x[etq]||'\u2014',x.n,money(x.inicial),money(x.monto),money(x.facturado)];}
var REP_GRP=['Registros','Propuesta inicial','Propuesta actual','Facturado'];
async function aplicarCrmReporte(){
  var box=document.getElementById('crmResultado');box.innerHTML='Cargando…';
  var d=await api('/api/reportes/crm?'+crmQS());
  if(!d||!d.ok){box.innerHTML='<p class="muted">'+((d&&d.error)||'Error')+'</p>';return;}
  REP_CRM=d.data;var r=d.data.resumen;
  var conv=(Number(r.suma_propuesta)>0)?(Number(r.suma_facturado)/Number(r.suma_propuesta)*100):0;
  var h='<div class="kpis">';
  h+=kpiCard('Registros',r.registros);
  h+=kpiCard('Propuesta inicial',money(r.suma_inicial));
  h+=kpiCard('Propuesta actual s/IVA',money(r.suma_propuesta));
  h+=kpiCard('Facturado',money(r.suma_facturado));
  h+=kpiCard('Ticket promedio',money(r.promedio));
  h+=kpiCard('Con propuesta',r.con_propuesta);
  h+=kpiCard('Con factura',r.con_factura);
  h+=kpiCard('Conversión prop. a factura',(Math.round(conv*10)/10)+'%');
  h+='</div>';
  h+=tablaReporte('Propuestas y facturación por periodo',['Periodo'].concat(REP_GRP),(d.data.por_mes||[]).map(function(x){return repFilaGrupo(x,'mes');}));
  h+=tablaReporte('Por asesor',['Asesor'].concat(REP_GRP),(d.data.por_asesor||[]).map(function(x){return repFilaGrupo(x,'asesor');}));
  h+=tablaReporte('Por estatus / nota',['Estatus'].concat(REP_GRP),(d.data.por_estatus||[]).map(function(x){return repFilaGrupo(x,'estatus');}));
  h+=tablaReporte('Por origen del lead',['Origen'].concat(REP_GRP),(d.data.por_origen||[]).map(function(x){return repFilaGrupo(x,'origen');}));
  h+=tablaReporte('Por material',['Material'].concat(REP_GRP),(d.data.por_material||[]).map(function(x){return repFilaGrupo(x,'material');}));
  h+=tablaReporte('Por acabado',['Acabado'].concat(REP_GRP),(d.data.por_acabado||[]).map(function(x){return repFilaGrupo(x,'acabado');}));
  h+=tablaReporte('Por ciudad',['Ciudad'].concat(REP_GRP),(d.data.por_ciudad||[]).map(function(x){return repFilaGrupo(x,'ciudad');}));
  h+=tablaReporte('Detalle ('+d.data.filas.length+' registros)',REP_DET_TIT,d.data.filas.map(repDetFila));
  if(d.data.truncado)h+='<p class="muted" style="font-size:.82rem">Se muestran los primeros '+d.data.filas.length+' registros. Refina los filtros para acotar.</p>';
  document.getElementById('crmResultado').innerHTML=h;
}
var REP_DET_TIT=['FECHA','ORIGEN','VALIDACIÓN','ESTATUS FINAL','ASESOR','ESTATUS/NOTA','F. CONTACTO','PROP/FACT','COMPAÑÍA','CONTACTO','TELÉFONO','MAIL','CIUDAD','MATERIAL','TIPO','ACABADO','FORMATO','CANTIDAD','PROP. INICIAL','PROP. S/IVA','MONEDA','FACTURADO'];
var REP_DET_CAM=['fecha_lead','origen','validacion','estatus_final','asesor','estatus','fecha_contacto','propuesta_factura','empresa','nombre','telefono','email','ciudad','material','tipo','acabado','formato','cantidad','propuesta_inicial','propuesta','moneda','facturado'];
function repDetFila(x){
  return REP_DET_CAM.map(function(k){
    if(k==='fecha_lead'||k==='fecha_contacto')return fFecha(x[k]);
    if(k==='propuesta_inicial'||k==='propuesta'||k==='facturado')return money(x[k]);
    return (x[k]==null||x[k]==='')?'\u2014':x[k];
  });
}
function exportarCrmCSV(){
  if(!REP_CRM){toast('Aplica los filtros primero');return;}
  var nl=String.fromCharCode(10),bom=String.fromCharCode(0xFEFF);
  function q(x){return '"'+String(x==null?'':x).replace(/"/g,'""')+'"';}
  var cols=REP_DET_TIT.concat(['NOTAS VERO','NOTAS ACTUALIZACIÓN','SEGUIMIENTO']);
  var cam=REP_DET_CAM.concat(['notas_vero','notas_actualizacion','notas_seguimiento']);
  var L=[cols.map(q).join(',')];
  REP_CRM.filas.forEach(function(x){L.push(cam.map(function(k){return q(x[k]);}).join(','));});
  var blob=new Blob([bom+L.join(nl)],{type:'text/csv;charset=utf-8'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='reporte_crm_aslan.csv';a.click();
}

// ----- CONFIGURACIÓN -----
function estadoLinea(label,okb){var col=okb?'var(--ok)':'var(--txt2)';var txt=okb?'Configurado':'Sin configurar';return '<div style="display:flex;justify-content:space-between;align-items:center;padding:.45rem 0;border-bottom:1px solid var(--bd)"><span style="font-size:.9rem">'+label+'</span><span style="color:'+col+';font-size:.82rem"><svg viewBox="0 0 24 24" width="10" height="10" fill="currentColor" style="margin-right:.3rem"><circle cx="12" cy="12" r="6"/></svg>'+txt+'</span></div>';}
function tarjetaPassword(){
  return '<div class="card"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Mi cuenta · cambiar contraseña</h3><div class="g2"><div><label>Contraseña actual</label><input id="pwActual" type="password"></div><div><label>Nueva contraseña</label><input id="pwNueva" type="password"></div></div><label>Repite la nueva contraseña</label><input id="pwRep" type="password"><div style="height:.6rem"></div><button class="btn" onclick="cambiarMiPassword()">Cambiar contraseña</button></div>';
}
async function viewConfig(c){
  if(USER.rol!=='admin'){c.innerHTML='<div class="card muted" style="margin-bottom:1rem">Solo administración puede editar la configuración general. Aquí puedes cambiar tu contraseña.</div>'+tarjetaPassword();return;}
  var d=await api('/api/config');var cfg=(d&&d.ok)?d.data:{};CFG=cfg;
  var sis=cfg.sistema||{};
  var h='';
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Datos de la empresa</h3>';
  h+='<p class="muted" style="font-size:.82rem;margin-bottom:.5rem">Aparecen en el encabezado de las cotizaciones en PDF.</p>';
  h+='<div class="g2"><div><label>Nombre</label><input id="cfgNombre" value="'+escAttr(cfg.nombre||'')+'"></div><div><label>RFC</label><input id="cfgRfc" value="'+escAttr(cfg.rfc||'')+'"></div></div>';
  h+='<label>Dirección</label><input id="cfgDir" value="'+escAttr(cfg.direccion||'')+'">';
  h+='<div class="g2"><div><label>Teléfono</label><input id="cfgTel" value="'+escAttr(cfg.telefono||'')+'"></div><div><label>WhatsApp (solo dígitos)</label><input id="cfgWa" value="'+escAttr(cfg.whatsapp||'')+'"></div></div>';
  h+='<label>Correo</label><input id="cfgEmail" value="'+escAttr(cfg.email||'')+'">';
  h+='<div style="height:.7rem"></div><button class="btn" onclick="guardarConfigEmpresa()">Guardar datos</button></div>';
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Logo de la empresa</h3>';
  h+='<p class="muted" style="font-size:.82rem;margin-bottom:.6rem">Se imprime en la esquina superior izquierda de la cotización en PDF. PNG o JPG, máximo 300 KB (ideal: PNG con fondo transparente, 1200 px de ancho).</p>';
  h+='<div id="cfgLogoPrev" style="margin-bottom:.7rem">'+logoPreviewHtml(cfg.logo_data)+'</div>';
  h+='<input id="cfgLogoFile" type="file" accept="image/png,image/jpeg" style="max-width:380px">';
  h+='<div style="display:flex;gap:.5rem;margin-top:.7rem;flex-wrap:wrap"><button class="btn" onclick="subirLogoCfg()">Guardar logo</button>'+(cfg.logo_data?'<button class="btn sec" onclick="quitarLogoCfg()">Quitar logo</button>':'')+'</div></div>';
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Parámetros</h3>';
  h+='<div style="max-width:240px"><label>IVA por defecto (%)</label><input id="cfgIva" type="number" step="0.01" value="'+(cfg.iva!=null?cfg.iva:16)+'"></div>';
  h+='<p class="muted" style="font-size:.8rem;margin-top:.4rem">Se aplica al crear una nueva cotización.</p>';
  h+='<div style="height:.6rem"></div><button class="btn" onclick="guardarConfigIva()">Guardar parámetros</button></div>';
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Estado del sistema</h3>';
  h+=estadoLinea('WhatsApp (envío real por Meta)',!!sis.whatsapp);
  h+=estadoLinea('Almacenamiento de fotos (R2)',!!sis.fotos_r2);
  h+=estadoLinea('Token de verificación del webhook',!!sis.verify_token);
  h+='<p class="muted" style="font-size:.78rem;margin-top:.5rem">Lo «sin configurar» se activa definiendo las variables del Worker en Cloudflare (WA_TOKEN, WA_PHONE_ID, WA_VERIFY_TOKEN) y el binding R2 FILES.</p></div>';
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Listas del CRM</h3>';
  h+='<p class="muted" style="font-size:.82rem;margin-bottom:.6rem">Son las opciones que el equipo puede elegir en el CRM. Ya no se escribe a mano: una opcion por renglon. El asesor se arma solo con los usuarios activos y con quienes ya traen leads.</p>';
  h+='<div class="g2"><div><label>Estatus / nota</label><textarea id="cfgCatNota" rows="12">'+escT(catTxt(cfg.cat_estatus_nota))+'</textarea></div>';
  h+='<div><label>Estatus final</label><textarea id="cfgCatFinal" rows="12">'+escT(catTxt(cfg.cat_estatus_final))+'</textarea></div></div>';
  h+='<p class="muted" style="font-size:.78rem;margin-top:.5rem">Asesores detectados: '+escT(((cfg.cat_asesores)||[]).join(', ')||'ninguno')+'.</p>';
  h+='<div style="height:.6rem"></div><button class="btn" onclick="guardarCatalogosCRM()">Guardar listas</button></div>';
  h+=tarjetaPassword();
  c.innerHTML=h;
}
async function guardarConfigEmpresa(){
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({nombre:val('cfgNombre'),rfc:val('cfgRfc'),direccion:val('cfgDir'),telefono:val('cfgTel'),whatsapp:val('cfgWa'),email:val('cfgEmail')})});
  if(d&&d.ok){CFG=d.data;toast('Datos guardados');}else if(d){toast(d.error||'No se pudo guardar');}
}
function logoPreviewHtml(data){
  if(!data)return '<p class="muted" style="font-size:.82rem">Sin logo cargado. Mientras tanto la cotización imprime el nombre ASLAN en dorado.</p>';
  return '<div style="background:#fff;padding:.8rem;border-radius:6px;display:inline-block"><img src="'+data+'" alt="Logo" style="max-width:260px;max-height:110px;display:block"></div>';
}
function leerArchivoDataURL(file){
  return new Promise(function(res,rej){var fr=new FileReader();fr.onload=function(){res(fr.result);};fr.onerror=function(){rej(new Error('lectura'));};fr.readAsDataURL(file);});
}
async function subirLogoCfg(){
  var inp=document.getElementById('cfgLogoFile');
  if(!inp||!inp.files||!inp.files.length){toast('Elige primero el archivo del logo');return;}
  var f=inp.files[0];
  if(f.type!=='image/png'&&f.type!=='image/jpeg'){toast('El logo debe ser PNG o JPG');return;}
  if(f.size>300*1024){toast('El logo supera 300 KB, usa una imagen más ligera');return;}
  var data;try{data=await leerArchivoDataURL(f);}catch(e){toast('No se pudo leer el archivo');return;}
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({logo_data:data})});
  if(d&&d.ok){CFG=d.data;toast('Logo guardado, ya sale en las cotizaciones');var pv=document.getElementById('cfgLogoPrev');if(pv)pv.innerHTML=logoPreviewHtml(CFG.logo_data);}
  else if(d){toast(d.error||'No se pudo guardar el logo');}
}
async function quitarLogoCfg(){
  if(!confirm('Quitar el logo de las cotizaciones?'))return;
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({logo_data:''})});
  if(d&&d.ok){CFG=d.data;toast('Logo eliminado');var pv=document.getElementById('cfgLogoPrev');if(pv)pv.innerHTML=logoPreviewHtml('');}
  else if(d){toast(d.error||'No se pudo quitar');}
}
function catTxt(v){
  var NL=String.fromCharCode(10);
  if(!v)return '';
  if(typeof v==='string'){try{v=JSON.parse(v);}catch(e){return String(v);}}
  return (v&&typeof v.length==='number')?v.join(NL):'';
}
function catSplit(t){
  var NL=String.fromCharCode(10),a=String(t||'').split(NL),o=[],i,j,p,v;
  for(i=0;i<a.length;i++){ p=a[i].split(','); for(j=0;j<p.length;j++){ v=p[j].trim(); if(v)o.push(v); } }
  return o;
}
async function guardarCatalogosCRM(){
  var n=catSplit(val('cfgCatNota')),f=catSplit(val('cfgCatFinal'));
  if(!n.length||!f.length){ toast('Cada lista necesita al menos una opcion'); return; }
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({cat_estatus_nota:n,cat_estatus_final:f})});
  if(d&&d.ok){ CFG=d.data; toast('Listas guardadas'); viewConfig(document.getElementById('content')); }
  else if(d){ toast(d.error||'No se pudieron guardar las listas'); }
}
async function guardarConfigIva(){
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({iva:val('cfgIva')})});
  if(d&&d.ok){CFG=d.data;toast('Parámetros guardados');}else if(d){toast(d.error||'No se pudo guardar');}
}
async function cambiarMiPassword(){
  var a=val('pwActual'),n=val('pwNueva'),r=val('pwRep');
  if(!n||n.length<6){toast('La nueva contraseña debe tener al menos 6 caracteres');return;}
  if(n!==r){toast('Las contraseñas no coinciden');return;}
  var d=await api('/api/auth/change-password',{method:'POST',body:JSON.stringify({actual:a,nueva:n})});
  if(d&&d.ok){toast('Contraseña actualizada');var ids=['pwActual','pwNueva','pwRep'];ids.forEach(function(x){var el=document.getElementById(x);if(el)el.value='';});}
  else if(d){toast(d.error||'No se pudo cambiar');}
}

var EMP_MAP=null;
function recargarEmpleados(){go('empleados');}
function fmtFechaHora(s){if(!s)return '—';try{var d=new Date(s.replace(' ','T')+'Z');function z(n){return (n<10?'0':'')+n;}return z(d.getDate())+'-'+z(d.getMonth()+1)+'-'+d.getFullYear()+' '+z(d.getHours())+':'+z(d.getMinutes());}catch(e){return s;}}
function empEstadoBadge(tipo,checkin){
  if(!checkin)return '<span class="pill" style="background:var(--inset);color:var(--txt2)">Sin registro</span>';
  var dt=new Date(checkin.replace(' ','T')+'Z'),hoy=new Date();
  var mismoDia=(dt.getFullYear()===hoy.getFullYear()&&dt.getMonth()===hoy.getMonth()&&dt.getDate()===hoy.getDate());
  if(!mismoDia)return '<span class="pill" style="background:var(--inset);color:var(--txt2)">Sin registro hoy</span>';
  if(tipo==='entrada')return '<span class="pill" style="background:rgba(76,175,80,.18);color:var(--ok)">En sitio</span>';
  return '<span class="pill" style="background:var(--inset);color:var(--txt2)">Salió</span>';
}
async function viewEmpleados(c){
  var puede=(USER.rol==='admin'||USER.rol==='gerente');
  if(!puede){
    c.innerHTML='<div class="card"><h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.4rem">Mi asistencia</h3><p class="muted">La gestión de empleados es para administración o gerencia. Para registrar tu entrada o salida usa la pantalla de check-in.</p><p style="margin-top:.8rem"><a class="btn" href="/check-in">Abrir check-in</a></p></div>';
    return;
  }
  var acc='';
  if(USER.rol==='admin')acc+='<button class="btn" onclick="nuevoEmpleado()">+ Nuevo empleado</button> ';
  acc+='<button class="btn sec" onclick="configGeocerca()">Configurar geocerca</button> <a class="btn sec" href="/check-in" target="_blank">Abrir check-in</a>';
  document.getElementById('acciones').innerHTML=acc;
  var d=await api('/api/empleados');if(!d||!d.ok)return;
  var cksR=await api('/api/checkins'),cks=(cksR&&cksR.ok)?cksR.data:[];
  var alR=await api('/api/geofencing/alertas'),alertas=(alR&&alR.ok)?alR.data:[];
  var geoR=await api('/api/geofencing'),geo=(geoR&&geoR.ok)?geoR.data:null;
  var h='';
  h+='<div class="card" style="padding:.6rem;margin-bottom:1rem"><div id="empMap" style="height:340px;border-radius:8px;overflow:hidden;background:var(--inset)"></div>';
  h+='<p class="muted" style="font-size:.74rem;margin-top:.45rem">Verde = entrada · Rojo = salida · Círculo dorado = geocerca'+(geo?(' («'+(geo.nombre||'Sitio')+'», radio '+geo.radio_metros+' m)'):' — sin configurar, usa «Configurar geocerca»')+'</p></div>';
  var pend=alertas.filter(function(a){return !a.revisada;});
  if(alertas.length){
    h+='<div class="card" style="margin-bottom:1rem"><h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Alertas de geocerca'+(pend.length?(' · '+pend.length+' sin revisar'):'')+'</h3>';
    alertas.slice(0,12).forEach(function(a){
      h+='<div style="display:flex;justify-content:space-between;align-items:center;gap:.6rem;border-bottom:1px solid var(--bd);padding:.45rem 0"><div><strong>'+(a.nombre||('Usuario '+a.usuario_id))+'</strong><br><span class="muted" style="font-size:.78rem">'+fmtFechaHora(a.created_at)+' · '+a.distancia_metros+' m fuera del centro</span></div>'+(a.revisada?'<span class="pill" style="background:var(--inset);color:var(--txt2)">Revisada</span>':'<button class="btn sec" style="padding:.25rem .6rem" onclick="revisarAlertaUI('+a.id+')">Revisar</button>')+'</div>';
    });
    h+='</div>';
  }
  h+='<div class="card" style="overflow-x:auto"><table><thead><tr><th>Empleado</th><th>Rol / Cargo</th><th>Estado hoy</th><th>Último registro</th><th>GPS</th><th>Acciones</th></tr></thead><tbody>';
  d.data.forEach(function(e){
    h+='<tr><td><strong>'+e.nombre+'</strong><br><span class="muted" style="font-size:.76rem">'+(e.email||'')+'</span></td>'+
      '<td>'+e.rol+(e.cargo?('<br><span class="muted" style="font-size:.76rem">'+e.cargo+'</span>'):'')+'</td>'+
      '<td>'+empEstadoBadge(e.ultimo_tipo,e.ultimo_checkin)+'</td>'+
      '<td class="muted" style="white-space:nowrap;font-size:.82rem">'+fmtFechaHora(e.ultimo_checkin)+'</td>'+
      '<td>'+(e.consentimiento_gps?'<span style="font-size:.78rem;color:var(--ok)">Sí</span>':'<span class="muted" style="font-size:.78rem">No</span>')+'</td>'+
      '<td style="white-space:nowrap"><button class="btn sec" style="padding:.25rem .55rem" onclick="editarEmpleado('+e.id+')">Editar</button></td></tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="6" class="muted">Sin empleados.</td></tr>';
  h+='</tbody></table></div>';
  c.innerHTML=h;
  setTimeout(function(){initEmpMap(cks,geo);},40);
}
function initEmpMap(cks,geo){
  if(typeof L==='undefined')return;
  if(EMP_MAP){try{EMP_MAP.remove();}catch(e){}EMP_MAP=null;}
  var center=[19.37241,-99.16830];
  if(geo&&isFinite(geo.lat_centro)&&isFinite(geo.lon_centro))center=[geo.lat_centro,geo.lon_centro];
  else if(cks.length&&isFinite(cks[0].lat))center=[cks[0].lat,cks[0].lon];
  EMP_MAP=L.map('empMap').setView(center,15);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap'}).addTo(EMP_MAP);
  if(geo&&isFinite(geo.lat_centro))L.circle([geo.lat_centro,geo.lon_centro],{radius:geo.radio_metros,color:'#8B6D3F',weight:1.5,fillColor:'#8B6D3F',fillOpacity:.12}).addTo(EMP_MAP);
  cks.forEach(function(ck){
    if(!isFinite(ck.lat)||!isFinite(ck.lon))return;
    var col=(ck.tipo==='entrada')?'#4CAF50':'#E53935';
    L.circleMarker([ck.lat,ck.lon],{radius:7,color:col,weight:1.5,fillColor:col,fillOpacity:.85}).addTo(EMP_MAP).bindPopup('<strong>'+(ck.nombre||('Usuario '+ck.usuario_id))+'</strong><br>'+(ck.tipo==='entrada'?'Entrada':'Salida')+'<br>'+fmtFechaHora(ck.created_at));
  });
  setTimeout(function(){try{EMP_MAP.invalidateSize();}catch(e){}},60);
}
function nuevoEmpleado(){
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.6rem">Nuevo empleado</h3>'+
    '<label>Nombre completo</label><input id="neNom">'+
    '<label>Correo</label><input id="neMail" type="email" placeholder="nombre@marmolesaslan.com">'+
    '<label>Rol</label><select id="neRol"><option value="empleado">Empleado</option><option value="gerente">Gerente</option></select>'+
    '<div class="g2"><div><label>Cargo</label><input id="neCargo"></div><div><label>Área</label><input id="neArea"></div></div>'+
    '<label>Teléfono</label><input id="neTel">'+
    '<label style="text-transform:none;display:flex;align-items:center;gap:.5rem;margin-top:.7rem"><input type="checkbox" id="neGps" style="width:auto"> El empleado dio consentimiento de ubicación GPS</label>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="guardarEmpleado()">Crear acceso</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
}
async function guardarEmpleado(){
  var b={nombre:val('neNom'),email:val('neMail'),rol:val('neRol'),cargo:val('neCargo'),area:val('neArea'),telefono:val('neTel'),consentimiento_gps:document.getElementById('neGps').checked};
  if(!b.nombre||!b.email){toast('Falta nombre o correo');return;}
  var d=await api('/api/empleados',{method:'POST',body:JSON.stringify(b)});
  if(!d)return;
  if(!d.ok){toast(d.error||'No se pudo crear');return;}
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Acceso creado</h3><p>Comparte estos datos con el empleado. Deberá cambiar la contraseña en su primer ingreso.</p><p style="margin-top:.6rem">Correo: <strong>'+escAttr(b.email)+'</strong></p><p>Contraseña temporal: <strong style="color:var(--gold)">'+escAttr(d.data.password_temporal)+'</strong></p><div style="margin-top:.9rem"><button class="btn" onclick="closeModal();recargarEmpleados()">Listo</button></div>');
}
var GC_MAP=null,GC_MARK=null,GC_CIRC=null,GC_TMP=null;
function initGcMap(){
  if(typeof L==='undefined')return;
  if(GC_MAP){try{GC_MAP.remove();}catch(e){}GC_MAP=null;}
  var t=GC_TMP||{lat:19.37241,lon:-99.16830,rad:150};
  GC_MAP=L.map('gcMap').setView([t.lat,t.lon],15);
  L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap'}).addTo(GC_MAP);
  GC_MARK=L.marker([t.lat,t.lon]).addTo(GC_MAP);
  GC_CIRC=L.circle([t.lat,t.lon],{radius:t.rad,color:'#8B6D3F',weight:1.5,fillColor:'#8B6D3F',fillOpacity:.12}).addTo(GC_MAP);
  GC_MAP.on('click',function(ev){
    var la=ev.latlng.lat,lo=ev.latlng.lng;
    var eLa=document.getElementById('gcLat'),eLo=document.getElementById('gcLon');
    if(eLa)eLa.value=la.toFixed(6);if(eLo)eLo.value=lo.toFixed(6);
    gcDraw(la,lo);
  });
  setTimeout(function(){try{GC_MAP.invalidateSize();}catch(e){}},80);
}
function gcDraw(la,lo){
  if(!GC_MAP)return;
  var rad=parseFloat(val('gcRad'))||150;
  if(GC_MARK)GC_MARK.setLatLng([la,lo]);
  if(GC_CIRC){GC_CIRC.setLatLng([la,lo]);GC_CIRC.setRadius(rad);}
  try{GC_MAP.panTo([la,lo]);}catch(e){}
}
function gcSync(){
  var la=parseFloat(val('gcLat')),lo=parseFloat(val('gcLon'));
  if(isFinite(la)&&isFinite(lo))gcDraw(la,lo);
}
async function configGeocerca(){
  var d=await api('/api/geofencing'),g=(d&&d.ok)?d.data:null;
  var lat=(g&&isFinite(g.lat_centro))?g.lat_centro:19.37241;
  var lon=(g&&isFinite(g.lon_centro))?g.lon_centro:-99.16830;
  var rad=(g&&isFinite(g.radio_metros))?g.radio_metros:150;
  GC_TMP={lat:lat,lon:lon,rad:rad};
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.3rem">Geocerca del sitio</h3>'+
    '<p class="muted" style="font-size:.82rem;margin-bottom:.5rem">Toca el mapa para fijar el centro del sitio (o usa tu ubicación). El círculo dorado muestra el radio. Los registros fuera de la zona generan una alerta.</p>'+
    '<label>Nombre del sitio</label><input id="gcNom" value="'+escAttr(g&&g.nombre?g.nombre:'')+'">'+
    '<div id="gcMap" style="height:240px;border-radius:8px;overflow:hidden;background:var(--inset);margin:.5rem 0"></div>'+
    '<div class="g2"><div><label>Latitud</label><input id="gcLat" type="number" step="0.000001" value="'+lat.toFixed(6)+'" oninput="gcSync()"></div><div><label>Longitud</label><input id="gcLon" type="number" step="0.000001" value="'+lon.toFixed(6)+'" oninput="gcSync()"></div></div>'+
    '<label>Radio (metros)</label><input id="gcRad" type="number" value="'+rad+'" oninput="gcSync()">'+
    '<button class="btn sec block" style="margin-top:.5rem" onclick="ubicarmeGeocerca()">Usar mi ubicación actual</button>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="guardarGeocerca()">Guardar</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
  setTimeout(initGcMap,160);
}
function ubicarmeGeocerca(){
  if(!navigator.geolocation){toast('Sin GPS disponible');return;}
  toast('Obteniendo ubicación…');
  navigator.geolocation.getCurrentPosition(function(pos){
    var la=pos.coords.latitude,lo=pos.coords.longitude;
    var eLa=document.getElementById('gcLat'),eLo=document.getElementById('gcLon');
    if(eLa)eLa.value=la.toFixed(6);if(eLo)eLo.value=lo.toFixed(6);
    gcDraw(la,lo);
    toast('Ubicación tomada');
  },function(){toast('No se pudo ubicar');},{enableHighAccuracy:true,timeout:10000});
}
async function guardarGeocerca(){
  var b={nombre:val('gcNom')||'Sitio ASLAN',lat_centro:parseFloat(val('gcLat')),lon_centro:parseFloat(val('gcLon')),radio_metros:parseFloat(val('gcRad'))};
  if(!isFinite(b.lat_centro)||!isFinite(b.lon_centro)||!isFinite(b.radio_metros)){toast('Completa latitud, longitud y radio');return;}
  var d=await api('/api/geofencing',{method:'POST',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Geocerca guardada');go('empleados');}else if(d){toast(d.error||'Error');}
}
var EMP_SEL_NOMBRE='';
async function editarEmpleado(id){
  var d=await api('/api/empleados/'+id);if(!d||!d.ok){toast('No se pudo cargar');return;}
  var e=d.data.empleado;EMP_SEL_NOMBRE=e.nombre;
  function v(x){return (x===null||x===undefined)?'':x;}
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.5rem">'+escAttr(e.nombre)+'</h3>'+
    '<div class="g2"><div><label>Cargo</label><input id="edCargo" value="'+escAttr(v(e.cargo))+'"></div><div><label>Área</label><input id="edArea" value="'+escAttr(v(e.area))+'"></div></div>'+
    '<label>Teléfono</label><input id="edTel" value="'+escAttr(v(e.telefono))+'">'+
    '<div class="g2"><div><label>Rol</label><select id="edRol"><option value="empleado"'+(e.rol==='empleado'?' selected':'')+'>Empleado</option><option value="gerente"'+(e.rol==='gerente'?' selected':'')+'>Gerente</option><option value="admin"'+(e.rol==='admin'?' selected':'')+'>Admin</option></select></div><div><label>Estado</label><select id="edAct"><option value="1"'+(e.activo?' selected':'')+'>Activo</option><option value="0"'+(!e.activo?' selected':'')+'>Inactivo</option></select></div></div>'+
    '<div class="g2"><div><label>CURP</label><input id="edCurp" value="'+escAttr(v(e.curp))+'"></div><div><label>RFC</label><input id="edRfc" value="'+escAttr(v(e.rfc))+'"></div></div>'+
    '<div class="g2"><div><label>Fecha de ingreso</label><input id="edIng" type="date" value="'+escAttr(v(e.fecha_ingreso))+'"></div><div><label>Tipo de contrato</label><input id="edCon" value="'+escAttr(v(e.tipo_contrato))+'"></div></div>'+
    '<label style="text-transform:none;display:flex;align-items:center;gap:.5rem;margin-top:.7rem"><input type="checkbox" id="edGps" style="width:auto"'+(e.consentimiento_gps?' checked':'')+'> Consentimiento de ubicación GPS</label>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem;flex-wrap:wrap"><button class="btn" onclick="guardarEmpleadoEdit('+id+')">Guardar</button><button class="btn sec" onclick="closeModal()">Cancelar</button>'+((USER.rol==='admin'&&USER.id!==id)?'<button class="btn" style="background:#7a1f1f;border-color:#7a1f1f;color:#fff;margin-left:auto" onclick="eliminarEmpleado('+id+')">Eliminar empleado</button>':'')+'</div>');
}
async function guardarEmpleadoEdit(id){
  var b={cargo:val('edCargo'),area:val('edArea'),telefono:val('edTel'),rol:val('edRol'),activo:val('edAct')==='1',curp:val('edCurp'),rfc:val('edRfc'),fecha_ingreso:val('edIng'),tipo_contrato:val('edCon'),consentimiento_gps:document.getElementById('edGps').checked};
  var d=await api('/api/empleados/'+id,{method:'PUT',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Guardado');go('empleados');}else if(d){toast(d.error||'Error');}
}
async function eliminarEmpleado(id){
  if(USER.rol!=='admin'){toast('Solo administracion puede eliminar empleados');return;}
  if(USER.id===id){toast('No puedes eliminar tu propia cuenta');return;}
  var nom=EMP_SEL_NOMBRE||'este empleado';
  if(!confirm('Vas a eliminar a '+nom+' del sistema. Ya no podra iniciar sesion ni aparecera en la lista de empleados. Continuar?'))return;
  var d=await api('/api/empleados/'+id,{method:'DELETE'});
  if(!d)return;
  if(d.ok){closeModal();toast('Empleado eliminado');go('empleados');}else{toast(d.error||'No se pudo eliminar');}
}
async function revisarAlertaUI(id){
  var d=await api('/api/geofencing/alertas/'+id+'/revisar',{method:'POST'});
  if(d&&d.ok){toast('Alerta revisada');go('empleados');}
}
var DASH_CHARTS=[];
function dashPaleta(){return ['#8B6D3F','#A07D4A','#C49A6C','#6E5630','#B98C4F','#D8B98C','#7D6B4A','#9A7B4F'];}
function mesCorto(ym){try{var p=ym.split('-');var d=new Date(parseInt(p[0]),parseInt(p[1])-1,1);return d.toLocaleDateString('es-MX',{month:'short'})+' '+p[0].slice(2);}catch(e){return ym;}}
function diaCorto(s){try{var d=new Date(s+'T00:00:00');return d.toLocaleDateString('es-MX',{day:'2-digit',month:'short'});}catch(e){return s;}}
function ultimosMeses(n){var a=[],d=new Date();for(var i=n-1;i>=0;i--){var x=new Date(d.getFullYear(),d.getMonth()-i,1);a.push(x.getFullYear()+'-'+('0'+(x.getMonth()+1)).slice(-2));}return a;}
function ultimosDias(n){var a=[],d=new Date();for(var i=n-1;i>=0;i--){var x=new Date(d.getFullYear(),d.getMonth(),d.getDate()-i);a.push(x.getFullYear()+'-'+('0'+(x.getMonth()+1)).slice(-2)+'-'+('0'+x.getDate()).slice(-2));}return a;}
function abreviaMonto(v){return '$'+(v>=1000?((v/1000).toFixed(v>=10000?0:1)+'k'):v);}
function destruirCharts(){DASH_CHARTS.forEach(function(ch){try{ch.destroy();}catch(e){}});DASH_CHARTS=[];}
function mkChart(id,cfg){var el=document.getElementById(id);if(!el||typeof Chart==='undefined')return;try{DASH_CHARTS.push(new Chart(el,cfg));}catch(e){}}
function chartCard(titulo,id){return '<div class="card"><h3 style="color:var(--gold);font-size:1.05rem;margin-bottom:.6rem">'+titulo+'</h3><div style="position:relative;height:240px"><canvas id="'+id+'"></canvas></div></div>';}
function initDashCharts(cd){
  if(typeof Chart==='undefined')return;
  Chart.defaults.color='#6B6256';Chart.defaults.borderColor='rgba(0,0,0,.09)';
  try{Chart.defaults.font.family="Montserrat, system-ui, sans-serif";}catch(e){}
  var pal=dashPaleta();
  var meses=ultimosMeses(6),mapC={};(cd.cotiz_por_mes||[]).forEach(function(r){mapC[r.mes]=r.monto;});
  mkChart('chCotiz',{type:'bar',data:{labels:meses.map(mesCorto),datasets:[{label:'Monto cotizado',data:meses.map(function(m){return mapC[m]||0;}),backgroundColor:'#8B6D3F',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return money(ctx.parsed.y);}}}},scales:{y:{ticks:{callback:function(v){return abreviaMonto(v);}}}}}});
  var pe=cd.proyectos_por_etapa||[];
  mkChart('chProy',{type:'doughnut',data:{labels:pe.map(function(r){return r.nombre;}),datasets:[{data:pe.map(function(r){return r.n;}),backgroundColor:pal,borderColor:'#FFFFFF',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{boxWidth:12,font:{size:11}}}}}});
  var ce=cd.clientes_por_etapa||[];
  mkChart('chCli',{type:'bar',data:{labels:ce.map(function(r){var s=r.etapa||'';return s.charAt(0).toUpperCase()+s.slice(1);}),datasets:[{label:'Clientes',data:ce.map(function(r){return r.n;}),backgroundColor:'#A07D4A',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{ticks:{precision:0}}}}});
  var ic=cd.inventario_por_categoria||[];
  mkChart('chInv',{type:'bar',data:{labels:ic.map(function(r){return r.categoria;}),datasets:[{label:'Valor',data:ic.map(function(r){return r.valor;}),backgroundColor:'#C49A6C',borderRadius:4}]},options:{indexAxis:'y',responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return money(ctx.parsed.x);}}}},scales:{x:{ticks:{callback:function(v){return abreviaMonto(v);}}}}}});
  var dias=ultimosDias(7),mapA={};(cd.asistencia_7d||[]).forEach(function(r){mapA[r.dia]=r.n;});
  mkChart('chAsis',{type:'line',data:{labels:dias.map(diaCorto),datasets:[{label:'Entradas',data:dias.map(function(x){return mapA[x]||0;}),borderColor:'#8B6D3F',backgroundColor:'rgba(139,109,63,.18)',fill:true,tension:.3,pointBackgroundColor:'#A07D4A'}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{y:{ticks:{precision:0}}}}});
}
async function viewDashboard(c){
  var d=await api('/api/dashboard/stats');if(!d||!d.ok)return;
  var cdR=await api('/api/dashboard/charts');var cd=(cdR&&cdR.ok)?cdR.data:{};
  var k=d.data.kpis;
  var kpis=[['Clientes activos',k.clientes,'clientes'],['Cotizaciones (mes)',k.cotizMes,'cotizaciones'],['Proyectos en curso',k.proyectos,'proyectos'],['Empleados hoy',k.empleadosHoy,'empleados'],['Pipeline',money(k.pipeline),'cotizaciones'],['Stock crítico',k.stockCritico,'inventario']];
  var h='<div class="kpis">';
  kpis.forEach(function(x){h+='<div class="card kpi kpi-click" data-mod="'+x[2]+'" onclick="go(this.dataset.mod)" title="Ir a '+x[0]+'"><div class="n">'+x[1]+'</div><div class="l">'+x[0]+'</div></div>';});
  h+='</div>';
  h+='<div class="card al-sec" id="dashAlertas"><h3 class="serif" style="color:var(--gold);font-size:1.15rem">Alertas de leads (CRM)</h3><p class="muted" style="font-size:.8rem;margin-top:.4rem">Cargando alertas…</p></div>';
  h+='<div class="charts-grid">'+chartCard('Monto cotizado por mes','chCotiz')+chartCard('Proyectos por etapa','chProy')+chartCard('Pipeline de clientes','chCli')+chartCard('Valor de inventario por categoría','chInv')+chartCard('Asistencia · entradas (7 días)','chAsis')+'</div>';
  h+='<div class="card" style="overflow-x:auto"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Cotizaciones recientes</h3><table><thead><tr><th>Folio</th><th>Cliente</th><th>Total</th><th>Estado</th></tr></thead><tbody>';
  (d.data.recientes||[]).forEach(function(r){h+='<tr><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+money(r.total)+'</td><td>'+estadoPill(r.estado)+'</td></tr>';});
  if(!d.data.recientes.length)h+='<tr><td colspan="4" class="muted">Sin cotizaciones aún.</td></tr>';
  h+='</tbody></table></div>';
  destruirCharts();
  c.innerHTML=h;
  setTimeout(function(){initDashCharts(cd);},40);
  pintarAlertasDash();
}
function estadoPill(e){
  var map={aceptada:'var(--ok)',enviada:'var(--gold)',borrador:'#666',rechazada:'var(--err)',expirada:'#888'};
  return '<span class="pill" style="background:'+(map[e]||'#666')+'">'+(e||'—')+'</span>';
}

var CRM_ROWS=[];
function fFecha(s){if(!s)return '';s=(''+s).trim();var m=/^([0-9]{4})-([0-9]{2})-([0-9]{2})/.exec(s);return m?m[3]+'-'+m[2]+'-'+m[1]:s;}
function fFechaISO(s){if(!s)return '';s=(''+s).trim();if(/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(s))return s;var m=/^([0-9]{1,2})[-/]([0-9]{1,2})[-/]([0-9]{4})$/.exec(s);if(!m)return s;var d=('0'+m[1]).slice(-2),mo=('0'+m[2]).slice(-2);return m[3]+'-'+mo+'-'+d;}
function crmCell(r,campo,val,num,ex){
  return '<td tabindex="-1" class="crmc'+(num?' crmnum':'')+(ex?' '+ex:'')+'" data-id="'+r.id+'" data-campo="'+campo+'" data-num="'+(num?1:0)+'" onclick="xlsSel(this)" ondblclick="xlsEditStart(this)">'+escAttr(val==null?'':String(val))+'</td>';
}
function celdasExtraCRM(r){
  var h='';
  for(var i=0;i<CRM_COLS.length;i++)h+=crmCell(r,CRM_COLS[i].c,r[CRM_COLS[i].c]);
  return h;
}
function crmCellNombre(r,ex){
  return '<td tabindex="-1" class="crmc crmlink'+(ex?' '+ex:'')+'" data-id="'+r.id+'" data-campo="nombre" data-num="0" data-noed="1" title="Clic para abrir la ficha del lead. Clic derecho para el cardex." oncontextmenu="return cardexLead(event,'+r.id+')" onclick="abrirFicha('+r.id+')">'+escAttr(r.nombre==null?'':String(r.nombre))+'</td>';
}
function celdaBloqueada(td){return !!(td&&td.dataset&&td.dataset.noed==='1');}
// ---- Campos que NO se escriben a mano: solo se eligen de una lista ----
var CRM_CAT={estatus_final:1,asesor:1,estatus_nota:1,validacion:1,probabilidad_cierre:1};
var CRM_CAT_INLINE={estatus_final:1,estatus_nota:1,validacion:1,probabilidad_cierre:1};
var CAT_NOTA_DEF=['SEGUIMIENTO','SIN RESPUESTA','PRECIO','MATERIAL','PROVEEDOR','PRESUPUESTO','EXISTENCIA','TIEMPO DE ENTREGA','VISITA','CONTACTAR','STAND BY','OTRO'];
var CAT_FINAL_DEF=['VIABLE','NV'];
function catCFG(k){
  var v=(CFG&&CFG[k])?CFG[k]:null;
  if(!v)return null;
  if(typeof v==='string'){try{v=JSON.parse(v);}catch(e){return null;}}
  return (v&&typeof v.length==='number'&&v.length)?v:null;
}
// Opciones validas de un campo. Siempre incluye el valor que ya trae el registro
// para no perder lo capturado antes de que existieran las listas.
function crmOpciones(campo,actual){
  var base=[];
  if(campo==='estatus_nota')base=catCFG('cat_estatus_nota')||CAT_NOTA_DEF;
  else if(campo==='estatus_final')base=catCFG('cat_estatus_final')||CAT_FINAL_DEF;
  else if(campo==='validacion')base=['VIABLE','NV'];
  else if(campo==='probabilidad_cierre')base=CAT_GESTION;
  else if(campo==='asesor')base=catCFG('cat_asesores')||[];
  var seen={},out=[],i,x;
  for(i=0;i<base.length;i++){x=String(base[i]==null?'':base[i]).trim();if(x&&!seen[x.toUpperCase()]){seen[x.toUpperCase()]=1;out.push(x);}}
  if(campo==='asesor'&&!out.length){
    (typeof CRM_ROWS!=='undefined'?(CRM_ROWS||[]):[]).forEach(function(r){
      var a=String(r.asesor==null?'':r.asesor).trim();
      if(a&&a.length<=40&&!seen[a.toUpperCase()]){seen[a.toUpperCase()]=1;out.push(a);}
    });
    out.sort();
  }
  var v=String(actual==null?'':actual).trim();
  if(v&&!seen[v.toUpperCase()]){out.push(v);seen[v.toUpperCase()]=1;}
  return out;
}
function crmCellSel(r,campo,val,ex){
  if(CRM_CAT_INLINE[campo]){
    var actual=(val==null?'':String(val)).trim(),ops=crmOpciones(campo,actual),i,h='<select class="crmsel" onchange="crmSelInline(this)" onmousedown="event.stopPropagation()" onclick="event.stopPropagation()"><option value="">(sin dato)</option>';
    for(i=0;i<ops.length;i++)h+='<option'+(ops[i].toUpperCase()===actual.toUpperCase()?' selected':'')+'>'+escT(ops[i])+'</option>';
    return '<td tabindex="-1" class="crmc crmcat crmcatsel'+(ex?' '+ex:'')+'" data-id="'+r.id+'" data-campo="'+campo+'" data-num="0" data-cat="2" title="Elige de la lista y se guarda al instante" onclick="xlsSel(this)">'+h+'</select></td>';
  }
  return '<td tabindex="-1" class="crmc crmcat'+(ex?' '+ex:'')+'" data-id="'+r.id+'" data-campo="'+campo+'" data-num="0" data-cat="1" title="Doble clic para elegir de la lista" onclick="xlsSel(this)" ondblclick="xlsEditStart(this)">'+escAttr(val==null?'':String(val))+'</td>';
}
async function crmSelInline(sel){
  var td=sel.parentNode;if(!td||!td.dataset)return;
  var id=td.dataset.id,campo=td.dataset.campo,v=String(sel.value||'').trim();
  var body={};body[campo]=v;
  var d=await api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)});
  if(d&&d.ok){
    var row=CRM_ROWS.find(function(x){return String(x.id)===String(id);});
    if(row)row[campo]=v;
    toast('Guardado');
    if(campo==='estatus_final'||campo==='estatus_nota')pintarFiltros();
  }else if(d){toast(d.error||'Error al guardar');}
}
function crmSelStart(td){
  if(!td||td._sel)return;
  if(td.dataset&&td.dataset.cat==='2'){var ps=td.querySelector('select.crmsel');if(ps){try{ps.focus();}catch(e){}}return;}
  var campo=td.dataset.campo,actual=(td.textContent||'').trim();
  var ops=crmOpciones(campo,actual),i;
  var h='<select><option value="">(sin dato)</option>';
  for(i=0;i<ops.length;i++)h+='<option'+(ops[i].toUpperCase()===actual.toUpperCase()?' selected':'')+'>'+escT(ops[i])+'</option>';
  td._orig=actual;td._sel=1;td.classList.add('selopen');td.innerHTML=h+'</select>';
  var sel=td.querySelector('select');
  if(!sel){crmSelCerrar(td,actual);return;}
  sel.onchange=function(){crmSelCerrar(td,sel.value);};
  sel.onblur=function(){if(td._sel)crmSelCerrar(td,td._orig);};
  sel.onkeydown=function(ev){if(ev.key==='Escape'){ev.preventDefault();crmSelCerrar(td,td._orig);}};
  try{sel.focus();}catch(e){}
}
function crmSelCerrar(td,valor){
  if(!td||!td._sel)return;
  var previo=td._orig;
  td._sel=0;td.classList.remove('selopen');
  td.textContent=(valor==null?'':String(valor));
  if(String(valor||'')!==String(previo||''))guardarCeldaCRM(td);
  try{td.focus({preventScroll:true});}catch(e){}
}
function crmCellWide(r,campo,val,ex){
  return '<td tabindex="-1" class="crmc crmwide'+(ex?' '+ex:'')+'" data-id="'+r.id+'" data-campo="'+campo+'" data-num="0" onclick="xlsSel(this)" ondblclick="xlsEditStart(this)">'+escAttr(val==null?'':String(val))+'</td>';
}
var CRM_VISTA='tabla';
var CRM_ESTATUS=['SIN RESPUESTA','SEGUIMIENTO','PRECIO','MATERIAL','OTRO'];
// ===== MODULO ALERTAS (gestion de leads por estatus y fechas programadas) =====
var ALERTA_ROWS=[];
function diasDesde(ts){if(!ts)return null;var s=(''+ts).trim();if(s.indexOf('T')<0)s=s.replace(' ','T');if(s.indexOf('Z')<0&&s.indexOf('+')<0)s+='Z';var t=Date.parse(s);if(isNaN(t))return null;var d=Math.floor((Date.now()-t)/86400000);return d<0?0:d;}
function fechaProg(v){if(!v)return null;var s=(''+v).trim().slice(0,10);var p=s.split('-');if(p.length!==3)return null;var d=new Date(Number(p[0]),Number(p[1])-1,Number(p[2]));return isNaN(d.getTime())?null:d;}
function calcAlertas(rows){
  var r={fechas:[],seg:[],sinresp:[],alarmas:0,avisos:0};
  var hoy=new Date();var hoy0=new Date(hoy.getFullYear(),hoy.getMonth(),hoy.getDate()).getTime();
  (rows||[]).forEach(function(c){
    if(c.deleted_at)return;
    var fin=(''+(c.estatus_final||'')).trim().toUpperCase();if(fin==='NV')return;
    if((''+(c.etapa||'')).trim().toLowerCase()==='cliente')return;
    var est=(''+(c.estatus_nota||'')).trim().toUpperCase();
    var dias=diasDesde(c.updated_at);if(dias===null)dias=diasDesde(c.created_at);if(dias===null)dias=0;
    var fp=fechaProg(c.proximo_seguimiento);
    if(fp){
      var df=Math.round((fp.getTime()-hoy0)/86400000);
      if(df===0)r.fechas.push({c:c,nivel:'alarma',txt:'Programado para HOY',fecha:1});
      else if(df<0)r.fechas.push({c:c,nivel:'alarma',txt:'Vencido hace '+(-df)+(df===-1?' día':' días'),fecha:1});
      else if(df<=3)r.fechas.push({c:c,nivel:'aviso',txt:'Programado en '+df+(df===1?' día':' días'),fecha:1});
    }
    if(est==='SEGUIMIENTO'){
      if(dias>=8)r.seg.push({c:c,nivel:'alarma',txt:dias+' días sin gestión (límite 8)'});
      else if(dias>=6)r.seg.push({c:c,nivel:'aviso',txt:dias+' días sin gestión (por vencer, límite 8)'});
    }else if(est==='SIN RESPUESTA'){
      if(dias>=2)r.sinresp.push({c:c,nivel:'alarma',txt:dias+' días sin gestión (límite 2)'});
      else if(dias>=1)r.sinresp.push({c:c,nivel:'aviso',txt:'1 día sin gestión (por vencer, límite 2)'});
    }
  });
  [r.fechas,r.seg,r.sinresp].forEach(function(a){
    a.sort(function(x,y){return (x.nivel===y.nivel)?0:(x.nivel==='alarma'?-1:1);});
    a.forEach(function(i){if(i.nivel==='alarma')r.alarmas++;else r.avisos++;});
  });
  return r;
}
function alSec(titulo,sub,items){
  var h='<div class="card al-sec"><h3 class="serif" style="color:var(--gold);font-size:1.15rem">'+titulo+' <span class="muted" style="font-size:.8rem">('+items.length+')</span></h3><p class="muted" style="font-size:.78rem;margin:.15rem 0 .7rem">'+sub+'</p>';
  if(!items.length){h+='<p class="muted" style="font-size:.82rem">Sin alertas en esta área.</p>';}
  else items.forEach(function(i){var c=i.c;
    h+='<div class="al-item '+i.nivel+'"><div style="min-width:0"><span class="al-tag '+i.nivel+'">'+(i.nivel==='alarma'?'Alarma':'Aviso')+'</span> <strong>'+escAttr(c.nombre||'—')+'</strong>'+(c.empresa?(' · '+escAttr(c.empresa)):'')+
      '<div class="muted" style="font-size:.76rem;margin-top:.15rem">'+escAttr(i.txt)+(c.asesor?(' · '+escAttr(c.asesor)):'')+(c.propuesta_antes_iva?(' · '+money(c.propuesta_antes_iva)):'')+'</div></div>'+
      '<div style="display:flex;gap:.35rem;flex-shrink:0"><button class="btn sec" style="padding:.28rem .55rem;font-size:.72rem" onclick="abrirFicha('+c.id+')" title="Abrir ficha 360">Ficha</button><button class="btn" style="padding:.28rem .55rem;font-size:.72rem" onclick="alertaAtendida('+c.id+','+(i.fecha?1:0)+')" title="Registrar gestión de hoy">Atendido</button></div></div>';
  });
  return h+'</div>';
}
function pintarAlertas(){
  var cont=document.getElementById('content');if(!cont)return;
  var r=calcAlertas(ALERTA_ROWS);
  var h='<div class="kpis" style="margin-bottom:1rem">'+
    '<div class="kpi"><div class="n" style="color:#d9534f">'+r.alarmas+'</div><div class="l">Alarmas</div></div>'+
    '<div class="kpi"><div class="n" style="color:#c4983a">'+r.avisos+'</div><div class="l">Avisos</div></div>'+
    '<div class="kpi"><div class="n">'+(r.alarmas+r.avisos)+'</div><div class="l">Total por gestionar</div></div></div>';
  h+=alSec('Fechas programadas','Leads con próximo seguimiento agendado: alarma el día programado o ya vencido; aviso 3 días antes.',r.fechas);
  h+=alSec('En seguimiento','Estatus SEGUIMIENTO: alarma a los 8 días sin gestión; aviso desde el día 6.',r.seg);
  h+=alSec('Sin respuesta','Estatus SIN RESPUESTA: alarma a los 2 días sin gestión; aviso al día 1.',r.sinresp);
  cont.innerHTML=h;
  actualizarBadgeAlertas(r);
}
async function viewAlertas(c){
  document.getElementById('acciones').innerHTML='<button class="btn sec" onclick="refrescarAlertas()">Actualizar</button>';
  var cont=document.getElementById('content');cont.innerHTML='Cargando…';
  var d=await api('/api/clientes');if(!d||!d.ok)return;
  ALERTA_ROWS=d.data;
  pintarAlertas();
}
function refrescarAlertas(){go('alertas');}
async function alertaAtendida(id,limpiarFecha){
  var row=null;ALERTA_ROWS.forEach(function(x){if(x.id===id)row=x;});
  var body={};
  if(limpiarFecha)body.proximo_seguimiento='';
  else if(row)body.estatus_nota=row.estatus_nota||'';
  if(!Object.keys(body).length){toast('No se pudo registrar');return;}
  var d=await api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)});
  if(d&&d.ok){
    toast('Gestión registrada');
    if(row){row.updated_at=new Date().toISOString();if(limpiarFecha)row.proximo_seguimiento='';}
    pintarAlertas();
  }else toast('No se pudo registrar');
}
function actualizarBadgeAlertas(r){var b=document.getElementById('alertBadge');if(!b)return;var n=r.alarmas+r.avisos;if(n>0){b.textContent=n;b.style.display='';}else{b.style.display='none';}}
function irAlertas(){go('alertas');}
async function pintarAlertasDash(){
  var d=await api('/api/clientes');if(!d||!d.ok)return;
  var box=document.getElementById('dashAlertas');if(!box)return;
  ALERTA_ROWS=d.data;
  var r=calcAlertas(ALERTA_ROWS);
  actualizarBadgeAlertas(r);
  var todos=r.fechas.concat(r.seg,r.sinresp,r.noviable);
  todos.sort(function(x,y){return (x.nivel===y.nivel)?0:(x.nivel==='alarma'?-1:1);});
  var h='<div style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;flex-wrap:wrap"><h3 class="serif" style="color:var(--gold);font-size:1.15rem">Alertas de leads (CRM)</h3><button class="btn sec" style="padding:.3rem .7rem;font-size:.74rem" onclick="irAlertas()">Ver todas</button></div>';
  h+='<div style="display:flex;gap:1.4rem;margin:.5rem 0 .7rem;font-size:.85rem;flex-wrap:wrap"><span><strong style="color:#d9534f;font-size:1.05rem">'+r.alarmas+'</strong> <span class="muted">alarmas</span></span><span><strong style="color:#c4983a;font-size:1.05rem">'+r.avisos+'</strong> <span class="muted">avisos</span></span><span><strong style="font-size:1.05rem">'+(r.alarmas+r.avisos)+'</strong> <span class="muted">por gestionar</span></span></div>';
  if(!todos.length){h+='<p class="muted" style="font-size:.82rem">Sin leads pendientes de gestión. Todo al día.</p>';}
  else{
    todos.slice(0,6).forEach(function(i){var c=i.c;
      h+='<div class="al-item '+i.nivel+'" style="cursor:pointer" onclick="abrirFicha('+c.id+')" title="Abrir ficha 360"><div style="min-width:0"><span class="al-tag '+i.nivel+'">'+(i.nivel==='alarma'?'Alarma':'Aviso')+'</span> <strong>'+escAttr(c.nombre||'—')+'</strong>'+(c.empresa?(' · '+escAttr(c.empresa)):'')+'<div class="muted" style="font-size:.76rem;margin-top:.15rem">'+escAttr(i.txt)+(c.asesor?(' · '+escAttr(c.asesor)):'')+'</div></div></div>';
    });
    if(todos.length>6)h+='<p class="muted" style="font-size:.78rem;margin-top:.3rem">Y '+(todos.length-6)+' más en el área de Alertas.</p>';
  }
  box.innerHTML=h;
}
async function refrescarBadgeAlertas(){try{var d=await api('/api/clientes');if(d&&d.ok){var r=calcAlertas(d.data);actualizarBadgeAlertas(r);avisoSeguimientosHoy(r);}}catch(e){}}
function avisoSeguimientosHoy(r){
  var hoyA=0,venc=0;
  (r.fechas||[]).forEach(function(i){if(i.nivel!=='alarma')return;if(i.txt&&i.txt.indexOf('HOY')>=0)hoyA++;else venc++;});
  if(!hoyA&&!venc)return;
  var k='aviso_seg_'+hoyISO()+'_'+((typeof USER!=='undefined'&&USER&&USER.id)?USER.id:'');
  try{if(localStorage.getItem(k))return;localStorage.setItem(k,'1');}catch(e){}
  var txt='';
  if(hoyA)txt+=hoyA+(hoyA===1?' seguimiento programado para hoy':' seguimientos programados para hoy');
  if(venc)txt+=(txt?' y ':'')+venc+(venc===1?' seguimiento vencido':' seguimientos vencidos');
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Seguimientos pendientes</h3><p style="font-size:.92rem;line-height:1.5;margin-bottom:1.1rem">Tienes '+txt+'.</p><div style="display:flex;gap:.5rem"><button class="btn" onclick="irAlertasAviso()">Ver alertas</button><button class="btn sec" onclick="closeModal()">Después</button></div>');
}
function irAlertasAviso(){if(typeof closeModal==='function')closeModal();go('alertas');}

async function viewClientes(c){
  document.getElementById('acciones').innerHTML='';
  var cont=document.getElementById('content');
  cont.innerHTML='<div id="crmFiltros"></div><div id="crmResumen"></div><div id="crmBody">Cargando…</div>';
  var d=await api('/api/clientes');if(!d||!d.ok)return;
  CRM_ROWS=d.data;
  if(!CFG)await cargarCFG();
  cargarTitulosCRM();
  pintarFiltros();
  renderCRM();
}
function setVistaCRM(v){
  CRM_VISTA=v;
  var bt=document.getElementById('cvTabla'),bb=document.getElementById('cvTablero');
  if(bt)bt.className=(v==='tabla'?'btn':'btn sec');
  if(bb)bb.className=(v==='tablero'?'btn':'btn sec');
  renderCRM();
}
function valFil(id){var e=document.getElementById(id);return e?(''+e.value):'';}
function sumaDiasISO(iso,n){var p=iso.split('-');var d=new Date(Number(p[0]),Number(p[1])-1,Number(p[2])+n);return d.getFullYear()+'-'+('0'+(d.getMonth()+1)).slice(-2)+'-'+('0'+d.getDate()).slice(-2);}
var CRM_MESES_NOM=['enero','febrero','marzo','abril','mayo','junio','julio','agosto','septiembre','octubre','noviembre','diciembre'];
// Al elegir un mes sin año, el filtro mezclaba septiembre de todos los años.
// Ahora se ancla al año en curso y el año se puede abrir a mano si se quiere el historico.
function crmMesCambio(){
  var m=document.getElementById('fMes'),a=document.getElementById('fAnio');
  if(m&&a&&m.value&&!a.value){
    var y=String(new Date().getFullYear()),i;
    for(i=0;i<a.options.length;i++){
      if(a.options[i].value===y||a.options[i].text===y){a.selectedIndex=i;toast('Filtrando '+y+'. Cambia el año si necesitas otro.');break;}
    }
  }
  renderCRM();
}
function crmPeriodoTxt(){
  var a=valFil('fAnio'),m=valFil('fMes');
  if(!a&&!m)return '';
  var nm=m?CRM_MESES_NOM[parseInt(m,10)-1]:'';
  if(a&&m)return nm+' '+a;
  if(m)return nm+' de todos los años';
  return 'año '+a;
}
function filasCRMFiltradas(){
  var q=catKey(valFil('crmq'));
  var as=valFil('fAsesor'),es=valFil('fEstatus'),an=valFil('fAnio'),me=valFil('fMes'),fa=valFil('fFact'),ef=valFil('fEFin'),sg=valFil('fSeg');
  var hoyS=hoyISO(),lim7=sumaDiasISO(hoyS,7);
  var mn=parseFloat(valFil('fMin')),mx=parseFloat(valFil('fMax'));
  return CRM_ROWS.filter(function(r){
    if(q && catKey(JSON.stringify(r)).indexOf(q)<0)return false;
    if(sg){var ps=(r.proximo_seguimiento==null?'':String(r.proximo_seguimiento)).trim().slice(0,10);var okp=/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(ps);
      if(sg==='con'&&!okp)return false;
      if(sg==='sin'&&okp)return false;
      if(sg==='hoy'&&!(okp&&ps===hoyS))return false;
      if(sg==='venc'&&!(okp&&ps<hoyS))return false;
      if(sg==='prox'&&!(okp&&ps>=hoyS&&ps<=lim7))return false;}
    if(as && (r.asesor||'').trim()!==as)return false;
    if(es){var st=(r.estatus_nota||'').trim().toUpperCase();if(es==='__SIN__'){if(st!=='')return false;}else if(st!==es.toUpperCase())return false;}
    if(ef){var sf=(r.estatus_final||'').trim().toUpperCase();if(ef==='__SIN__'){if(sf!=='')return false;}else if(sf!==ef.toUpperCase())return false;}
    var fl=(r.fecha_lead||'');
    if(an && fl.slice(0,4)!==an)return false;
    if(me && fl.slice(5,7)!==me)return false;
    var fact=Number(r.facturado)||0;
    if(fa==='con' && !(fact>0))return false;
    if(fa==='sin' && fact>0)return false;
    var monto=(r.propuesta_antes_iva!=null)?(Number(r.propuesta_antes_iva)||0):0;
    if(!isNaN(mn) && monto<mn)return false;
    if(!isNaN(mx) && monto>mx)return false;
    return true;
  });
}
function renderCRM(){
  var rows=filasCRMFiltradas();
  pintarResumen(rows);
  if(CRM_VISTA==='tablero')pintarTableroCRM(rows);else pintarCRM(rows);
}
var CRM_TIT_DEF=['FECHA','ORIGEN','ESTATUS FINAL','ASESOR','ESTATUS/NOTA','PROP/FACT','COMPAÑÍA','CONTACTO','NOTAS VERO','NOTAS ACTUALIZACIÓN','SEGUIMIENTO','TELÉFONO','MAIL','MATERIAL','TIPO','ACABADO','FORMATO','CANTIDAD','PROP. S/IVA','MONEDA','FACTURADO','COTIZACIONES'];
var CRM_TIT_CAMPOS=['fecha_lead','origen','estatus_final','asesor','estatus_nota','probabilidad_cierre','empresa','nombre','notas_vero','notas_actualizacion','notas_seguimiento','telefono','email','material','tipo','acabado','formato','cantidad','propuesta_antes_iva','moneda','facturado'];
var CRM_KEYS=CRM_TIT_CAMPOS.concat(['__acc']);
var CRM_WIDE={notas_vero:1,notas_actualizacion:1,notas_seguimiento:1};
var CRM_NUM={propuesta_antes_iva:1,facturado:1};
var CRM_FECHAS={fecha_lead:1,fecha_contacto:1};
var CRM_TIT=CRM_TIT_DEF.slice();
var CRM_COLS=[];
var CRM_LAY=[];
var CRM_DRAG=-1;
var TIT_ORIG='';
function escT(v){return String(v==null?'':v).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function cargarColsCRM(){
  CRM_COLS=[];
  try{
    var raw=(CFG&&CFG.crm_cols)?CFG.crm_cols:'';
    if(!raw)return;
    var a=JSON.parse(raw);
    if(!a||typeof a.length!=='number')return;
    for(var i=0;i<a.length;i++){
      if(a[i]&&typeof a[i].c==='string'&&/^col_[a-z0-9_]{1,24}$/.test(a[i].c))CRM_COLS.push({c:a[i].c,t:String(a[i].t||a[i].c)});
    }
  }catch(e){CRM_COLS=[];}
}
function layPropia(k){return /^col_/.test(String(k));}
function layBase(){
  var a=[];
  for(var i=0;i<CRM_KEYS.length;i++)a.push({k:CRM_KEYS[i],t:CRM_TIT_DEF[i],v:1,f:0});
  for(var j=0;j<CRM_COLS.length;j++)a.push({k:CRM_COLS[j].c,t:CRM_COLS[j].t,v:1,f:0});
  return a;
}
function layIdx(k){for(var i=0;i<CRM_LAY.length;i++)if(CRM_LAY[i].k===k)return i;return -1;}
function layVisibles(){var n=0;for(var i=0;i<CRM_LAY.length;i++)if(CRM_LAY[i].v!==0)n++;return n;}
function layOrden(){
  var fj=[],rs=[];
  for(var i=0;i<CRM_LAY.length;i++){
    if(CRM_LAY[i].v===0)continue;
    if(CRM_LAY[i].f===1)fj.push(i);else rs.push(i);
  }
  return fj.concat(rs);
}
function cargarTitulosCRM(){
  cargarColsCRM();
  var base=layBase(),mapa={},usado={};
  base.forEach(function(x){mapa[x.k]=x;});
  try{
    var rt=(CFG&&CFG.crm_titulos)?CFG.crm_titulos:'';
    if(rt){
      var t=JSON.parse(rt);
      if(t&&typeof t.length==='number'){
        for(var i=0;i<CRM_KEYS.length&&i<t.length;i++){
          var vv=(t[i]==null)?'':String(t[i]).replace(/[<>]/g,'').trim();
          if(vv)mapa[CRM_KEYS[i]].t=vv;
        }
      }
    }
  }catch(e){}
  var out=[];
  try{
    var rl=(CFG&&CFG.crm_layout)?CFG.crm_layout:'';
    if(rl){
      var L=JSON.parse(rl);
      if(L&&typeof L.length==='number'){
        for(var j=0;j<L.length;j++){
          var e=L[j];
          if(!e||typeof e.k!=='string')continue;
          if(e.k==='propuesta_factura')e.k='probabilidad_cierre';
          var b=mapa[e.k];
          if(!b||usado[e.k])continue;
          usado[e.k]=1;
          var tt=(e.t==null)?b.t:String(e.t).replace(/[<>]/g,'').trim();
          out.push({k:e.k,t:tt||b.t,v:(e.v===0?0:1),f:(e.f===1?1:0)});
        }
      }
    }
  }catch(e){out=[];usado={};}
  base.forEach(function(x){if(!usado[x.k])out.push({k:x.k,t:x.t,v:1,f:0});});
  CRM_LAY=out;
  var ia=layIdx('__acc');
  if(ia<0){CRM_LAY.push({k:'__acc',t:'COTIZACIONES',v:1,f:0});}
  else CRM_LAY[ia].v=1;
  if(!layVisibles())CRM_LAY.forEach(function(x){x.v=1;});
  CRM_TIT=CRM_LAY.map(function(x){return x.t;});
}
function puedeTitulosCRM(){return USER&&(USER.rol==='admin'||USER.rol==='gerente');}
function thsCRM(){
  var ed=puedeTitulosCRM(),h='',ord=layOrden(),ult=-1;
  for(var p=0;p<ord.length;p++)if(CRM_LAY[ord[p]].f===1)ult=p;
  for(var n=0;n<ord.length;n++){
    var i=ord[n],x=CRM_LAY[i],cl=[];
    if(x.f===1){cl.push('fx');if(n===ult)cl.push('fxend');}
    if(x.k==='__acc')cl.push('crmact');
    if(ed)cl.push('thed');
    var at=ed?(' draggable="true" ondragstart="crmDragIni(event,'+n+')" ondragover="crmDragSobre(event)" ondrop="crmDragSuelta(event,'+n+')" ondragend="crmDragFin()" ondblclick="tituloCRMEdit('+i+')" title="Arrastra para moverla. Doble clic para renombrarla."'):(' title="'+escT(x.t)+'"');
    h+='<th data-ti="'+i+'"'+(cl.length?(' class="'+cl.join(' ')+'"'):'')+at+'>'+escT(x.t)+'</th>';
  }
  return h;
}
function tituloCRMEdit(i){
  if(!puedeTitulosCRM())return;
  var th=document.querySelector('.crmtable th[data-ti="'+i+'"]');if(!th)return;
  TIT_ORIG=th.textContent;
  th.setAttribute('draggable','false');
  th.contentEditable='true';th.classList.add('thedit');th.focus();
  try{var rg=document.createRange();rg.selectNodeContents(th);var sl=window.getSelection();sl.removeAllRanges();sl.addRange(rg);}catch(e){}
  th.onkeydown=function(ev){
    ev.stopPropagation();
    if(ev.key==='Enter'){ev.preventDefault();th.blur();}
    else if(ev.key==='Escape'){ev.preventDefault();th.textContent=TIT_ORIG;th.blur();}
  };
  th.onblur=function(){tituloCRMFin(i,th);};
}
function tituloCRMFin(i,th){
  th.onblur=null;th.onkeydown=null;th.contentEditable='false';th.classList.remove('thedit');th.setAttribute('draggable','true');
  var x=CRM_LAY[i];if(!x)return;
  var v=(th.textContent||'').replace(/[<>]/g,'').trim();
  if(!v){var d=CRM_KEYS.indexOf(x.k);v=(d>=0?CRM_TIT_DEF[d]:x.t);}
  th.textContent=v;
  if(v===x.t)return;
  x.t=v;
  guardarLayoutCRM('Título de columna actualizado');
}
function layPayload(){
  return CRM_LAY.map(function(x){return {k:x.k,t:x.t,v:(x.v===0?0:1),f:(x.f===1?1:0)};});
}
async function guardarLayoutCRM(aviso){
  CRM_TIT=CRM_LAY.map(function(x){return x.t;});
  renderCRM();
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({crm_layout:JSON.stringify(layPayload())})});
  if(d&&d.ok){CFG=d.data;if(aviso)toast(aviso);}
  else{toast((d&&d.error)||'No se pudieron guardar las columnas');cargarTitulosCRM();renderCRM();}
}
async function restaurarTitulosCRM(){
  if(!puedeTitulosCRM()){toast('Sin permiso');return;}
  CRM_LAY=layBase();
  await guardarLayoutCRM('');
  if(document.getElementById('colManBody'))gestionColumnasCRM();
  toast('Columnas restauradas');
}
function crmDragIni(ev,pos){
  CRM_DRAG=pos;
  try{ev.dataTransfer.setData('text/plain',String(pos));ev.dataTransfer.effectAllowed='move';}catch(e){}
  if(ev&&ev.target&&ev.target.classList)ev.target.classList.add('drag');
}
function crmDragSobre(ev){if(ev&&ev.preventDefault)ev.preventDefault();if(ev&&ev.dataTransfer)try{ev.dataTransfer.dropEffect='move';}catch(e){}return false;}
function crmDragFin(){
  CRM_DRAG=-1;
  var ths=document.querySelectorAll('.crmtable th.drag');
  for(var i=0;i<ths.length;i++)ths[i].classList.remove('drag');
}
function crmDragSuelta(ev,pos){
  if(ev&&ev.preventDefault)ev.preventDefault();
  var d=CRM_DRAG;CRM_DRAG=-1;
  var ord=layOrden();
  if(d<0||d>=ord.length||pos<0||pos>=ord.length||d===pos)return false;
  var iFrom=ord[d],iTo=ord[pos];
  var mov=CRM_LAY[iFrom],dest=CRM_LAY[iTo];
  if(!mov||!dest)return false;
  var derecha=(iFrom<iTo);
  CRM_LAY.splice(CRM_LAY.indexOf(mov),1);
  var iD=CRM_LAY.indexOf(dest);
  CRM_LAY.splice(derecha?(iD+1):iD,0,mov);
  mov.f=dest.f;
  guardarLayoutCRM('');
  return false;
}
function colFijar(i){
  var x=CRM_LAY[i];if(!x)return;
  x.f=(x.f===1?0:1);
  guardarLayoutCRM('');gestionColumnasCRM();
}
function colVer(i){
  var x=CRM_LAY[i];if(!x)return;
  if(x.k==='__acc'){toast('La columna de acciones no se puede ocultar');return;}
  if(x.v!==0&&layVisibles()<=1){toast('Debe quedar al menos una columna visible');return;}
  x.v=(x.v===0?1:0);
  guardarLayoutCRM('');gestionColumnasCRM();
}
function colMover(i,d){
  var j=i+d;if(j<0||j>=CRM_LAY.length)return;
  var t=CRM_LAY[i];CRM_LAY[i]=CRM_LAY[j];CRM_LAY[j]=t;
  guardarLayoutCRM('');gestionColumnasCRM();
}
function colArriba(i){colMover(i,-1);}
function colAbajo(i){colMover(i,1);}
async function colEliminar(i){
  var x=CRM_LAY[i];if(!x)return;
  if(!layPropia(x.k)){toast('Solo se eliminan las columnas que tú creaste. Las de origen se pueden ocultar.');return;}
  var d=await api('/api/crm/columnas',{method:'POST',body:JSON.stringify({quitar:x.k})});
  if(!d||!d.ok){toast((d&&d.error)||'No se pudo eliminar la columna');return;}
  CRM_COLS=d.data||[];
  CRM_LAY.splice(i,1);
  await guardarLayoutCRM('');
  gestionColumnasCRM();
  toast('Columna eliminada');
}
function puedeBorrarCRM(){return typeof USER!=='undefined'&&USER&&(USER.rol==='admin'||USER.rol==='gerente');}
function crmAccBtns(r){
  return '<button class="btn" style="padding:.25rem .5rem;font-size:.72rem" onclick="abrirFicha('+r.id+')" title="Ficha 360 del cliente">Ficha</button> '+
    '<button class="btn sec" style="padding:.25rem .5rem;font-size:.72rem" onclick="verCotizacionesCliente('+r.id+')" title="Ver cotizaciones ligadas a este cliente">Cot. '+(r.num_cotizaciones||0)+'</button> '+
    '<button class="btn" style="padding:.25rem .5rem;font-size:.72rem" onclick="cotizarCliente('+r.id+')" title="Crear cotización para este cliente">+ Cotizar</button>'+
    (puedeBorrarCRM()?(' <button class="btn" style="padding:.25rem .5rem;font-size:.72rem;background:#7a1f1f;border-color:#7a1f1f;color:#fff" onclick="eliminarLead('+r.id+')" title="Eliminar este registro del CRM">Eliminar</button>'):'');
}
function nombreLead(id){
  for(var i=0;i<CRM_ROWS.length;i++)if(String(CRM_ROWS[i].id)===String(id))return CRM_ROWS[i].nombre||'';
  return '';
}
function eliminarLead(id){
  if(!puedeBorrarCRM()){toast('Solo administración o gerencia puede eliminar registros');return;}
  var nom=nombreLead(id);
  confirmModal('¿Eliminar el registro '+escT(nom)+'? Sale del CRM, de los reportes y del pipeline. Queda guardado en la base por si hay que recuperarlo.','Sí, eliminar',function(){_eliminarLead(id);});
}
async function _eliminarLead(id){
  var d=await api('/api/clientes/'+id,{method:'DELETE'});
  if(!d)return;
  if(d.ok){
    var q=[];
    for(var i=0;i<CRM_ROWS.length;i++)if(String(CRM_ROWS[i].id)!==String(id))q.push(CRM_ROWS[i]);
    CRM_ROWS=q;
    if(typeof closeModal==='function')closeModal();
    toast('Registro eliminado');
    renderCRM();
  }else{toast(d.error||'No se pudo eliminar');}
}
function crmCeldas(r,ord,ult){
  var h='';
  for(var n=0;n<ord.length;n++){
    var x=CRM_LAY[ord[n]],ex='';
    if(x.f===1){ex='fx';if(n===ult)ex='fx fxend';}
    if(x.k==='__acc'){
      h+='<td class="crmact'+(ex?' '+ex:'')+'" style="white-space:nowrap;text-align:center">'+crmAccBtns(r)+'</td>';
    }else if(x.k==='nombre'){
      h+=crmCellNombre(r,ex);
    }else if(CRM_CAT[x.k]){
      h+=crmCellSel(r,x.k,r[x.k],ex);
    }else if(CRM_WIDE[x.k]){
      h+=crmCellWide(r,x.k,r[x.k],ex);
    }else if(CRM_NUM[x.k]){
      h+=crmCell(r,x.k,(r[x.k]==null?'':money(r[x.k])),true,ex);
    }else if(CRM_FECHAS[x.k]){
      h+=crmCell(r,x.k,fFecha(r[x.k]),false,ex);
    }else{
      h+=crmCell(r,x.k,r[x.k],false,ex);
    }
  }
  return h;
}
function fijarColsCRM(){
  var t=document.querySelector('.crmtable');if(!t)return;
  var ths=t.querySelectorAll('thead th');
  var left=0;
  for(var i=0;i<ths.length;i++){
    if(!ths[i].classList.contains('fx'))continue;
    ths[i].style.left=left+'px';
    var tds=t.querySelectorAll('tbody tr > *:nth-child('+(i+1)+')');
    for(var j=0;j<tds.length;j++)tds[j].style.left=left+'px';
    left+=ths[i].offsetWidth;
  }
}
function pintarCRM(rows){
  var c=document.getElementById('crmBody')||document.getElementById('content');
  var ord=layOrden(),ult=-1;
  for(var p=0;p<ord.length;p++)if(CRM_LAY[ord[p]].f===1)ult=p;
  var ancho=Math.max(1100,ord.length*110);
  var h='<div class="card xls" tabindex="0" style="padding:.4rem"><table class="crmtable" style="min-width:'+ancho+'px"><thead><tr>'+
    thsCRM()+'</tr></thead><tbody>';
  rows.forEach(function(r){h+='<tr>'+crmCeldas(r,ord,ult)+'</tr>';});
  if(!rows.length)h+='<tr><td colspan="'+ord.length+'" class="muted">Sin registros. Crea el primero con «+ Nuevo registro».</td></tr>';
  h+='</tbody></table></div>';
  c.innerHTML=h;ajustarXls();fijarColsCRM();setTimeout(fijarColsCRM,120);
}
function filtrarCRM(){ renderCRM(); }
function xlsEditable(el){if(!el)return false;var t=(el.tagName||'').toLowerCase();return t==='input'||t==='textarea'||t==='select'||el.isContentEditable;}
var XLS_HOVER=null;function xlsPane(){var a=document.activeElement;if(a&&a.closest){var pf=a.closest('.xls');if(pf)return pf;}return XLS_HOVER;}
var XLS_CUR=null,XLS_EDIT=false,XLS_ORIG='';
function xlsSel(td){
  if(!td)return;
  if(XLS_EDIT&&XLS_CUR===td)return;
  if(XLS_EDIT&&XLS_CUR&&XLS_CUR!==td)xlsCommit();
  if(XLS_CUR===td&&!XLS_EDIT){xlsEditStart(td);return;}
  if(XLS_CUR&&XLS_CUR!==td)XLS_CUR.classList.remove('sel');
  XLS_CUR=td;td.classList.add('sel');
  try{td.focus({preventScroll:true});}catch(e){td.focus();}
  if(td.scrollIntoView)td.scrollIntoView({block:'nearest',inline:'nearest'});
}
function xlsEditStart(td,ch){
  if(!td)return;
  if(celdaBloqueada(td)){toast('El nombre se edita en la ficha o en el cardex (clic derecho)');return;}
  if(td.dataset&&(td.dataset.cat==='1'||td.dataset.cat==='2')){
    if(XLS_CUR!==td){if(XLS_CUR)XLS_CUR.classList.remove('sel');XLS_CUR=td;td.classList.add('sel');}
    crmSelStart(td);
    return;
  }
  if(XLS_CUR!==td){if(XLS_CUR)XLS_CUR.classList.remove('sel');XLS_CUR=td;td.classList.add('sel');}
  XLS_EDIT=true;XLS_ORIG=td.textContent;
  td.classList.add('edit');td.contentEditable='true';
  if(ch!=null)td.textContent=ch;
  td.focus();
  var rg=document.createRange();rg.selectNodeContents(td);rg.collapse(false);
  var sl=window.getSelection();sl.removeAllRanges();sl.addRange(rg);
  td.onblur=function(){if(XLS_EDIT&&XLS_CUR===td)xlsCommit();};
}
function xlsCommit(){
  var td=XLS_CUR;if(!td||!XLS_EDIT)return;
  XLS_EDIT=false;td.onblur=null;td.contentEditable='false';td.classList.remove('edit');
  if(td.textContent!==XLS_ORIG)guardarCeldaCRM(td);
}
function xlsCancel(){
  var td=XLS_CUR;if(!td)return;
  XLS_EDIT=false;td.onblur=null;td.contentEditable='false';td.classList.remove('edit');
  td.textContent=XLS_ORIG;
  try{td.focus({preventScroll:true});}catch(e){}
}
function xlsMove(dx,dy,edge){
  var td=XLS_CUR;if(!td)return;
  var tr=td.parentNode,i;
  if(dy){
    var t=tr;
    if(edge){for(;;){var nx=(dy>0)?t.nextElementSibling:t.previousElementSibling;if(!nx)break;t=nx;}}
    else{var n=Math.abs(dy);while(n-->0){var nx2=(dy>0)?t.nextElementSibling:t.previousElementSibling;if(!nx2)break;t=nx2;}}
    var cell=t.cells&&t.cells[td.cellIndex];
    if(cell&&cell.classList.contains('crmc'))xlsSel(cell);
    return;
  }
  if(dx){
    if(edge){
      var cells=tr.cells,target=null;
      if(dx<0){for(i=0;i<cells.length;i++){if(cells[i].classList.contains('crmc')){target=cells[i];break;}}}
      else{for(i=cells.length-1;i>=0;i--){if(cells[i].classList.contains('crmc')){target=cells[i];break;}}}
      if(target)xlsSel(target);
      return;
    }
    var nxt=(dx>0)?td.nextElementSibling:td.previousElementSibling;
    if(nxt&&nxt.classList.contains('crmc'))xlsSel(nxt);
  }
}
function xlsKey(e){
  var k=e.key;
  if(XLS_EDIT&&XLS_CUR){
    if(k==='Enter'){e.preventDefault();xlsCommit();xlsMove(0,1);}
    else if(k==='Tab'){e.preventDefault();xlsCommit();xlsMove(e.shiftKey?-1:1,0);}
    else if(k==='Escape'){e.preventDefault();xlsCancel();}
    return;
  }
  if(XLS_CUR&&document.body.contains(XLS_CUR)&&!xlsEditable(document.activeElement)){
    if(k==='ArrowDown'){e.preventDefault();xlsMove(0,1,e.ctrlKey);}
    else if(k==='ArrowUp'){e.preventDefault();xlsMove(0,-1,e.ctrlKey);}
    else if(k==='ArrowRight'){e.preventDefault();xlsMove(1,0,e.ctrlKey);}
    else if(k==='ArrowLeft'){e.preventDefault();xlsMove(-1,0,e.ctrlKey);}
    else if(k==='Tab'){e.preventDefault();xlsMove(e.shiftKey?-1:1,0);}
    else if(k==='PageDown'){e.preventDefault();xlsMove(0,12);}
    else if(k==='PageUp'){e.preventDefault();xlsMove(0,-12);}
    else if(k==='Home'){e.preventDefault();xlsMove(-1,0,true);}
    else if(k==='End'){e.preventDefault();xlsMove(1,0,true);}
    else if(k==='Enter'||k==='F2'){e.preventDefault();xlsEditStart(XLS_CUR);}
    else if(k==='Delete'||k==='Backspace'){e.preventDefault();if(celdaBloqueada(XLS_CUR)){toast('El nombre se edita en la ficha o en el cardex (clic derecho)');return;}var prev=XLS_CUR.textContent;XLS_CUR.textContent='';if(prev!=='')guardarCeldaCRM(XLS_CUR);}
    else if((e.ctrlKey||e.metaKey)&&(k==='c'||k==='C')){e.preventDefault();try{navigator.clipboard.writeText(XLS_CUR.textContent);toast('Copiado');}catch(err){}}
    else if((e.ctrlKey||e.metaKey)&&(k==='v'||k==='V')){e.preventDefault();try{navigator.clipboard.readText().then(function(tx){if(tx==null||!XLS_CUR)return;XLS_CUR.textContent=(''+tx).trim();guardarCeldaCRM(XLS_CUR);});}catch(err){}}
    else if(k.length===1&&!e.ctrlKey&&!e.metaKey&&!e.altKey){e.preventDefault();xlsEditStart(XLS_CUR,k);}
    return;
  }
  if(xlsEditable(document.activeElement))return;
  var p=xlsPane();if(!p)return;
  var dx=0,dy=0,V=Math.max(80,p.clientHeight-60);if(k==='ArrowLeft')dx=-140;else if(k==='ArrowRight')dx=140;else if(k==='ArrowUp')dy=-70;else if(k==='ArrowDown')dy=70;else if(k==='PageDown')dy=V;else if(k==='PageUp')dy=-V;else if(k==='Home'){p.scrollTo(0,p.scrollTop);e.preventDefault();return;}else if(k==='End'){p.scrollTo(p.scrollWidth,p.scrollTop);e.preventDefault();return;}else return;p.scrollBy(dx,dy);e.preventDefault();
}
function tcardCRM(r){
  var opts='<option value="">(Sin estatus)</option>';
  crmOpciones('estatus_nota',r.estatus_nota).forEach(function(s){opts+='<option value="'+escAttr(s)+'"'+(((r.estatus_nota||'').trim().toUpperCase()===s.toUpperCase())?' selected':'')+'>'+escT(s)+'</option>';});
  var monto=(r.propuesta_antes_iva!=null)?money(r.propuesta_antes_iva):((r.facturado!=null)?money(r.facturado):'');
  var sub=(r.empresa||r.material||'');
  return '<div class="tcard">'+
    '<div class="nm">'+escAttr(r.nombre||'—')+'</div>'+
    (sub?'<div class="mt">'+escAttr(sub)+'</div>':'')+
    '<div class="mt">'+(r.asesor?('Asesor: '+escAttr(r.asesor)):'Sin asesor')+(monto?(' · '+monto):'')+'</div>'+
    '<select onchange="cambiarEstatusCRM('+r.id+',this.value)">'+opts+'</select> '+
    '<button class="btn" style="padding:.18rem .45rem;font-size:.68rem;margin-top:.35rem" onclick="abrirFicha('+r.id+')" title="Ficha 360">Ficha</button> <button class="btn sec" style="padding:.18rem .45rem;font-size:.68rem;margin-top:.35rem" onclick="verCotizacionesCliente('+r.id+')" title="Cotizaciones del cliente">Cot. '+(r.num_cotizaciones||0)+'</button>'+
    '</div>';
}
function pintarTableroCRM(rows){
  var c=document.getElementById('crmBody')||document.getElementById('content');
  var cols=crmOpciones('estatus_nota','').concat(['(Sin estatus)']);
  var colsU={};cols.forEach(function(k){colsU[k.toUpperCase()]=k;});
  var color={'SIN RESPUESTA':'var(--err)','SEGUIMIENTO':'var(--gold)','PRECIO':'#5B8DEF','MATERIAL':'var(--ok)','OTRO':'#9C7BD6','(Sin estatus)':'#888'};
  var grupos={};cols.forEach(function(k){grupos[k]=[];});
  rows.forEach(function(r){var s=(r.estatus_nota||'').trim().toUpperCase();var key=colsU[s]||'(Sin estatus)';grupos[key].push(r);});
  var nota='<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Tablero por estatus: cambia el estatus en el menú de cada tarjeta y el cliente se reacomoda en su columna. Desliza horizontalmente para ver todas las columnas. Registros: '+rows.length+'.</p>';
  var h=nota+'<div class="tablero">';
  cols.forEach(function(k){
    var lista=grupos[k];
    h+='<div class="tcol"><h4 style="color:'+(color[k]||'var(--gold)')+'">'+k+'<span class="cnt">'+lista.length+'</span></h4>';
    if(!lista.length)h+='<p class="muted" style="font-size:.74rem;padding:.3rem">—</p>';
    lista.forEach(function(r){h+=tcardCRM(r);});
    h+='</div>';
  });
  h+='</div>';c.innerHTML=h;ajustarXls();
}
async function cambiarEstatusCRM(id,valor){
  var d=await api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify({estatus_nota:valor})});
  if(d&&d.ok){
    var row=CRM_ROWS.find(function(x){return String(x.id)===String(id);});
    if(row)row.estatus_nota=valor;
    toast('Estatus actualizado');
    renderCRM();
  } else if(d){ toast(d.error||'Error al actualizar'); }
}
async function guardarCeldaCRM(el){
  if(celdaBloqueada(el))return;
  var id=el.dataset.id, campo=el.dataset.campo, num=el.dataset.num==='1';
  var raw=el.textContent.trim();
  if(CRM_CAT[campo]&&raw!==''){
    var ops=crmOpciones(campo,''),valido=null,i;
    for(i=0;i<ops.length;i++)if(ops[i].toUpperCase()===raw.toUpperCase())valido=ops[i];
    if(!valido){
      toast('Ese valor no esta en la lista. Elige una de las opciones.');
      var orig=CRM_ROWS.find(function(x){return String(x.id)===String(id);});
      el.textContent=(orig&&orig[campo]!=null)?String(orig[campo]):'';
      return;
    }
    raw=valido;
  }
  var body={};
  if(num){ body[campo]=(raw===''?null:(parseFloat(raw.replace(/[^0-9.-]/g,''))||0)); }
  else if(campo==='fecha_lead'||campo==='fecha_contacto'){ body[campo]=fFechaISO(raw); }
  else { body[campo]=raw; }
  var d=await api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)});
  if(d&&d.ok){
    toast('Guardado');
    var row=CRM_ROWS.find(function(x){return String(x.id)===String(id);});
    if(row)row[campo]=body[campo];
    if(num)el.textContent=(body[campo]==null?'':money(body[campo]));
    else if(campo==='fecha_lead'||campo==='fecha_contacto')el.textContent=fFecha(body[campo]);
  } else if(d){ toast(d.error||'Error al guardar'); }
}
var PEND_CLIENTE=null;
var CAT_MATERIAL=['MARMOL','GRANITO','CUARCITA','CALIZA','CUARZO','PIEDRA SINTERIZADA','ONIX','SEMIPRECIOSA','CANTERA','INSUMOS'];
var CAT_SERVICIOS=[['FLETE','pza'],['MANIOBRA','pza'],['INSTALACIÓN','m2']];
var CAT_FORMATO=['Plancha','Media plancha','Bloque','Loseta','Duela','Tira','Mosaico','Formato especial'];
var CAT_ORIGEN=['WhatsApp','Llamada','Correo','Propio','Redes','Campaña','Oficina','Otro'];
var CAT_GESTION=['COTIZACIÓN','FACTURA'];
var CAT_TIPO_SEG=['LLAMADA','VISITA','MUESTRA'];
var CAT_TIPO=['Nacional','Importado','Santo Tomás','Carrara','Calacatta','Crema Marfil','Negro Marquina','Negro Monterrey','Travertino Veracruz','Travertino Puebla','Travertino Fiorito','Taj Mahal','Cosmos','Tundra','Galarza','Alpina'];
var CAT_ACAB_MAT={
  'MARMOL':['PULIDO BRILLADO','PULIDO MATE','CEPILLADO','SANDBLAST','MARTELINADO','BUZARDEADO','AL ACIDO','BAMBOO','FLUTTED','AL CORTE'],
  'GRANITO':['PULIDO BRILLADO','PULIDO MATE','LEATHER','CEPILLADO','ANTIQUE','FLAMEADO','FLAMEADO + CEPILLADO'],
  'CUARCITA':['PULIDO BRILLADO','PULIDO MATE','LEATHER'],
  'CALIZA':['MATE','PULIDO BRILLADO'],
  'CUARZO':['PULIDO BRILLADO','PULIDO MATE'],
  'ONIX':['PULIDO BRILLADO'],
  'SEMIPRECIOSA':['PULIDO BRILLADO'],
  'CANTERA':['AL CORTE','CEPILLADO','MARTELINADO','BUZARDEADO','SANDBLAST','MATE']
};
function acabTodos(){
  var m={},o=[];
  for(var k in CAT_ACAB_MAT)CAT_ACAB_MAT[k].forEach(function(v){if(!m[v]){m[v]=1;o.push(v);}});
  o.sort(function(a,b){return a.localeCompare(b,'es');});
  return o;
}
function acabadosDe(mat){
  var k=catKey(mat),l;
  if(k&&CAT_ACAB_MAT[k])l=CAT_ACAB_MAT[k].slice();else l=acabTodos();
  var hay=false;l.forEach(function(x){if(catKey(x)==='N/A')hay=true;});
  if(!hay)l.push('N/A');
  return l;
}
function acabOpts(mat,actual){
  var v=(actual==null?'':String(actual)).trim(),lista=acabadosDe(mat),seen={},h='';
  if(v){var hay=false;lista.forEach(function(x){if(catKey(x)===catKey(v))hay=true;});if(!hay)lista=[v].concat(lista);}
  lista.forEach(function(x){var kk=catKey(x);if(seen[kk])return;seen[kk]=1;
    h+='<option'+(catKey(v)===kk?' selected':'')+'>'+escT(x)+'</option>';});
  return h;
}
var CAT_ACABADO=acabTodos();
var NC_IDS=['ncMat','ncAcab'];
function catKey(v){
  var ac='ÁÀÄÂÃÉÈËÊÍÌÏÎÓÒÖÔÕÚÙÜÛÑÇ',pl='AAAAAEEEEIIIIOOOOOUUUUNC',o='';
  var u=String(v==null?'':v).toUpperCase().trim();
  for(var i=0;i<u.length;i++){var p=ac.indexOf(u.charAt(i));o+=(p>=0?pl.charAt(p):u.charAt(i));}
  return o;
}
function catCombina(campo,base){
  var m={},out=[];
  base.forEach(function(x){m[catKey(x)]=x;});
  (CRM_ROWS||[]).forEach(function(r){
    var v=(r[campo]==null?'':String(r[campo])).trim();
    if(v&&v.length<=45){var k=catKey(v);if(!m[k])m[k]=v;}
  });
  for(var kk in m)out.push(m[kk]);
  out.sort(function(a,b){return a.localeCompare(b,'es');});
  return out;
}
function catSelect(id,label,lista,n,extra){
  var h='<label>'+escT(label)+'</label><select id="'+id+'" onchange="'+(extra?extra:('ncOtroTog('+n+')'))+'"><option value="">— '+escT(label)+' —</option>';
  lista.forEach(function(v){h+='<option>'+escT(v)+'</option>';});
  h+='<option value="__otro__">— Otro (escribir) —</option></select>';
  h+='<input id="'+id+'Otro" style="display:none;margin-top:.35rem" placeholder="Escribe el '+escT(label.toLowerCase())+'">';
  return h;
}
function ncOtroTog(n){
  var sel=document.getElementById(NC_IDS[n]),otr=document.getElementById(NC_IDS[n]+'Otro');
  if(!sel||!otr)return;
  if(sel.value==='__otro__'){otr.style.display='';otr.focus();}
  else{otr.style.display='none';otr.value='';}
}
function ncPick(n){
  var sel=document.getElementById(NC_IDS[n]),otr=document.getElementById(NC_IDS[n]+'Otro');
  if(!sel)return '';
  if(sel.value==='__otro__')return otr?String(otr.value).trim():'';
  return String(sel.value).trim();
}
function nuevoCliente(){
  var ases={};(CRM_ROWS||[]).forEach(function(r){var a=(r.asesor||'').trim();if(a)ases[a]=1;});
  var aopt='<option value="">— Asesor —</option>';Object.keys(ases).sort().forEach(function(a){aopt+='<option>'+escAttr(a)+'</option>';});
  var origenes=['WhatsApp','Llamada','Correo','Propio','Redes','Campaña','Oficina','Otro'];
  var oopt='<option value="">— Origen —</option>';origenes.forEach(function(o){oopt+='<option>'+o+'</option>';});
  var eopt='<option value="">— Estatus —</option>';CRM_ESTATUS.forEach(function(s){eopt+='<option>'+escAttr(s)+'</option>';});
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.2rem">Nuevo registro</h3>'+
    '<p class="muted" style="font-size:.8rem;margin-bottom:.8rem">Solo el nombre es obligatorio. Lo demás lo puedes completar después en la ficha.</p>'+
    '<label>Nombre del contacto *</label><input id="ncNom" placeholder="Nombre y apellido">'+
    '<div class="g2"><div><label>Empresa</label><input id="ncEmp"></div><div><label>Teléfono</label><input id="ncTel" placeholder="55..."></div></div>'+
    '<div class="g2"><div><label>Correo</label><input id="ncMail" type="email"></div><div><label>Asesor</label><select id="ncAse">'+aopt+'</select></div></div>'+
    '<div class="g2"><div><label>Origen del lead</label><select id="ncOri">'+oopt+'</select></div><div><label>Estatus</label><select id="ncEst">'+eopt+'</select></div></div>'+
    '<div class="g2"><div>'+catSelect('ncMat','Material',CAT_MATERIAL,0,'ncSyncAcab()')+'</div><div>'+catSelect('ncAcab','Acabado',[],1)+'</div></div>'+
    '<div class="g2"><div><label>Tipo</label><input id="ncTipo" placeholder="Ejemplo: Santo Tomás"></div><div><label>Formato</label><input id="ncForm" placeholder="Ejemplo: Plancha 3.20 x 1.80"></div></div>'+
    '<label>Cantidad</label><input id="ncCant" placeholder="Ejemplo: 30 m2 / 2 planchas">'+
    '<label>Propuesta s/IVA (opcional)</label><input id="ncProp" type="number" placeholder="0.00">'+
    '<label>Notas admin</label><textarea id="ncNotasAdm" rows="3" placeholder="Pega aquí lo que te comentó el prospecto: otras opciones, formatos, referencias... Lo verá el asesor en la ficha."></textarea>'+
    '<div style="display:flex;gap:.5rem;margin-top:1rem"><button class="btn" onclick="guardarNuevoCliente()">Crear registro</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
  setTimeout(function(){var n=document.getElementById('ncNom');if(n)n.focus();ncSyncAcab();},80);
}
function ncSyncAcab(){
  ncOtroTog(0);
  var sel=document.getElementById('ncAcab');if(!sel)return;
  var prev=sel.value;
  var h='<option value="">— Acabado —</option>'+acabOpts(ncPick(0),(prev==='__otro__'?'':prev))+'<option value="__otro__">— Otro (escribir) —</option>';
  sel.innerHTML=h;
  if(prev==='__otro__')sel.value='__otro__';
  ncOtroTog(1);
}
function guardarNuevoCliente(){
  var nom=val('ncNom');if(!nom){toast('El nombre es obligatorio');return;}
  var body={nombre:nom};
  var emp=val('ncEmp');if(emp)body.empresa=emp;
  var tel=val('ncTel');if(tel)body.telefono=tel;
  var mail=val('ncMail');if(mail)body.email=mail;
  var ase=val('ncAse');if(ase)body.asesor=ase;
  var ori=val('ncOri');if(ori)body.origen=ori;
  var est=val('ncEst');if(est)body.estatus_nota=est;
  var mat=ncPick(0);if(mat)body.material=mat;
  var aca=ncPick(1);if(aca)body.acabado=aca;
  var tip=val('ncTipo');if(tip)body.tipo=tip;
  var fmt=val('ncForm');if(fmt)body.formato=fmt;
  var cant=val('ncCant');if(cant)body.cantidad=cant;
  var prop=val('ncProp');if(prop!=='')body.propuesta_antes_iva=parseFloat(prop);
  var nadm=val('ncNotasAdm');if(nadm)body.notas_vero=nadm;
  crearCliente(body, false);
}
async function crearCliente(body, force){
  var payload={};for(var k in body)payload[k]=body[k];
  if(!payload.etapa)payload.etapa='prospecto';
  if(!payload.moneda)payload.moneda='MXN';
  if(!payload.fecha_lead)payload.fecha_lead=new Date().toISOString().slice(0,10);
  if(force)payload.force=true;
  var d=await api('/api/clientes',{method:'POST',body:JSON.stringify(payload)});
  if(!d)return;
  if(d.ok && d.data && d.data.duplicado){ PEND_CLIENTE=payload; mostrarDuplicadoAviso(d.data.existentes); return; }
  if(d.ok){ if(typeof closeModal==='function')closeModal(); toast('Registro creado'); viewClientes(document.getElementById('content')); }
  else { toast(d.error||'Error'); }
}
function crearClienteForzado(){ if(PEND_CLIENTE){ var p={};for(var k in PEND_CLIENTE)p[k]=PEND_CLIENTE[k]; delete p.force; crearCliente(p, true); } }
function mostrarDuplicadoAviso(existentes){
  var h='<h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.4rem">Posible duplicado</h3>'+
    '<p class="muted" style="font-size:.85rem;margin-bottom:.7rem">Ya hay registro(s) parecido(s). Abre el existente para no duplicar, o crea uno nuevo de todos modos.</p>'+
    '<div style="display:flex;flex-direction:column;gap:.4rem;margin-bottom:1rem">';
  (existentes||[]).forEach(function(x){
    h+='<div class="card" style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;padding:.5rem .7rem"><div><strong>'+escAttr(x.nombre||'—')+'</strong>'+(x.empresa?(' · '+escAttr(x.empresa)):'')+'<div class="muted" style="font-size:.76rem">'+escAttr(x.telefono||'')+(x.email?(' · '+escAttr(x.email)):'')+(x.asesor?(' · '+escAttr(x.asesor)):'')+'</div></div><button class="btn" style="padding:.3rem .6rem" onclick="abrirFicha('+x.id+')">Abrir ficha</button></div>';
  });
  h+='</div><div style="display:flex;gap:.5rem"><button class="btn sec" onclick="crearClienteForzado()">Crear de todos modos</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>';
  openModal(h);
}
async function verDuplicados(){
  var d=await api('/api/clientes/duplicados');if(!d||!d.ok){toast('No se pudo revisar');return;}
  var grupos=d.data.grupos||[];
  var h='<h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.4rem">Posibles duplicados</h3>';
  if(!grupos.length){ h+='<p class="muted">No se encontraron repetidos por teléfono, correo ni nombre.</p>'; }
  else{
    h+='<p class="muted" style="font-size:.84rem;margin-bottom:.7rem">'+grupos.length+' grupo(s). Abre cada ficha para revisar y consolidar.</p>';
    grupos.forEach(function(g){
      h+='<div class="card" style="margin-bottom:.6rem;padding:.6rem .8rem"><div class="muted" style="font-size:.74rem;margin-bottom:.3rem">'+escAttr(g.tipo)+': '+escAttr(g.clave)+'</div>';
      (g.miembros||[]).forEach(function(x){ h+='<div style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;padding:.25rem 0;border-top:1px solid var(--bd)"><div><strong>'+escAttr(x.nombre||'—')+'</strong>'+(x.empresa?(' · '+escAttr(x.empresa)):'')+(x.asesor?('<span class="muted" style="font-size:.74rem"> · '+escAttr(x.asesor)+'</span>'):'')+'</div><div style="display:flex;gap:.35rem"><button class="btn sec" style="padding:.25rem .55rem" onclick="abrirFicha('+x.id+')">Abrir</button>'+(puedeBorrarCRM()?('<button class="btn" style="padding:.25rem .55rem;background:#7a1f1f;border-color:#7a1f1f;color:#fff" onclick="eliminarLead('+x.id+')">Eliminar</button>'):'')+'</div></div>'; });
      h+='</div>';
    });
  }
  h+='<div style="margin-top:.6rem"><button class="btn sec" onclick="closeModal()">Cerrar</button></div>';
  openModal(h);
}
function pintarFiltros(){
  var box=document.getElementById('crmFiltros');if(!box)return;
  var ases={};CRM_ROWS.forEach(function(r){var a=(r.asesor||'').trim();if(a)ases[a]=1;});
  var aopts='<option value="">Asesor: todos</option>';Object.keys(ases).sort().forEach(function(a){aopts+='<option>'+escAttr(a)+'</option>';});
  var yrs={};CRM_ROWS.forEach(function(r){var y=(r.fecha_lead||'').slice(0,4);if(/^[0-9]{4}$/.test(y))yrs[y]=1;});
  var yopts='<option value="">Año: todos</option>';Object.keys(yrs).sort().reverse().forEach(function(y){yopts+='<option>'+y+'</option>';});
  var meses=[['01','Enero'],['02','Febrero'],['03','Marzo'],['04','Abril'],['05','Mayo'],['06','Junio'],['07','Julio'],['08','Agosto'],['09','Septiembre'],['10','Octubre'],['11','Noviembre'],['12','Diciembre']];
  var mopts='<option value="">Mes: todos</option>';meses.forEach(function(m){mopts+='<option value="'+m[0]+'">'+m[1]+'</option>';});
  var eopts='<option value="">Estatus: todos</option>';CRM_ESTATUS.forEach(function(s){eopts+='<option>'+escAttr(s)+'</option>';});eopts+='<option value="__SIN__">(Sin estatus)</option>';
  var efs={};CRM_ROWS.forEach(function(r){var v=(r.estatus_final||'').trim();if(v&&v.length<=25)efs[v.toUpperCase()]=v;});
  var efopts='<option value="">Estatus final: todos</option>';Object.keys(efs).sort().forEach(function(k){efopts+='<option>'+escAttr(efs[k])+'</option>';});efopts+='<option value="__SIN__">(Sin estatus final)</option>';
  box.innerHTML='<div class="colhd'+(CRM_FIL_OPEN?'':' closed')+'" id="filHd" onclick="togFiltros()"><span class="chev">\u25be</span> Filtros</div>'+
    '<div class="card crmfilt" id="filBody" style="'+(CRM_FIL_OPEN?'':'display:none')+'">'+
    '<input id="crmq" placeholder="Buscar texto..." oninput="renderCRM()">'+
    '<select id="fAsesor" onchange="renderCRM()">'+aopts+'</select>'+
    '<select id="fEstatus" onchange="renderCRM()">'+eopts+'</select>'+
    '<select id="fEFin" onchange="renderCRM()">'+efopts+'</select>'+
    '<select id="fAnio" onchange="renderCRM()">'+yopts+'</select>'+
    '<select id="fMes" onchange="crmMesCambio()">'+mopts+'</select>'+
    '<select id="fFact" onchange="renderCRM()"><option value="">Facturación: todas</option><option value="con">Con factura</option><option value="sin">Sin factura</option></select>'+
    '<select id="fSeg" onchange="renderCRM()" title="Fecha del seguimiento"><option value="">Seguimiento: todos</option><option value="hoy">Hoy</option><option value="venc">Vencidos</option><option value="prox">Próximos 7 días</option><option value="con">Con fecha</option><option value="sin">Sin fecha</option></select>'+
    '<input id="fMin" type="number" placeholder="Monto min" oninput="renderCRM()">'+
    '<input id="fMax" type="number" placeholder="Monto max" oninput="renderCRM()">'+
    '<button class="btn sec" onclick="limpiarFiltros()">Limpiar</button>'+
    '<span class="filsep"></span>'+
    '<button class="btn" id="cvTabla" data-v="tabla" onclick="setVistaCRM(this.dataset.v)">Tabla</button>'+
    '<button class="btn sec" id="cvTablero" data-v="tablero" onclick="setVistaCRM(this.dataset.v)">Tablero</button>'+
    '<button class="btn sec" onclick="verDuplicados()" title="Buscar registros repetidos">Duplicados</button>'+
    '<button class="btn sec" onclick="exportarCRMCSV()">Exportar CSV</button>'+
    (puedeTitulosCRM()?'<button class="btn sec" onclick="gestionColumnasCRM()" title="Estaticas, orden, ocultar o eliminar columnas">Columnas</button>':'')+
    '<button class="btn sec" onclick="nuevoCliente()">+ Nuevo registro</button>'+
    '</div>';
}
function pintarResumen(rows){
  var box=document.getElementById('crmResumen');if(!box)return;
  var n=rows.length,sumP=0,sumF=0,conF=0;
  rows.forEach(function(r){if(r.propuesta_antes_iva!=null)sumP+=Number(r.propuesta_antes_iva)||0;var f=Number(r.facturado)||0;sumF+=f;if(f>0)conF++;});
  var compacto=n+' reg \u00b7 Prop '+money(sumP)+' \u00b7 Fact '+money(sumF)+' \u00b7 C/fact '+conF;
  var per=crmPeriodoTxt();
  var rh='<div class="colhd'+(CRM_KPI_OPEN?'':' closed')+'" onclick="togKpis()"><span class="chev">\u25be</span> Resumen'+(per?(' \u00b7 '+per):'')+(CRM_KPI_OPEN?'':' \u2014 '+compacto)+'</div>';
  if(CRM_KPI_OPEN)rh+='<div class="kpis crmkpis">'+kpiCard('Registros',n)+kpiCard('Propuesta s/IVA',money(sumP))+kpiCard('Facturado',money(sumF))+kpiCard('Con factura',conF)+'</div>';
  box.innerHTML=rh;
}
function soloMios(){
  var sel=document.getElementById('fAsesor');if(!sel)return;
  var nom=(typeof USER!=='undefined'&&USER.nombre)?USER.nombre:'';
  if(!nom){toast('No identifico tu usuario');return;}
  var found=false;for(var i=0;i<sel.options.length;i++){if(sel.options[i].value===nom||sel.options[i].text===nom){sel.selectedIndex=i;found=true;break;}}
  if(!found){var o=document.createElement('option');o.text=nom;o.value=nom;sel.add(o);sel.value=nom;}
  renderCRM();
}
function limpiarFiltros(){
  ['crmq','fMin','fMax'].forEach(function(id){var e=document.getElementById(id);if(e)e.value='';});
  ['fAsesor','fEstatus','fEFin','fAnio','fMes','fFact','fSeg'].forEach(function(id){var e=document.getElementById(id);if(e)e.selectedIndex=0;});
  renderCRM();
}
var CX_ID=null;
function cxSel(id,label,lista,actual,onch){
  var v=(actual==null?'':String(actual)).trim(),vis=[],seen={};
  for(var i=0;i<lista.length;i++){
    var x=String(lista[i]).trim();
    if(x&&!seen[x.toUpperCase()]){seen[x.toUpperCase()]=1;vis.push(x);}
  }
  if(v&&!seen[v.toUpperCase()])vis.unshift(v);
  var h='<label>'+escT(label)+'</label><select id="'+id+'"'+(onch?(' onchange="'+onch+'"'):'')+'><option value="">— '+escT(label)+' —</option>';
  for(var j=0;j<vis.length;j++){
    h+='<option'+(vis[j].toUpperCase()===v.toUpperCase()?' selected':'')+'>'+escT(vis[j])+'</option>';
  }
  return h+'</select>';
}
function cxIn(id,label,v,ph,tipo){
  return '<label>'+escT(label)+'</label><input id="'+id+'"'+(tipo?' type="'+tipo+'"':'')+' placeholder="'+escAttr(ph||'')+'" value="'+escAttr(v==null?'':String(v))+'">';
}
function cardexLead(ev,id){
  if(ev&&ev.preventDefault)ev.preventDefault();
  var r=null;
  for(var i=0;i<CRM_ROWS.length;i++){if(String(CRM_ROWS[i].id)===String(id))r=CRM_ROWS[i];}
  if(!r){toast('No encontré ese registro');return false;}
  CX_ID=r.id;
  var ases={};CRM_ROWS.forEach(function(x){var a=(x.asesor||'').trim();if(a)ases[a]=1;});
  var lAse=Object.keys(ases).sort();
  var lOri=['WhatsApp','Llamada','Correo','Propio','Redes','Campaña','Oficina','Otro'];
  var sub=[];
  if(r.fecha_lead)sub.push('Lead '+fFecha(r.fecha_lead));
  if(r.estatus_final)sub.push('Final: '+r.estatus_final);
  if(r.facturado!=null&&Number(r.facturado)>0)sub.push('Facturado '+money(r.facturado));
  sub.push((r.num_cotizaciones||0)+' cotizaciones');
  var h='<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.2rem">Cardex del lead</h3>'+
    '<p class="muted" style="font-size:.8rem;margin-bottom:.8rem">'+escT(sub.join('  ·  '))+'</p>'+
    cxIn('cxNom','Nombre del contacto *',r.nombre,'Nombre y apellido')+
    '<div class="g2"><div>'+cxIn('cxEmp','Empresa',r.empresa,'')+'</div><div>'+cxIn('cxTel','Teléfono',r.telefono,'55...')+'</div></div>'+
    '<div class="g2"><div>'+cxIn('cxMail','Correo',r.email,'','email')+'</div><div>'+cxSel('cxAse','Asesor',lAse,r.asesor)+'</div></div>'+
    '<div class="g2"><div>'+cxSel('cxOri','Origen del lead',lOri,r.origen)+'</div><div>'+cxSel('cxEst','Estatus',CRM_ESTATUS,r.estatus_nota)+'</div></div>'+
    '<div class="g2"><div>'+cxSel('cxMat','Material',CAT_MATERIAL,r.material,'cxSyncAcab()')+'</div><div><label>Acabado</label><select id="cxAcab"><option value="">— Acabado —</option>'+acabOpts(r.material,r.acabado)+'</select></div></div>'+
    '<div class="g2"><div>'+cxIn('cxTipo','Tipo',r.tipo,'Ejemplo: Santo Tomás')+'</div><div>'+cxIn('cxForm','Formato',r.formato,'Ejemplo: Plancha 3.20 x 1.80')+'</div></div>'+
    cxIn('cxCant','Cantidad',r.cantidad,'Ejemplo: 30 m2 / 2 planchas')+
    cxIn('cxProp','Propuesta s/IVA',(r.propuesta_antes_iva==null?'':r.propuesta_antes_iva),'0.00','number')+
    '<div style="display:flex;gap:.5rem;margin-top:1rem;flex-wrap:wrap"><button class="btn" onclick="guardarCardex()">Guardar cambios</button><button class="btn sec" onclick="cardexFicha()">Abrir ficha completa</button><button class="btn sec" onclick="closeModal()">Cerrar</button></div>';
  openModal(h);
  return false;
}
function cxSyncAcab(){
  var m=document.getElementById('cxMat'),s=document.getElementById('cxAcab');
  if(!m||!s)return;
  var prev=s.value;
  s.innerHTML='<option value="">— Acabado —</option>'+acabOpts(m.value,prev);
}
function cardexFicha(){var id=CX_ID;closeModal();if(id)abrirFicha(id);}
async function guardarCardex(){
  var id=CX_ID;if(!id)return;
  var nom=val('cxNom');
  if(!nom){toast('El nombre no puede quedar vacío');return;}
  function nn(x){x=val(x);return x===''?null:x;}
  var body={nombre:nom,empresa:nn('cxEmp'),telefono:nn('cxTel'),email:nn('cxMail'),
    asesor:nn('cxAse'),origen:nn('cxOri'),estatus_nota:nn('cxEst'),
    material:nn('cxMat'),acabado:nn('cxAcab'),tipo:nn('cxTipo'),
    formato:nn('cxForm'),cantidad:nn('cxCant')};
  var p=val('cxProp');
  body.propuesta_antes_iva=(p===''?null:parseFloat(p));
  var d=await api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)});
  if(d&&d.ok){
    for(var i=0;i<CRM_ROWS.length;i++){
      if(String(CRM_ROWS[i].id)===String(id)){for(var k in body)CRM_ROWS[i][k]=body[k];}
    }
    closeModal();renderCRM();toast('Cardex guardado');
  }else toast((d&&d.error)||'No se pudo guardar el cardex');
}
function gestionColumnasCRM(){
  var h='<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.2rem">Columnas del CRM</h3>'+
    '<p class="muted" style="font-size:.8rem;margin-bottom:.7rem">Estática = se congela a la izquierda y no se mueve al desplazar la tabla. También puedes ocultarlas, reordenarlas con las flechas o arrastrando el encabezado, y eliminar las que tú creaste.</p>'+
    '<div id="colManBody" style="max-height:44vh;overflow:auto;border:1px solid var(--bd);border-radius:6px">'+
    '<table class="colman" style="width:100%;font-size:.82rem"><thead><tr>'+
    '<th style="width:44%">Columna</th><th style="text-align:center">Estática</th><th style="text-align:center">Visible</th><th style="text-align:center">Orden</th><th></th>'+
    '</tr></thead><tbody>';
  for(var i=0;i<CRM_LAY.length;i++){
    var x=CRM_LAY[i],propia=layPropia(x.k),acc=(x.k==='__acc');
    h+='<tr>'+
      '<td>'+escT(x.t)+(propia?' <span class="muted" style="font-size:.68rem">(creada por ti)</span>':'')+(acc?' <span class="muted" style="font-size:.68rem">(acciones)</span>':'')+'</td>'+
      '<td style="text-align:center"><button class="btn'+(x.f===1?'':' sec')+'" style="padding:.18rem .55rem;font-size:.7rem" onclick="colFijar('+i+')">'+(x.f===1?'Sí':'No')+'</button></td>'+
      '<td style="text-align:center">'+(acc?'<span class="muted" style="font-size:.72rem">Siempre</span>':'<button class="btn'+(x.v===0?' sec':'')+'" style="padding:.18rem .55rem;font-size:.7rem" onclick="colVer('+i+')">'+(x.v===0?'Oculta':'Sí')+'</button>')+'</td>'+
      '<td style="text-align:center;white-space:nowrap"><button class="btn sec" style="padding:.18rem .45rem;font-size:.7rem" onclick="colArriba('+i+')" title="Subir">\u25b2</button> <button class="btn sec" style="padding:.18rem .45rem;font-size:.7rem" onclick="colAbajo('+i+')" title="Bajar">\u25bc</button></td>'+
      '<td style="text-align:right">'+(propia?'<button class="btn sec" style="padding:.18rem .55rem;font-size:.7rem" onclick="colEliminar('+i+')">Eliminar</button>':'')+'</td>'+
      '</tr>';
  }
  h+='</tbody></table></div>'+
    '<label style="margin-top:.9rem">Nueva columna</label><input id="ncColT" placeholder="Ejemplo: Espesor" maxlength="28">'+
    '<div style="display:flex;gap:.5rem;margin-top:.7rem;flex-wrap:wrap"><button class="btn" onclick="agregarColumnaCRM()">Agregar columna</button><button class="btn sec" onclick="restaurarTitulosCRM()">Restaurar por defecto</button><button class="btn sec" onclick="closeModal()">Cerrar</button></div>';
  openModal(h);
}
async function agregarColumnaCRM(){
  var t=val('ncColT');
  if(!t){toast('Escribe el nombre de la columna');return;}
  var d=await api('/api/crm/columnas',{method:'POST',body:JSON.stringify({titulo:t})});
  if(!d||!d.ok){toast((d&&d.error)||'No se pudo agregar la columna');return;}
  CRM_COLS=d.data||[];
  for(var i=0;i<CRM_COLS.length;i++){
    if(layIdx(CRM_COLS[i].c)<0)CRM_LAY.push({k:CRM_COLS[i].c,t:CRM_COLS[i].t,v:1,f:0});
  }
  await guardarLayoutCRM('');
  gestionColumnasCRM();
  toast('Columna agregada');
}
async function exportarCRMCSV(){
  var ord=layOrden(),cols=[],tiene={};
  ord.forEach(function(i){var x=CRM_LAY[i];if(x.k==='__acc')return;cols.push([x.k,x.t]);tiene[x.k]=1;});
  if(!cols.length){toast('No hay columnas visibles');return;}
  if(!tiene.notas_seguimiento)cols.push(['notas_seguimiento','NOTAS DEL ASESOR']);
  if(!tiene.notas)cols.push(['notas','NOTAS GENERALES']);
  cols.push(['__hist','HISTORIAL']);
  var hist={};
  try{var dh=await api('/api/clientes/historial');if(dh&&dh.ok){(dh.data||[]).forEach(function(n){var k=String(n.cliente_id);var lin=fmtFechaHora(n.created_at)+(n.usuario?(' · '+n.usuario):'')+': '+(n.nota||'');hist[k]=hist[k]?(hist[k]+' | '+lin):lin;});}}catch(e){}
  function esc(v){v=(v==null?'':String(v));return '"'+v.replace(/"/g,'""')+'"';}
  var lines=[cols.map(function(x){return esc(x[1]);}).join(',')];
  filasCRMFiltradas().forEach(function(r){lines.push(cols.map(function(x){return esc(x[0]==='__hist'?(hist[String(r.id)]||''):r[x[0]]);}).join(','));});
  var csv='\\ufeff'+lines.join('\\r\\n');
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='CRM_ASLAN'+(crmPeriodoTxt()?('_'+(valFil('fAnio')||'todos')+(valFil('fMes')?('-'+valFil('fMes')):'')):'')+'.csv';document.body.appendChild(a);a.click();a.remove();
}
async function verCotizacionesCliente(id){
  var row=CRM_ROWS.find(function(x){return String(x.id)===String(id);})||{};
  var d=await api('/api/cotizaciones?cliente='+id);
  var lista=(d&&d.ok)?d.data:[];
  var h='<h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.15rem">Cotizaciones · '+escAttr(row.nombre||'')+'</h3>';
  h+='<p class="muted" style="font-size:.82rem;margin-bottom:.7rem">Asesor: <strong>'+escAttr(row.asesor||row.empleado_nombre||'—')+'</strong>'+(row.empresa?(' · '+escAttr(row.empresa)):'')+'</p>';
  if(!lista.length){h+='<p class="muted">Este cliente aún no tiene cotizaciones ligadas.</p>';}
  else{
    h+='<div style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th>Folio</th><th>Total</th><th>Estado</th><th>Vendedor</th><th>Proyecto</th><th></th></tr></thead><tbody>';
    lista.forEach(function(c){
      var proy=c.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+c.proyecto_folio+'</span>'):'—';
      h+='<tr><td>'+(c.folio||'—')+'</td><td>'+money(c.total)+'</td><td>'+(c.estado||'—')+'</td><td>'+(c.vendedor||'—')+'</td><td>'+proy+'</td><td><button class="btn sec" style="padding:.2rem .5rem" onclick="pdfCotizacion('+c.id+')">PDF</button></td></tr>';
    });
    h+='</tbody></table></div>';
  }
  h+='<div style="display:flex;gap:.5rem;margin-top:1rem"><button class="btn" onclick="cotizarCliente('+id+')">+ Nueva cotización</button><button class="btn sec" onclick="closeModal()">Cerrar</button></div>';
  openModal(h);
}
function cotizarCliente(id){ if(typeof closeModal==='function')closeModal(); nuevaCotizacion(id); }

// ============================================================================
//  FICHA 360° — vista integral del prospecto/cliente (datos+historial+
//  cotizaciones+proyectos+trazabilidad en un solo lugar). Editable inline.
// ============================================================================
var FICHA={};
function volverCRM(){ go('clientes'); }
async function abrirFicha(id){
  FICHA={id:id};
  var content=document.getElementById('content');
  content.innerHTML='<button class="back" onclick="volverCRM()">‹ Volver al CRM</button><p class="muted">Cargando ficha…</p>';
  var acc=document.getElementById('acciones'); if(acc)acc.innerHTML='';
  var d=await api('/api/clientes/'+id+'/ficha');
  if(!d||!d.ok){ content.innerHTML='<button class="back" onclick="volverCRM()">‹ Volver al CRM</button><p class="muted">No se pudo cargar la ficha.</p>'; return; }
  FICHA=d.data; FICHA.id=id;
  renderFicha();
}
// Guarda una celda editable de la ficha (PUT a /api/clientes/:id)
function fGuardar(el){
  var id=el.dataset.id, campo=el.dataset.campo, tipo=el.dataset.tipo||'text';
  var raw=el.textContent.trim();
  var body={};
  if(tipo==='num'){ body[campo]=(raw===''?null:(parseFloat(raw.replace(/[^0-9.-]/g,''))||0)); }
  else { body[campo]=(raw===''?null:raw); }
  api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)}).then(function(d){
    if(d&&d.ok){ toast('Guardado'); if(FICHA.cliente)FICHA.cliente[campo]=body[campo]; if(tipo==='num')el.textContent=(body[campo]==null?'':money(body[campo])); }
    else if(d){ toast(d.error||'Error al guardar'); }
  });
}
function fField(label,campo,val,tipo){
  tipo=tipo||'text';
  var disp=(val==null||val==='')?'':(tipo==='num'?money(val):String(val));
  return '<div class="ffield"><label>'+label+'</label>'+
    '<span class="fedit'+(tipo==='num'?' fnum':'')+'" contenteditable="true" data-id="'+FICHA.id+'" data-campo="'+campo+'" data-tipo="'+tipo+'" data-ph="'+escAttr(label)+'" onblur="fGuardar(this)">'+escAttr(disp)+'</span></div>';
}
function fWide(label,campo,val){
  return '<div class="fwide"><label>'+label+'</label>'+
    '<div class="fedit" contenteditable="true" data-id="'+FICHA.id+'" data-campo="'+campo+'" data-tipo="text" data-ph="'+escAttr(label)+'" onblur="fGuardar(this)">'+escAttr(val==null?'':String(val))+'</div></div>';
}
// Campo de la ficha con lista de opciones (no se escribe a mano)
function fSel(label,campo,valor,lista){
  var v=(valor==null?'':String(valor)).trim(),seen={},arr=[],i;
  for(i=0;i<lista.length;i++){var x=String(lista[i]==null?'':lista[i]).trim();if(x&&!seen[x.toUpperCase()]){seen[x.toUpperCase()]=1;arr.push(x);}}
  if(v&&!seen[v.toUpperCase()]){arr.unshift(v);seen[v.toUpperCase()]=1;}
  var h='<div class="ffield"><label>'+label+'</label><select data-id="'+FICHA.id+'" data-campo="'+campo+'" onchange="fGuardarSel(this)"><option value="">— '+escT(label)+' —</option>';
  for(i=0;i<arr.length;i++)h+='<option'+(arr[i].toUpperCase()===v.toUpperCase()?' selected':'')+'>'+escT(arr[i])+'</option>';
  return h+'</select></div>';
}
// Campo de la ficha con calendario
function fDate(label,campo,valor){
  var v=(valor==null?'':String(valor)).trim().slice(0,10);
  if(!/^[0-9]{4}-[0-9]{2}-[0-9]{2}$/.test(v))v='';
  return '<div class="ffield"><label>'+label+'</label><input type="date" class="fdate" data-id="'+FICHA.id+'" data-campo="'+campo+'" value="'+escAttr(v)+'" onchange="fGuardarSel(this)"></div>';
}
function fGuardarSel(el){
  var id=el.dataset.id,campo=el.dataset.campo,v=String(el.value==null?'':el.value).trim();
  var body={};body[campo]=(v===''?null:v);
  api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)}).then(function(d){
    if(d&&d.ok){toast('Guardado');if(FICHA.cliente)FICHA.cliente[campo]=body[campo];}
    else if(d){toast(d.error||'Error al guardar');}
  });
}
function fCatAsesores(){
  var m={},o=[];
  function add(v){v=String(v==null?'':v).trim();if(v&&v.length<=40&&!m[v.toUpperCase()]){m[v.toUpperCase()]=1;o.push(v);}}
  ((FICHA.catalogos&&FICHA.catalogos.asesores)||[]).forEach(add);
  (typeof CRM_ROWS!=='undefined'?(CRM_ROWS||[]):[]).forEach(function(r){add(r.asesor);});
  o.sort(function(a,b){return a.localeCompare(b,'es');});
  return o;
}
function fCatFinales(){
  var m={},o=[];
  function add(v){v=String(v==null?'':v).trim();if(v&&v.length<=25&&!m[v.toUpperCase()]){m[v.toUpperCase()]=1;o.push(v);}}
  add('VIABLE');add('NV');
  ((FICHA.catalogos&&FICHA.catalogos.finales)||[]).forEach(add);
  (typeof CRM_ROWS!=='undefined'?(CRM_ROWS||[]):[]).forEach(function(r){add(r.estatus_final);});
  return o;
}
async function toggleEtapaFicha(){
  var cid=FICHA.id; var c=FICHA.cliente||{};
  var nueva=(c.etapa==='cliente')?'prospecto':'cliente';
  var d=await api('/api/clientes/'+cid,{method:'PUT',body:JSON.stringify({etapa:nueva})});
  if(d&&d.ok){ if(FICHA.cliente)FICHA.cliente.etapa=nueva; toast('Etapa actualizada'); renderFicha(); }
  else if(d){ toast(d.error||'Error'); }
}
function cotizarClienteFicha(){ nuevaCotizacion(FICHA.id); }
async function agregarNotaFicha(){
  var cid=FICHA.id;
  var inp=document.getElementById('fNota'); var nota=inp?inp.value.trim():'';
  if(!nota){ toast('Escribe una nota'); return; }
  var d=await api('/api/clientes/'+cid+'/notas',{method:'POST',body:JSON.stringify({nota:nota})});
  if(d&&d.ok){
    var fresh=await api('/api/clientes/'+cid+'/ficha');
    if(fresh&&fresh.ok){ FICHA=fresh.data; FICHA.id=cid; renderFicha(); }
    toast('Agregado al historial');
  } else if(d){ toast(d.error||'Error'); }
}
function renderFicha(){
  var c=FICHA.cliente||{}, R=FICHA.resumen||{};
  var content=document.getElementById('content'); if(!content)return;
  var etapaBadge=(c.etapa==='cliente')?'<span class="pill" style="background:var(--ok)">CLIENTE</span>':'<span class="pill" style="background:var(--gold)">PROSPECTO</span>';
  var h='<button class="back" onclick="volverCRM()">‹ Volver al CRM</button>';
  h+='<div class="ficha-head"><div><div class="ficha-name fedit" contenteditable="true" data-id="'+FICHA.id+'" data-campo="nombre" data-tipo="text" data-ph="Nombre" title="Clic para editar el nombre" onblur="fGuardar(this)">'+escAttr(c.nombre||'')+'</div>'+
     '<div class="muted" style="font-size:.85rem">'+escAttr(c.empresa||'Sin empresa')+(c.industria?(' · '+escAttr(c.industria)):'')+'</div></div>'+
     '<div class="ficha-actions">'+etapaBadge+
     ' <button class="btn" onclick="cotizarClienteFicha()">+ Cotización</button>'+
     ' <button class="btn sec" onclick="toggleEtapaFicha()">'+(c.etapa==='cliente'?'Marcar prospecto':'Marcar cliente')+'</button></div></div>';
  h+='<div class="kpis" style="margin:1rem 0">'+
     kpiCard('Cotizaciones',(R.num_cotizaciones||0))+
     kpiCard('Total cotizado',money(R.total_cotizado))+
     kpiCard('Total aceptado',money(R.total_aceptado))+
     kpiCard('Facturado',money(R.facturado))+
     kpiCard('Pagado',money(R.total_pagado))+
     kpiCard('Saldo pendiente',money(R.saldo))+
     kpiCard('m² cortados',(R.m2_cortados||0))+'</div>';
  h+='<div class="fsec"><h3>Datos de contacto</h3><div class="fgrid">'+
     fField('Teléfono','telefono',c.telefono)+
     fField('Teléfono alterno','telefono_alt',c.telefono_alt)+
     fField('Correo','email',c.email)+
     fField('Sitio web','sitio_web',c.sitio_web)+
     fField('Ciudad','ciudad',c.ciudad)+
     fField('RFC','rfc',c.rfc)+
     fField('Razón social','razon_social',c.razon_social)+
     fSel('Asesor','asesor',c.asesor,crmOpciones('asesor',c.asesor))+
     fSel('Origen del lead','origen',c.origen,CAT_ORIGEN)+
     fWide('Dirección fiscal','direccion',c.direccion)+'</div></div>';
  h+='<div class="fsec"><h3>Comercial y oportunidad</h3><div class="fgrid">'+
     fSel('Estatus','estatus_nota',c.estatus_nota,crmOpciones('estatus_nota',c.estatus_nota))+
     fSel('Estatus final','estatus_final',c.estatus_final,crmOpciones('estatus_final',c.estatus_final))+
     fSel('Material de interés','material',c.material,CAT_MATERIAL)+
     fSel('Gestión comercial','probabilidad_cierre',c.probabilidad_cierre,CAT_GESTION)+
     fDate('Cierre estimado','fecha_cierre_estimada',c.fecha_cierre_estimada)+
     fSel('Próximo seguimiento','tipo_seguimiento',c.tipo_seguimiento,CAT_TIPO_SEG)+
     fDate('Fecha del seguimiento','proximo_seguimiento',c.proximo_seguimiento)+'</div></div>';
  var pIni=(c.propuesta_inicial==null?null:Number(c.propuesta_inicial));
  var pAct=(c.propuesta_antes_iva==null?null:Number(c.propuesta_antes_iva));
  var crec=(pIni!=null&&pAct!=null)?(pAct-pIni):null;
  var crecPct=(crec!=null&&pIni&&pIni>0)?(' ('+(crec>0?'+':'')+((crec/pIni)*100).toFixed(1)+'%)'):'';
  var crecTxt=(crec==null)?'\u2014':((crec>0?'+':'')+money(crec)+crecPct);
  var crecColor=(crec==null||crec===0)?'var(--txt2)':(crec>0?'var(--ok)':'var(--err)');
  h+='<div class="fsec"><h3>Propuesta comercial</h3><div class="fgrid">'+
     '<div class="ffield"><label>Valor inicial (primer contacto)</label><span class="fnum" style="color:var(--txt2)">'+(pIni==null?'\u2014':money(pIni))+'</span></div>'+
     fField('Propuesta actual antes de IVA','propuesta_antes_iva',c.propuesta_antes_iva,'num')+
     '<div class="ffield"><label>Crecimiento vs inicial</label><span class="fnum" style="color:'+crecColor+'">'+crecTxt+'</span></div>'+
     '<div class="ffield"><label>\u00daltima actualizaci\u00f3n</label><span style="color:var(--txt2);font-size:.85rem">'+(c.propuesta_updated_at?fmtFechaHora(c.propuesta_updated_at):'Sin cambios desde el inicial')+'</span></div>'+
     '</div><p class="muted" style="font-size:.78rem;margin-top:.4rem">El valor inicial queda congelado del primer contacto. La propuesta actual es la que suma al pipeline; al editarla se guarda sola la fecha del cambio.</p></div>';
  h+='<div class="fsec"><h3>Financiero y pagos</h3><div class="fgrid">'+
     fField('Condiciones de pago','condiciones_pago',c.condiciones_pago)+
     fField('Línea de crédito','linea_credito',c.linea_credito,'num')+
     '<div class="ffield"><label>Saldo actual</label><span class="fnum" style="color:var(--gold)">'+(c.saldo_actual==null?'\u2014':money(c.saldo_actual))+'</span></div>'+
     fField('Riesgo de crédito','riesgo_credito',c.riesgo_credito)+
     fField('Facturado','facturado',c.facturado,'num')+
     fField('Moneda','moneda',c.moneda)+'</div>'+
     '<p class="muted" style="font-size:.78rem;margin:.4rem 0 .9rem">El saldo ya no se escribe a mano: sale de restarle a la base los pagos capturados aqui mismo.</p>'+
     '<div id="fPagosBox">'+fPagosHtml()+'</div></div>';
  h+='<div class="fsec"><h3>Datos personalizados</h3><div class="fgrid">'+
     fField('Cumpleaños','cumpleanos',c.cumpleanos)+
     fField('Referido por','referido_por',c.referido_por)+
     fField('Industria','industria',c.industria)+
     fField('Tipo de origen','tipo_origen_lead',c.tipo_origen_lead)+'</div></div>';
  h+='<div class="fsec"><h3>Historial del lead</h3><div class="fgrid">'+
     fWide('Notas admin','notas_vero',c.notas_vero)+
     fWide('Notas de actualización','notas_actualizacion',c.notas_actualizacion)+
     fWide('Notas del asesor','notas_seguimiento',c.notas_seguimiento)+
     fWide('Notas generales','notas',c.notas)+'</div>';
  h+='<div style="margin-top:.8rem"><div style="display:flex;gap:.5rem;margin-bottom:.6rem"><input id="fNota" placeholder="Agregar al historial (llamada, visita, acuerdo...)" style="flex:1"><button class="btn" onclick="agregarNotaFicha()">Agregar</button></div>';
  var notas=FICHA.notas||[];
  if(!notas.length){ h+='<p class="muted" style="font-size:.83rem">Sin entradas en la bitácora todavía.</p>'; }
  else { h+='<div class="tl">'; notas.forEach(function(n){ h+='<div class="tl-item"><div class="muted" style="font-size:.72rem;margin-bottom:.15rem">'+fmtFechaHora(n.created_at)+(n.usuario?(' · '+escAttr(n.usuario)):'')+'</div><div>'+escAttr(n.nota||'')+'</div></div>'; }); h+='</div>'; }
  h+='</div></div>';
  var cots=FICHA.cotizaciones||[];
  h+='<div class="fsec"><h3>Cotizaciones y documentos</h3>';
  if(!cots.length){ h+='<p class="muted" style="font-size:.83rem">Sin cotizaciones ligadas a este cliente.</p>'; }
  else { h+='<div style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th title="Marca las cotizaciones que si forman la propuesta final">FINAL</th><th>Folio</th><th>Total</th><th>Estado</th><th>Vendedor</th><th>Proyecto</th><th>PDF</th></tr></thead><tbody>';
    cots.forEach(function(q){ var proy=q.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+q.proyecto_folio+'</span>'):'—';
      h+='<tr><td style="text-align:center"><input type="checkbox"'+(Number(q.propuesta_final)?' checked':'')+' onchange="marcarCotFinal('+q.id+',this.checked)"></td><td>'+(q.folio||'—')+'</td><td>'+money(q.total)+'</td><td>'+estadoPill(q.estado)+'</td><td>'+escAttr(q.vendedor||'—')+'</td><td>'+proy+'</td><td><button class="btn sec" style="padding:.2rem .5rem" onclick="pdfCotizacion('+q.id+')">PDF</button></td></tr>'; });
    h+='</tbody></table></div>'; }
  h+='<div id="fCotFinal">'+cotFinalHtml()+'</div>';
  h+='</div>';
  h+='<div class="fsec"><h3>Archivos y documentos</h3>'+
     '<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Comprobantes de pago, fotos del cliente, material que se le compartió, contratos. Máximo 10 MB por archivo.</p>'+
     '<div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:flex-end;margin-bottom:.7rem">'+
     '<div style="flex:1;min-width:200px"><label>Categoría</label><select id="faCat"><option>Comprobante de pago</option><option>Foto del cliente</option><option>Material compartido</option><option>Cotizacion</option><option>Contrato</option><option>Otro</option></select></div>'+
     '<div style="flex:2;min-width:220px"><label>Archivo(s)</label><input id="faFile" type="file" multiple></div>'+
     '<div><button class="btn" onclick="subirArchivoFicha()">Subir</button></div></div>'+
     '<div id="faLista"><p class="muted" style="font-size:.83rem">Cargando archivos…</p></div></div>';
  var prys=FICHA.proyectos||[];
  h+='<div class="fsec"><h3>Proyectos y compras</h3>';
  if(!prys.length){ h+='<p class="muted" style="font-size:.83rem">Sin proyectos registrados.</p>'; }
  else { h+='<div style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th>Folio</th><th>Descripción</th><th>Etapa</th><th>Avance</th><th>m²</th><th></th></tr></thead><tbody>';
    prys.forEach(function(p){ h+='<tr><td>'+(p.folio||'—')+'</td><td>'+escAttr(p.descripcion||'—')+'</td><td>'+escAttr(p.etapa_portal||p.estado||'—')+'</td><td>'+(p.avance_pct||0)+'%</td><td>'+(p.m2_totales||0)+'</td><td><button class="btn sec" style="padding:.2rem .5rem" onclick="abrirProyecto('+p.id+')">Ver</button></td></tr>'; });
    h+='</tbody></table></div>'; }
  h+='</div>';
  var cortes=FICHA.cortes||[];
  h+='<div class="fsec"><h3>Trazabilidad · de dónde viene cada material</h3>'+
     '<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Cadena: Material → Corte → Cotización → Cortador → Proyecto.</p>';
  if(!cortes.length){ h+='<p class="muted" style="font-size:.83rem">Aún no hay cortes ligados a este cliente.</p>'; }
  else { h+='<div style="overflow-x:auto"><table style="font-size:.8rem"><thead><tr><th>Material</th><th>Corte</th><th>Cant.</th><th>Cotización</th><th>Cortador</th><th>Proyecto</th><th>Estado</th></tr></thead><tbody>';
    cortes.forEach(function(x){ var cot=x.cotizacion_folio?('<span class="pill" style="background:var(--gold)">'+x.cotizacion_folio+'</span>'):'—'; var proy=x.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+x.proyecto_folio+'</span>'):'—';
      h+='<tr><td>'+escAttr(x.material||'—')+(x.material_sku?(' <span class="muted">'+escAttr(x.material_sku)+'</span>'):'')+'</td><td>'+(x.folio||'—')+'</td><td style="white-space:nowrap">'+(x.cantidad||0)+' '+escAttr(x.unidad||'')+'</td><td>'+cot+'</td><td>'+escAttr(x.cortador||'—')+'</td><td>'+proy+'</td><td>'+escAttr(x.estado||'—')+'</td></tr>'; });
    h+='</tbody></table></div>'; }
  h+='</div>';
  content.innerHTML=h;
  cargarArchivosFicha();
}
// ---- PAGOS DEL CLIENTE: historico con fecha (el cliente puede pagar en partes) ----
var CAT_PAGO_TIPO=['Anticipo','Pago parcial','Liquidacion','Reembolso','Ajuste'];
var CAT_PAGO_METODO=['Transferencia','Efectivo','Cheque','Tarjeta','Deposito','Otro'];
function hoyISO(){var d=new Date();return d.getFullYear()+'-'+('0'+(d.getMonth()+1)).slice(-2)+'-'+('0'+d.getDate()).slice(-2);}
function fPagosHtml(){
  var cb=(FICHA&&FICHA.cobranza)||{},pg=(FICHA&&FICHA.pagos)||[];
  var base=Number(cb.base||0),pagado=Number(cb.total_pagado||0),saldo=Number(cb.saldo||0);
  var org=(cb.base_origen==='facturado')?'Base tomada de lo facturado.':((cb.base_origen==='propuesta')?'Base tomada de la propuesta actual, porque todavia no hay factura.':'Aun no hay monto facturado ni propuesta para calcular la base.');
  var h='<div class="kpis" style="margin:.1rem 0 .7rem">'+kpiCard('Base a cobrar',money(base))+kpiCard('Pagado',money(pagado))+kpiCard('Saldo',money(saldo))+'</div>';
  h+='<p class="muted" style="font-size:.8rem;margin-bottom:.6rem">'+org+' Cada abono se captura con su fecha y el saldo se recalcula solo.</p>';
  var to='',mo='',i;
  for(i=0;i<CAT_PAGO_TIPO.length;i++)to+='<option>'+escT(CAT_PAGO_TIPO[i])+'</option>';
  for(i=0;i<CAT_PAGO_METODO.length;i++)mo+='<option>'+escT(CAT_PAGO_METODO[i])+'</option>';
  h+='<div style="display:flex;gap:.5rem;flex-wrap:wrap;align-items:flex-end;margin-bottom:.8rem">'+
     '<div style="min-width:150px"><label>Fecha del pago</label><input id="pgFecha" type="date" value="'+hoyISO()+'"></div>'+
     '<div style="min-width:130px"><label>Monto</label><input id="pgMonto" type="number" step="0.01" placeholder="0.00"></div>'+
     '<div style="min-width:150px"><label>Tipo</label><select id="pgTipo">'+to+'</select></div>'+
     '<div style="min-width:150px"><label>Metodo</label><select id="pgMetodo">'+mo+'</select></div>'+
     '<div style="min-width:160px"><label>Referencia</label><input id="pgRef" placeholder="Folio o transferencia"></div>'+
     '<div style="flex:1;min-width:180px"><label>Nota</label><input id="pgNota" placeholder="Observaciones"></div>'+
     '<div style="min-width:220px"><label>Comprobante</label><input id="pgComp" type="file"></div>'+
     '<div><button class="btn" onclick="agregarPagoFicha()">Registrar pago</button></div></div>';
  if(!pg.length){ h+='<p class="muted" style="font-size:.83rem">Sin pagos registrados todavia.</p>'; }
  else{
    var puedeTodo=(USER.rol==='admin'||USER.rol==='gerente'),acum=0;
    h+='<div style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th>Fecha</th><th>Tipo</th><th>Metodo</th><th>Referencia</th><th style="text-align:right">Monto</th><th>Nota</th><th>Capturo</th><th>Comprobante</th><th></th></tr></thead><tbody>';
    pg.forEach(function(p){
      acum+=Number(p.monto)||0;
      var mio=String(p.usuario_id)===String(USER.id);
      h+='<tr><td style="white-space:nowrap">'+fFecha(p.fecha)+'</td><td>'+escT(p.tipo||'\u2014')+'</td><td>'+escT(p.metodo||'\u2014')+'</td><td>'+escT(p.referencia||'\u2014')+'</td>'+
         '<td class="crmnum">'+money(p.monto)+'</td><td>'+escT(p.notas||'\u2014')+'</td><td style="white-space:nowrap">'+escT(p.usuario||'\u2014')+'</td>'+
         '<td style="white-space:nowrap">'+compPagoHtml(p)+'</td>'+
         '<td style="white-space:nowrap">'+((puedeTodo||mio)?('<button class="btn sec" style="padding:.25rem .55rem" onclick="borrarPagoFicha('+p.id+')">Eliminar</button>'):'')+'</td></tr>';
    });
    h+='</tbody><tfoot><tr><th colspan="4" style="text-align:right">Total pagado</th><th class="crmnum">'+money(acum)+'</th><th colspan="4"></th></tr></tfoot></table></div>';
  }
  h+='<div style="margin-top:.7rem"><button class="btn sec" onclick="recalcularSaldoFicha()">Recalcular saldo</button></div>';
  return h;
}
function compPagoHtml(p){
  if(p.archivo_url)return '<a class="btn sec" style="padding:.25rem .55rem;text-decoration:none" href="'+p.archivo_url+'" target="_blank" rel="noopener">Ver</a>';
  return '<input type="file" id="pgF'+p.id+'" style="width:140px;padding:.2rem;font-size:.68rem"> <button class="btn sec" style="padding:.25rem .55rem" onclick="subirComprobantePago('+p.id+')">Subir</button>';
}
// Sube el comprobante al mismo almacen de archivos del cliente y devuelve su id
async function subirComprobanteArchivo(f){
  if(f.size>10*1024*1024){ toast('El comprobante supera 10 MB'); return null; }
  var data;
  try{ data=await leerArchivoDataURL(f); }catch(e){ toast('No se pudo leer el comprobante'); return null; }
  var d=await api('/api/clientes/'+FICHA.id+'/archivos',{method:'POST',body:JSON.stringify({nombre:f.name,categoria:'Comprobante de pago',contentType:f.type||'application/octet-stream',data:data})});
  if(d&&d.ok&&d.data&&d.data.id)return d.data.id;
  toast((d&&d.error)||'No se pudo subir el comprobante');
  return null;
}
async function subirComprobantePago(id){
  var inp=document.getElementById('pgF'+id);
  if(!inp||!inp.files||!inp.files.length){ toast('Elige primero el archivo del comprobante'); return; }
  var aid=await subirComprobanteArchivo(inp.files[0]);
  if(!aid)return;
  var d=await api('/api/clientes/'+FICHA.id+'/pagos/'+id,{method:'PUT',body:JSON.stringify({archivo_id:aid})});
  if(d&&d.ok){ toast('Comprobante guardado'); await refrescarFicha(); }
  else if(d){ toast(d.error||'No se pudo guardar el comprobante'); }
}
async function refrescarFicha(){
  var cid=FICHA.id;
  var fresh=await api('/api/clientes/'+cid+'/ficha');
  if(fresh&&fresh.ok){ FICHA=fresh.data; FICHA.id=cid; renderFicha(); }
}
async function agregarPagoFicha(){
  var monto=parseFloat(val('pgMonto'));
  if(!monto||isNaN(monto)){ toast('Captura el monto del pago'); return; }
  var comp=document.getElementById('pgComp'),aid=null;
  if(comp&&comp.files&&comp.files.length){ aid=await subirComprobanteArchivo(comp.files[0]); if(!aid)return; }
  var body={fecha:val('pgFecha'),monto:monto,tipo:val('pgTipo'),metodo:val('pgMetodo'),referencia:val('pgRef'),notas:val('pgNota'),archivo_id:aid};
  var d=await api('/api/clientes/'+FICHA.id+'/pagos',{method:'POST',body:JSON.stringify(body)});
  if(d&&d.ok){ toast('Pago registrado'); await refrescarFicha(); }
  else if(d){ toast(d.error||'No se pudo registrar el pago'); }
}
async function borrarPagoFicha(id){
  if(!confirm('Eliminar este pago del historial? El saldo se recalcula.'))return;
  var d=await api('/api/clientes/'+FICHA.id+'/pagos/'+id,{method:'DELETE'});
  if(d&&d.ok){ toast('Pago eliminado'); await refrescarFicha(); }
  else if(d){ toast(d.error||'No se pudo eliminar'); }
}
async function recalcularSaldoFicha(){
  var d=await api('/api/clientes/'+FICHA.id+'/pagos/recalcular',{method:'POST',body:JSON.stringify({})});
  if(d&&d.ok){ toast('Saldo actualizado'); await refrescarFicha(); }
  else if(d){ toast(d.error||'No se pudo recalcular'); }
}
// ---- COTIZACIONES QUE SI FORMAN LA PROPUESTA FINAL ----
function cotFinalHtml(){
  var cots=(FICHA&&FICHA.cotizaciones)||[],n=0,sIva=0,sTot=0;
  cots.forEach(function(q){ if(Number(q.propuesta_final)){ n++; sIva+=Number(q.subtotal)||0; sTot+=Number(q.total)||0; } });
  if(!n)return '<p class="muted" style="font-size:.8rem;margin-top:.5rem">Marca la casilla FINAL de las cotizaciones que si forman la propuesta real del cliente. La suma pasa sola a PROP. S/IVA en el CRM; las demas quedan como historial.</p>';
  return '<div style="margin-top:.7rem"><span style="font-size:.86rem">Propuesta final: <b>'+n+'</b> cotizacion'+(n===1?'':'es')+' \u00b7 '+money(sIva)+' s/IVA \u00b7 '+money(sTot)+' con IVA</span>'+
    '<div class="muted" style="font-size:.78rem;margin-top:.25rem">Esa suma s/IVA ya quedo en PROP. S/IVA del CRM.</div></div>';
}
async function marcarCotFinal(id,ck){
  var d=await api('/api/cotizaciones/'+id,{method:'PUT',body:JSON.stringify({propuesta_final:ck?1:0})});
  if(!d||!d.ok){ toast((d&&d.error)||'No se pudo marcar la cotizacion'); return; }
  var prop=(d.data&&d.data.propuesta_antes_iva!=null)?d.data.propuesta_antes_iva:null;
  // Si el CRM esta cargado, la casilla PROP. S/IVA se actualiza en pantalla al momento
  if(prop!=null&&typeof CRM_ROWS!=='undefined'&&CRM_ROWS){
    var cli=null,i;
    for(i=0;i<CRM_ROWS.length;i++)if(FICHA&&String(CRM_ROWS[i].id)===String(FICHA.id))cli=CRM_ROWS[i];
    if(cli)cli.propuesta_antes_iva=prop;
  }
  if(document.getElementById('fCotFinal')&&FICHA&&FICHA.id){
    toast(prop!=null?('PROP. S/IVA actualizada: '+money(prop)):'Cotizacion desmarcada');
    await refrescarFicha();
    return;
  }
  toast(ck?'Cotizacion marcada para la propuesta final':'Cotizacion desmarcada');
}
function fmtTam(n){n=Number(n||0);if(n<1024)return n+' B';if(n<1048576)return (n/1024).toFixed(0)+' KB';return (n/1048576).toFixed(1)+' MB';}
async function cargarArchivosFicha(){
  var box=document.getElementById('faLista');if(!box||!FICHA||!FICHA.id)return;
  var d=await api('/api/clientes/'+FICHA.id+'/archivos');
  if(!d||!d.ok){box.innerHTML='<p class="muted" style="font-size:.83rem">'+((d&&d.error)||'No se pudieron cargar los archivos.')+'</p>';return;}
  var lista=d.data||[];FICHA.archivos=lista;
  if(!lista.length){box.innerHTML='<p class="muted" style="font-size:.83rem">Sin archivos todavía.</p>';return;}
  var puedeTodo=(USER.rol==='admin'||USER.rol==='gerente');
  var h='<div style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th>Archivo</th><th>Categoría</th><th>Tamaño</th><th>Subió</th><th>Fecha</th><th></th></tr></thead><tbody>';
  lista.forEach(function(a){
    var mio=String(a.usuario_id)===String(USER.id);
    h+='<tr><td><a href="'+a.url+'" target="_blank" rel="noopener" style="color:var(--gold)">'+escT(a.nombre)+'</a></td><td>'+escT(a.categoria||'—')+'</td><td style="white-space:nowrap">'+fmtTam(a.tamano)+'</td><td>'+escT(a.usuario||'—')+'</td><td style="white-space:nowrap">'+fmtFechaHora(a.created_at)+'</td>'+
       '<td style="white-space:nowrap"><a class="btn sec" style="padding:.3rem .6rem;text-decoration:none" href="'+a.url+'" target="_blank" rel="noopener">Abrir</a>'+((puedeTodo||mio)?(' <button class="btn sec" style="padding:.3rem .6rem" onclick="borrarArchivoFicha('+a.id+')">Eliminar</button>'):'')+'</td></tr>';
  });
  h+='</tbody></table></div>';
  box.innerHTML=h;
}
async function subirArchivoFicha(){
  var inp=document.getElementById('faFile');var cat=val('faCat')||'Otro';
  if(!inp||!inp.files||!inp.files.length){toast('Elige primero uno o más archivos');return;}
  var files=Array.prototype.slice.call(inp.files);var okN=0;
  for(var i=0;i<files.length;i++){
    var f=files[i];
    if(f.size>10*1024*1024){toast(f.name+': supera 10 MB, se omite');continue;}
    var data;try{data=await leerArchivoDataURL(f);}catch(e){toast(f.name+': no se pudo leer');continue;}
    var d=await api('/api/clientes/'+FICHA.id+'/archivos',{method:'POST',body:JSON.stringify({nombre:f.name,categoria:cat,contentType:f.type||'application/octet-stream',data:data})});
    if(d&&d.ok)okN++;else if(d)toast(f.name+': '+(d.error||'error'));
  }
  if(okN){toast(okN===1?'Archivo guardado':okN+' archivos guardados');inp.value='';}
  cargarArchivosFicha();
}
async function borrarArchivoFicha(id){
  if(!confirm('Eliminar este archivo de la ficha?'))return;
  var d=await api('/api/clientes/'+FICHA.id+'/archivos/'+id,{method:'DELETE'});
  if(d&&d.ok){toast('Archivo eliminado');cargarArchivosFicha();}else if(d){toast(d.error||'No se pudo eliminar');}
}

var INV_PROD=[];
var INV_PUEDE_EDITAR=false;
var MAT_CTRL=null;
async function viewInventario(c){
  INV_PUEDE_EDITAR=(USER.rol==='admin'||USER.rol==='gerente');
  var acc='';
  if(INV_PUEDE_EDITAR)acc+='<button class="btn" onclick="nuevoProducto()">+ Nuevo producto</button> ';
  acc+='<button class="btn sec" onclick="viewAlertasStock()">Alertas de stock</button> <button class="btn sec" onclick="viewMovimientos()">Movimientos</button> <button class="btn sec" onclick="viewProveedores()">Proveedores</button> <button class="btn sec" onclick="exportarInventarioCSV()">Exportar CSV</button>';
  document.getElementById('acciones').innerHTML=acc;
  var d=await api('/api/productos');if(!d||!d.ok)return;
  INV_PROD=d.data;
  var nota=INV_PUEDE_EDITAR?'<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Doble clic en una celda con borde punteado para editar. El stock se cambia con «Mov» para dejar registro.</p>':'';
  var h=nota+'<div class="card xls" tabindex="0"><table><thead><tr><th>SKU</th><th>Material</th><th>Categoría</th><th>Stock</th><th>Mín</th><th>Ubicación</th><th>Costo</th><th>Venta</th><th>Acciones</th></tr></thead><tbody>';
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
    '<div class="g2"><div><label>Stock inicial</label><input id="npStock" type="number" value="0"></div><div><label>Stock mínimo</label><input id="npMin" type="number" value="0"></div><div><label>Unidad</label><input id="npUni" value="m2"></div><div><label>Ubicación</label><input id="npUbi"></div><div><label>Precio costo</label><input id="npCosto" type="number" value="0"></div><div><label>Precio venta</label><input id="npVenta" type="number" value="0"></div></div>'+
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
  if(d&&d.ok){closeModal();toast('Movimiento registrado · stock: '+d.data.stock_actual+(d.data.bajo_minimo?' (¡bajo mínimo!)':''));if(MAT_CTRL){abrirMaterialControl(MAT_CTRL);}else{viewInventario(document.getElementById('content'));}}else if(d){toast(d.error);}
}
async function historialProd(prodId){
  var d=await api('/api/productos/'+prodId+'/movimientos');if(!d||!d.ok)return;
  var h='<div style="max-height:200px;overflow:auto;border-top:1px solid var(--bd);padding-top:.5rem"><table><thead><tr><th>Fecha</th><th>Tipo</th><th>Cant.</th><th>Motivo</th></tr></thead><tbody>';
  d.data.forEach(function(m){h+='<tr><td class="muted" style="font-size:.78rem">'+fmtFechaHora(m.created_at)+'</td><td>'+m.tipo+'</td><td>'+m.cantidad+'</td><td>'+(m.motivo||'—')+'</td></tr>';});
  if(!d.data.length)h+='<tr><td colspan="4" class="muted">Sin movimientos.</td></tr>';
  h+='</tbody></table></div>';
  document.getElementById('mvHist').innerHTML=h;
}
function qrProducto(prodId){
  var p=INV_PROD.find(function(x){return x.id===prodId;})||{};
  if(typeof qrcode==='undefined'){toast('Generador de QR no cargó, reintenta');return;}
  var clave=p.sku?p.sku:String(p.id);
  var url=location.origin+'/m/'+encodeURIComponent(clave);
  var qr=qrcode(0,'M');qr.addData(url);qr.make();
  var img=qr.createDataURL(6,8);
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.4rem">Etiqueta del material</h3>'+
    '<p class="muted" style="font-size:.82rem;margin-bottom:.7rem">Imprime y pega esta etiqueta en la losa o el rack. Al escanear el QR se abre el control de este material en el sistema: stock, ubicación, costo y movimientos.</p>'+
    '<div id="qrLabel" style="text-align:center;background:#fff;padding:16px;border-radius:8px">'+
      '<img id="qrImg" src="'+img+'" style="width:200px;height:200px;display:block;margin:0 auto">'+
      '<div style="font-family:Georgia,serif;font-size:1.25rem;color:#1a1a1a;margin-top:.35rem;line-height:1.15">'+escAttr(p.nombre||'')+'</div>'+
      '<div style="font-size:.85rem;color:#555;letter-spacing:.05em;margin-top:.1rem">'+escAttr(p.sku||'')+'</div>'+
      '<div style="font-size:.68rem;color:#999;margin-top:.25rem;letter-spacing:.06em">ESCANEA PARA CONTROL DE INVENTARIO · ASLAN</div>'+
    '</div>'+
    '<p class="muted" style="font-size:.72rem;margin-top:.5rem;word-break:break-all">Abre: '+escAttr(url)+'</p>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="descargarQR('+prodId+')">Descargar PNG</button><button class="btn sec" onclick="imprimirEtiqueta()">Imprimir</button><button class="btn sec" onclick="closeModal()">Cerrar</button></div>');
}
function descargarQR(prodId){
  var p=INV_PROD.find(function(x){return x.id===prodId;})||{};
  var sku=p.sku||String(prodId);
  var img=document.getElementById('qrImg');if(!img)return;
  var cv=document.createElement('canvas');cv.width=img.naturalWidth;cv.height=img.naturalHeight;
  cv.getContext('2d').drawImage(img,0,0);
  var a=document.createElement('a');a.href=cv.toDataURL('image/png');a.download='QR-'+sku+'.png';a.click();
}
function imprimirEtiqueta(){
  var el=document.getElementById('qrLabel');if(!el)return;
  var w=window.open('','_blank','width=420,height=560');
  if(!w){toast('Permite ventanas emergentes para imprimir');return;}
  w.document.write('<html><head><title>Etiqueta ASLAN</title></head><body style="margin:0;display:flex;align-items:center;justify-content:center;min-height:100vh;font-family:Georgia,serif">'+el.outerHTML+'</body></html>');
  w.document.close();
  setTimeout(function(){try{w.focus();w.print();}catch(e){}},300);
}
function irInv(){go('inventario');}
function controlMaterialHTML(p){
  var bajo=(Number(p.stock_actual)<=Number(p.stock_minimo));
  var color=Number(p.stock_actual)<=0?'var(--err)':(bajo?'var(--warn)':'var(--ok)');
  var estado=Number(p.stock_actual)<=0?'Sin existencias':(bajo?'En o bajo el mínimo':'En existencia');
  var h='<a class="back" onclick="irInv()">&larr; Volver a inventario</a>';
  h+='<div class="card"><h2 class="serif" style="color:var(--gold);font-size:1.7rem;line-height:1.1;margin:0">'+escAttr(p.nombre||'—')+'</h2>'+
     '<p class="muted" style="margin-top:.25rem">'+(p.sku?('<strong>'+escAttr(p.sku)+'</strong>'):'')+(p.categoria?(' · '+escAttr(p.categoria)):'')+(p.acabado?(' · '+escAttr(p.acabado)):'')+'</p></div>';
  h+='<div style="display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:.8rem;margin:1rem 0">'+
     '<div class="card" style="text-align:center"><div style="font-size:2rem;font-weight:700;color:'+color+'">'+(p.stock_actual!=null?p.stock_actual:0)+' <span style="font-size:.9rem">'+(p.unidad||'')+'</span></div><div class="muted" style="font-size:.74rem;text-transform:uppercase;letter-spacing:.04em">Stock actual · '+estado+'</div></div>'+
     '<div class="card" style="text-align:center"><div style="font-size:2rem;font-weight:700">'+(p.stock_minimo!=null?p.stock_minimo:0)+'</div><div class="muted" style="font-size:.74rem;text-transform:uppercase;letter-spacing:.04em">Stock mínimo</div></div>'+
     '<div class="card" style="text-align:center"><div style="font-size:1.3rem;font-weight:700;line-height:1.3;margin-top:.3rem">'+escAttr(p.ubicacion_almacen||'Sin asignar')+'</div><div class="muted" style="font-size:.74rem;text-transform:uppercase;letter-spacing:.04em">Ubicación en almacén</div></div>'+
     '</div>';
  if(bajo)h+='<div class="card" style="border-color:var(--warn);background:rgba(255,193,7,.08)"><strong style="color:var(--warn)">Conviene reabastecer.</strong> <span class="muted">El stock está en o por debajo del mínimo definido.</span></div>';
  h+='<div style="display:flex;gap:.5rem;flex-wrap:wrap;margin:1rem 0">'+
     '<button class="btn" onclick="movUI('+p.id+')">Registrar entrada / salida</button>'+
     '<button class="btn sec" onclick="qrProducto('+p.id+')">Ver / imprimir QR</button>'+
     '</div>';
  var filas='';
  function row(k,v){if(v!=null&&String(v).trim()!=='')filas+='<tr><td class="muted">'+k+'</td><td style="text-align:right">'+escAttr(String(v))+'</td></tr>';}
  row('Dimensiones',p.dimensiones);
  row('Procedencia',p.procedencia);
  row('Unidad de venta',p.unidad);
  if(INV_PUEDE_EDITAR){row('Precio costo',money(p.precio_costo));row('Precio venta',money(p.precio_venta));}
  if(p.notas_tecnicas)row('Notas técnicas',p.notas_tecnicas);
  if(filas)h+='<div class="card"><h3 class="serif" style="color:var(--gold);font-size:1.2rem;margin-bottom:.4rem">Ficha técnica</h3><table>'+filas+'</table></div>';
  h+='<div class="card"><h3 class="serif" style="color:var(--gold);font-size:1.2rem;margin-bottom:.4rem">Movimientos recientes</h3><div id="matMovs" class="muted">Cargando…</div></div>';
  return h;
}
async function abrirMaterialControl(clave){
  try{setActive('inventario');}catch(e){}
  var sd=document.getElementById('side');if(sd)sd.classList.remove('open');
  document.getElementById('acciones').innerHTML='';
  document.getElementById('titulo').textContent='Inventario';
  var c=document.getElementById('content');c.innerHTML='Cargando material…';
  INV_PUEDE_EDITAR=(USER.rol==='admin'||USER.rol==='gerente');
  var d=await api('/api/productos');
  if(!d||!d.ok){c.innerHTML='<a class="back" onclick="irInv()">&larr; Inventario</a><div class="card"><p class="muted">No se pudo cargar el inventario.</p></div>';return;}
  INV_PROD=d.data;
  var p=null,i;
  for(i=0;i<d.data.length;i++){var x=d.data[i];if((x.sku&&String(x.sku)===String(clave))||String(x.id)===String(clave)){p=x;break;}}
  if(!p){MAT_CTRL=null;c.innerHTML='<a class="back" onclick="irInv()">&larr; Inventario</a><div class="card"><h3 class="serif" style="color:var(--gold);font-size:1.4rem">Material no encontrado</h3><p class="muted" style="margin-top:.5rem">El código «'+escAttr(String(clave))+'» no corresponde a un material del inventario.</p></div>';return;}
  MAT_CTRL=p.sku?p.sku:String(p.id);
  c.innerHTML=controlMaterialHTML(p);
  var dm=await api('/api/productos/'+p.id+'/movimientos');
  var mc=document.getElementById('matMovs');if(!mc)return;
  if(dm&&dm.ok&&dm.data.length){
    var hh='<div style="max-height:240px;overflow:auto"><table><thead><tr><th>Fecha</th><th>Tipo</th><th>Cant.</th><th>Motivo</th></tr></thead><tbody>';
    dm.data.slice(0,30).forEach(function(m){hh+='<tr><td class="muted" style="font-size:.78rem;white-space:nowrap">'+fmtFechaHora(m.created_at)+'</td><td>'+m.tipo+'</td><td>'+m.cantidad+'</td><td>'+escAttr(m.motivo||'—')+'</td></tr>';});
    hh+='</tbody></table></div>';mc.innerHTML=hh;
  }else{mc.innerHTML='<p class="muted">Sin movimientos registrados.</p>';}
}
async function viewMovimientos(){
  document.getElementById('acciones').innerHTML='';
  document.getElementById('titulo').textContent='Movimientos de inventario';
  var c=document.getElementById('content');var d=await api('/api/movimientos');if(!d||!d.ok)return;
  var h='<button class="back" onclick="go(\\'inventario\\')">‹ Volver al catálogo</button><div class="card" style="overflow-x:auto"><table><thead><tr><th>Fecha</th><th>Producto</th><th>Tipo</th><th>Cant.</th><th>Motivo</th><th>Ref.</th><th>Usuario</th></tr></thead><tbody>';
  d.data.forEach(function(m){h+='<tr><td class="muted" style="font-size:.78rem;white-space:nowrap">'+fmtFechaHora(m.created_at)+'</td><td>'+(m.producto||'—')+'</td><td>'+m.tipo+'</td><td>'+m.cantidad+'</td><td>'+(m.motivo||'—')+'</td><td>'+(m.referencia||'—')+'</td><td class="muted">'+(m.usuario||'—')+'</td></tr>';});
  if(!d.data.length)h+='<tr><td colspan="7" class="muted">Sin movimientos registrados.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
async function viewAlertasStock(){
  document.getElementById('acciones').innerHTML='';
  document.getElementById('titulo').textContent='Alertas de stock';
  var c=document.getElementById('content');var d=await api('/api/productos');if(!d||!d.ok)return;
  INV_PROD=d.data;
  var bajos=d.data.filter(function(p){return p.stock_actual<=p.stock_minimo;});
  var h='<button class="back" onclick="go(\\'inventario\\')">‹ Volver al catálogo</button><div class="card"><table><thead><tr><th>SKU</th><th>Material</th><th>Stock</th><th>Mín</th><th></th></tr></thead><tbody>';
  bajos.forEach(function(p){
    var color=p.stock_actual<=0?'var(--err)':'var(--warn)';
    h+='<tr><td class="muted">'+(p.sku||'—')+'</td><td>'+p.nombre+'</td><td style="color:'+color+';font-weight:600">'+p.stock_actual+' '+p.unidad+'</td><td class="muted">'+p.stock_minimo+'</td><td><button class="btn sec" style="padding:.25rem .55rem" onclick="movUI('+p.id+')">Registrar entrada</button></td></tr>';
  });
  if(!bajos.length)h+='<tr><td colspan="5" class="muted">Todo el inventario está por encima del mínimo.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
async function viewProveedores(){
  document.getElementById('acciones').innerHTML=(USER.rol==='admin'||USER.rol==='gerente'?'<button class="btn" onclick="nuevoProveedor()">+ Nuevo proveedor</button> ':'');
  document.getElementById('titulo').textContent='Proveedores';
  var c=document.getElementById('content');var d=await api('/api/proveedores');if(!d||!d.ok)return;
  var h='<button class="back" onclick="go(\\'inventario\\')">‹ Volver al catálogo</button><div class="card" style="overflow-x:auto"><table><thead><tr><th>Nombre</th><th>País</th><th>Contacto</th><th>Teléfono</th><th>Email</th><th>Entrega (días)</th></tr></thead><tbody>';
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
  var h='<span class="back" onclick="go(\\'proyectos\\')">‹ Volver a proyectos</span>';
  h+='<div class="hd" style="margin-top:.4rem"><h2 style="font-size:1.6rem">'+(p.folio||'')+'</h2></div>';
  h+='<p class="muted" style="margin-top:-.6rem;margin-bottom:1rem">'+(p.descripcion||'')+' · Cliente: '+(cli.nombre||'—')+(cli.empresa?(' ('+cli.empresa+')'):'')+'</p>';

  if(!puede){c.innerHTML=h+'<div class="card muted">Solo administración o gerencia puede gestionar el portal. Tú puedes consultar el proyecto.</div>';return;}

  // Acceso al portal
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Acceso al portal</h3>';
  h+='<div style="display:flex;gap:.6rem;flex-wrap:wrap;align-items:center">';
  h+='<button class="btn '+(p.portal_activo?'':'sec')+'" onclick="togglePortal('+id+','+(p.portal_activo?0:1)+')">'+(p.portal_activo?'<svg viewBox="0 0 24 24" width="12" height="12" style="margin-right:.4rem" fill="currentColor"><circle cx="12" cy="12" r="6"/></svg>Portal ACTIVO — desactivar':'<svg viewBox="0 0 24 24" width="12" height="12" style="margin-right:.4rem" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="6"/></svg>Portal inactivo — activar')+'</button>';
  h+='<button class="btn sec" onclick="invitarPortal('+id+')">Invitar cliente por correo/WhatsApp</button></div>';
  h+='<div id="inviteRes" style="margin-top:.7rem"></div>';
  if(acc&&acc.ultimo_acceso)h+='<p class="muted" style="font-size:.78rem;margin-top:.5rem">Último acceso del cliente: '+acc.ultimo_acceso+'</p>';
  h+='</div>';

  // Etapa visible
  var opts='';
  d.data.etapas.forEach(function(e){opts+='<option value="'+e.clave+'"'+(p.etapa_portal===e.clave?' selected':'')+'>'+e.nombre+'</option>';});
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Etapa visible para el cliente</h3>';
  h+='<label>Etapa</label><select id="etapaSel">'+opts+'</select>';
  h+='<label>Nota para el cliente (opcional)</label><textarea id="etapaNota" rows="2" placeholder="Ej: Comenzamos el corte de tus cubiertas."></textarea>';
  h+='<label>Avance % (opcional)</label><input id="etapaAvance" type="number" min="0" max="100" placeholder="'+(p.avance_pct||0)+'">';
  h+='<div style="height:.7rem"></div><button class="btn" onclick="guardarEtapa('+id+')">Actualizar etapa</button></div>';

  // Avance del corte
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Progreso del corte</h3>';
  h+='<div class="g2">';
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

  // Fotos por etapa
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Fotos por etapa</h3>';
  h+='<p class="muted" style="font-size:.8rem;margin-bottom:.4rem">Sube fotos del avance; el cliente las verá en su portal.</p>';
  h+='<div class="g2"><div><label>Etapa</label><select id="fotoEtapa">'+opts+'</select></div><div><label>Descripción (opcional)</label><input id="fotoDesc"></div></div>';
  h+='<label>Imagen</label><input id="fotoFile" type="file" accept="image/*">';
  h+='<div style="height:.6rem"></div><button class="btn" onclick="subirFotoUI('+id+')">Subir foto</button>';
  h+='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(110px,1fr));gap:.5rem;margin-top:.8rem">';
  (d.data.fotos||[]).forEach(function(f){
    h+='<div style="position:relative"><img src="'+f.url+'" loading="lazy" style="width:100%;height:90px;object-fit:cover;border-radius:6px;border:1px solid var(--bd)"><button class="btn err" style="position:absolute;top:.2rem;right:.2rem;padding:.15rem .3rem;line-height:1" onclick="borrarFotoUI('+id+','+f.id+')"><svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2.5"><path d="M6 6l12 12M18 6L6 18"/></svg></button>'+(f.etapa?('<div class="muted" style="font-size:.66rem;margin-top:.15rem">'+f.etapa+'</div>'):'')+'</div>';
  });
  if(!(d.data.fotos||[]).length)h+='<p class="muted" style="font-size:.8rem;grid-column:1/-1">Aún no hay fotos.</p>';
  h+='</div></div>';

  // Chat
  h+='<div class="card"><h3 style="color:var(--gold);font-size:1.2rem;margin-bottom:.5rem">Chat con el cliente (portal)</h3><div style="max-height:240px;overflow:auto;padding:.3rem 0">';
  (d.data.mensajes||[]).forEach(function(m){
    var mine=m.direction==='aslan';
    h+='<div style="max-width:80%;padding:.5rem .8rem;border-radius:10px;margin:.3rem 0;font-size:.86rem;'+(mine?'background:var(--gold);color:#fff;margin-left:auto':'background:var(--card2);border:1px solid var(--bd)')+'">'+m.mensaje+'</div>';
  });
  if(!(d.data.mensajes||[]).length)h+='<p class="muted" style="font-size:.85rem">Sin mensajes todavía.</p>';
  h+='</div><div style="display:flex;gap:.5rem;margin-top:.6rem"><input id="admMsg" placeholder="Responder al cliente…" onkeydown="if(event.key===\\'Enter\\')responderPortal('+id+')"><button class="btn" onclick="responderPortal('+id+')">Enviar</button></div></div>';

  c.innerHTML=h;
}
async function togglePortal(id,activo){var d=await api('/api/admin/proyectos/'+id+'/portal/toggle',{method:'PUT',body:JSON.stringify({activo:!!activo})});if(d&&d.ok){toast(activo?'Portal activado':'Portal desactivado');abrirProyecto(id);}}
async function guardarEtapa(id){var d=await api('/api/admin/proyectos/'+id+'/portal/etapa',{method:'PUT',body:JSON.stringify({etapa_clave:document.getElementById('etapaSel').value,nota:document.getElementById('etapaNota').value,avance_pct:document.getElementById('etapaAvance').value})});if(d&&d.ok){toast('Etapa actualizada — el cliente fue notificado');abrirProyecto(id);}else if(d){toast(d.error);}}
async function guardarAvance(id){var d=await api('/api/admin/proyectos/'+id+'/portal/avance',{method:'PUT',body:JSON.stringify({avance_pct:document.getElementById('avPct').value,m2_procesados:document.getElementById('avProc').value,m2_totales:document.getElementById('avTot').value,fecha_entrega_estimada:document.getElementById('avFecha').value})});if(d&&d.ok){toast('Avance guardado');abrirProyecto(id);}}
async function agregarLosa(id){var desc=document.getElementById('losaDesc').value;if(!desc){toast('Describe la losa');return;}var d=await api('/api/admin/proyectos/'+id+'/portal/losa',{method:'POST',body:JSON.stringify({descripcion_losa:desc,foto_url_losa:document.getElementById('losaFoto').value})});if(d&&d.ok){toast('Losa agregada para aprobación');abrirProyecto(id);}}
async function subirFotoUI(id){
  var inp=document.getElementById('fotoFile');
  if(!inp||!inp.files||!inp.files[0]){toast('Elige una imagen');return;}
  var file=inp.files[0];
  if(file.size>8*1024*1024){toast('La imagen supera 8 MB');return;}
  toast('Subiendo…');
  var reader=new FileReader();
  reader.onload=async function(){
    var d=await api('/api/admin/proyectos/'+id+'/fotos',{method:'POST',body:JSON.stringify({data:reader.result,contentType:file.type,etapa:document.getElementById('fotoEtapa').value,descripcion:document.getElementById('fotoDesc').value})});
    if(d&&d.ok){toast('Foto subida');abrirProyecto(id);}else if(d){toast(d.error||'No se pudo subir');}
  };
  reader.onerror=function(){toast('No se pudo leer la imagen');};
  reader.readAsDataURL(file);
}
async function borrarFotoUI(id,fotoId){
  var d=await api('/api/admin/proyectos/'+id+'/fotos/'+fotoId,{method:'DELETE'});
  if(d&&d.ok){toast('Foto eliminada');abrirProyecto(id);}
}
async function responderPortal(id){var inp=document.getElementById('admMsg');if(!inp.value.trim())return;var d=await api('/api/admin/proyectos/'+id+'/portal/mensaje',{method:'POST',body:JSON.stringify({mensaje:inp.value})});if(d&&d.ok){inp.value='';abrirProyecto(id);}}
async function invitarPortal(id){
  var d=await api('/api/admin/proyectos/'+id+'/portal/invitar',{method:'POST',body:JSON.stringify({})});
  var box=document.getElementById('inviteRes');if(!box)return;
  if(!d||!d.ok){box.innerHTML='<span style="color:var(--err)">'+((d&&d.error)||'Error')+'</span>';return;}
  var msg=d.data.mensaje_whatsapp||'';
  var h='<div style="background:var(--inset);border:1px solid var(--bd);border-radius:6px;padding:.7rem;font-size:.85rem">';
  if(d.data.ya_existia){h+='<p style="color:var(--ok)">El cliente ya tiene acceso. Acceso por: <strong>'+d.data.url+'</strong> · Usuario: '+d.data.email+'</p>';}
  else{h+='<p style="color:var(--ok)">Acceso creado.</p><p>Acceso: <strong>'+d.data.url+'</strong></p><p>Usuario: '+d.data.email+'</p><p>Contraseña temporal: <strong style="color:var(--gold)">'+d.data.password_temporal+'</strong></p>';}
  h+='<div style="display:flex;gap:.5rem;margin-top:.5rem"><button class="btn sec" onclick="navigator.clipboard.writeText('+JSON.stringify(msg)+');toast(\\'Mensaje copiado\\')">Copiar mensaje para el cliente</button></div></div>';
  box.innerHTML=h;
}

// ====================== COTIZACIONES ======================
function volverCot(){go('cotizaciones');}
async function viewCotizaciones(c){
  document.getElementById('acciones').innerHTML='<button class="btn" onclick="nuevaCotizacion()">+ Nueva cotización</button>';
  var d=await api('/api/cotizaciones');if(!d||!d.ok)return;
  var h='<div class="card"><table><thead><tr><th title="Cotizaciones que forman la propuesta final del cliente">FINAL</th><th>Folio</th><th>Cliente</th><th>Total</th><th>Estado</th><th>Vendedor</th><th>Proyecto</th><th>Acciones</th></tr></thead><tbody>';
  d.data.forEach(function(r){
    var conv=(r.estado==='aceptada'&&!r.proyecto_folio)?' <button class="btn" style="padding:.3rem .6rem" onclick="convertirCot('+r.id+')"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:.3rem"><path d="M5 12h14M13 6l6 6-6 6"/></svg>Proyecto</button>':'';
    var proy=r.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+r.proyecto_folio+'</span>'):'—';
    h+='<tr><td style="text-align:center"><input type="checkbox"'+(Number(r.propuesta_final)?' checked':'')+' onchange="marcarCotFinal('+r.id+',this.checked)"></td><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+money(r.total)+(r.moneda==='USD'?' USD':'')+'</td><td>'+estadoCotSel(r.estado,r.id)+'</td><td>'+(r.vendedor||'—')+'</td><td>'+proy+'</td>'+
       '<td style="white-space:nowrap"><button class="btn sec" style="padding:.3rem .6rem" onclick="pdfCotizacion('+r.id+')">PDF</button> <button class="btn sec" style="padding:.3rem .6rem" onclick="editarCotizacion('+r.id+')">Editar</button> <button class="btn err" style="padding:.3rem .6rem" onclick="eliminarCot('+r.id+')">Eliminar</button>'+conv+'</td></tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="8" class="muted">Sin cotizaciones. Crea la primera.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
function estadoCotSel(e,id){
  var ops=['borrador','enviada','aceptada','rechazada','expirada'].map(function(s){return '<option value="'+s+'"'+(s===e?' selected':'')+'>'+s+'</option>';}).join('');
  return '<select style="width:auto;padding:.25rem .4rem;font-size:.78rem" onchange="cambiarEstadoCot('+id+',this.value)">'+ops+'</select>';
}
async function cambiarEstadoCot(id,estado){var d=await api('/api/cotizaciones/'+id,{method:'PUT',body:JSON.stringify({estado:estado})});if(d&&d.ok)toast('Estado: '+estado);}
var _CONFIRM_CB=null;
function confirmModal(msg,txtOk,cb){_CONFIRM_CB=cb;openModal('<h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Confirmar</h3><p style="font-size:.92rem;line-height:1.5;margin-bottom:1.1rem">'+msg+'</p><div style="display:flex;gap:.5rem"><button class="btn" onclick="confirmModalOk()">'+(txtOk||'Aceptar')+'</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');}
function confirmModalOk(){var cb=_CONFIRM_CB;_CONFIRM_CB=null;if(typeof closeModal==='function')closeModal();if(typeof cb==='function')cb();}
function convertirCot(id){confirmModal('¿Convertir esta cotización en proyecto? Se creará un proyecto ligado a esta cotización.','Sí, convertir',function(){_convertirCot(id);});}
async function _convertirCot(id){var d=await api('/api/cotizaciones/'+id+'/convertir',{method:'POST',body:JSON.stringify({})});if(d&&d.ok){toast('Proyecto '+d.data.folio+' creado');go('proyectos');}else if(d){toast(d.error);}}

var COT_PROD=[];var cotSeq=0;var COT_EDIT=null;
async function nuevaCotizacion(preselectId){COT_EDIT=null;await formCotizacion(preselectId,null);}
async function editarCotizacion(id){
  var d=await api('/api/cotizaciones/'+id);
  if(!d||!d.ok){toast('No se pudo cargar la cotización');return;}
  COT_EDIT=d.data;COT_EDIT.id=id;
  await formCotizacion(d.data.cliente_id,d.data);
}
async function formCotizacion(preselectId,ed){
  document.getElementById('acciones').innerHTML='';
  document.getElementById('titulo').textContent=ed?('Editar cotización '+(ed.folio||'')):'Nueva cotización';
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  var dc=await api('/api/clientes');var dp=await api('/api/productos');
  if(!dc||!dp)return;
  COT_PROD=dp.data;
  var cliOpts='<option value="">— Selecciona cliente —</option>';
  dc.data.forEach(function(cl){var sel=(preselectId&&String(cl.id)===String(preselectId))?' selected':'';cliOpts+='<option value="'+cl.id+'"'+sel+'>'+escAttr(cl.nombre)+(cl.empresa?(' · '+escAttr(cl.empresa)):'')+'</option>';});
  var asesorNom=(ed&&ed.vendedor)?ed.vendedor:((USER&&USER.nombre)?USER.nombre:'—');
  var vVig=ed?(ed.vigencia_dias||7):7;
  var vDescG=ed?(ed.descuento_global_pct||0):0;
  var vIva=(ed&&ed.iva_pct!=null)?ed.iva_pct:((CFG&&CFG.iva!=null)?CFG.iva:16);
  var vPago=ed?(ed.cond_pago||''):'100% ANTICIPADO';
  var vEntC=ed?(ed.cond_entrega||''):'';
  var vNoInc=ed?(ed.cond_no_incluye||''):'NO INCLUYE ENVÍO O DESCARGA DE MATERIAL';
  var vNotas=ed?(ed.notas||''):'TIEMPO DE ENTREGA DE 3 A 5 DIAS HABILES UNA VEZ ACREDITADO EL ANTICIPO, PRECIO SUJETO A TIPO DE CAMBIO';
  var vEntDir=ed?(ed.entrega_direccion||''):'';
  var vEntRef=ed?(ed.entrega_referencias||''):'';
  var vEntTel=ed?(ed.entrega_telefono||''):'';
  var vMon=(ed&&ed.moneda&&String(ed.moneda).toUpperCase()==='USD')?'USD':'MXN';
  var h='<span class="back" onclick="volverCot()">‹ Volver</span>';
  h+='<div class="card" style="margin-top:.5rem">';
  h+='<div class="muted" style="font-size:.85rem;margin-bottom:.6rem">Asesor: <strong style="color:var(--gold)">'+escAttr(asesorNom)+'</strong></div>';
  h+='<label>Cliente</label><select id="cotCliente">'+cliOpts+'</select>';
  h+='<div style="overflow-x:auto;margin-top:1rem"><table><thead><tr><th>Material / Servicios</th><th>Descripción</th><th>Cant.</th><th>Unidad</th><th>P. Unit.</th><th>Desc%</th><th>Importe</th><th></th></tr></thead><tbody id="cotBody"></tbody></table></div>';
  h+='<button class="btn sec" style="margin-top:.6rem" onclick="agregarFila()">+ Agregar línea</button>';
  h+='<div class="g2" style="margin-top:1rem;max-width:430px;margin-left:auto"><div><label>Descuento global %</label><input id="cotDescG" type="number" value="'+vDescG+'" oninput="recalcCot()"></div><div><label>IVA %</label><input id="cotIva" type="number" value="'+vIva+'" oninput="recalcCot()"></div><div><label>Vigencia (días)</label><input id="cotVig" type="number" value="'+vVig+'"></div><div><label>Moneda</label><select id="cotMoneda" onchange="recalcCot()"><option value="MXN"'+(vMon==='MXN'?' selected':'')+'>MXN (pesos)</option><option value="USD"'+(vMon==='USD'?' selected':'')+'>USD (dólares)</option></select></div></div>';
  h+='<div style="text-align:right;margin-top:1rem"><div>Subtotal: <strong id="cotSub">$0.00</strong></div><div>IVA: <strong id="cotIvaM">$0.00</strong></div><div style="font-size:1.3rem;color:var(--gold);margin-top:.3rem">TOTAL: <strong id="cotTotal">$0.00</strong></div></div>';
  h+='<h3 class="serif" style="color:var(--gold);font-size:1.05rem;margin-top:1.1rem">Datos de entrega</h3>';
  h+='<div class="g2"><div><label>Dirección de entrega</label><input id="cotEntDir" value="'+escAttr(vEntDir)+'"></div><div><label>Referencias</label><input id="cotEntRef" value="'+escAttr(vEntRef)+'"></div><div><label>Teléfono de entrega</label><input id="cotEntTel" value="'+escAttr(vEntTel)+'"></div></div>';
  h+='<h3 class="serif" style="color:var(--gold);font-size:1.05rem;margin-top:1.1rem">Condiciones</h3>';
  h+='<div class="g2"><div><label>Pago</label><input id="cotCondPago" value="'+escAttr(vPago)+'"></div><div><label>Entrega</label><input id="cotCondEntrega" value="'+escAttr(vEntC)+'"></div><div><label>No incluye</label><input id="cotCondNoInc" value="'+escAttr(vNoInc)+'"></div></div>';
  h+='<label style="margin-top:1rem">Notas</label><textarea id="cotNotas" rows="2">'+escAttr(vNotas)+'</textarea>';
  h+='<div style="height:.8rem"></div><button class="btn" onclick="guardarCotizacion()">'+(ed?'Guardar cambios':'Guardar cotización')+'</button></div>';
  c.innerHTML=h;
  if(ed&&ed.items&&ed.items.length){
    ed.items.forEach(function(it){
      agregarFila();
      var rows=document.querySelectorAll('#cotBody tr.cotlin');var tr=rows[rows.length-1];
      var sel=tr.querySelector('select.c-mat');
      if(it.producto_id!=null){sel.value=String(it.producto_id);}
      tr.querySelector('.c-desc').value=it.descripcion||'';
      tr.querySelector('.c-cant').value=(it.cantidad!=null?it.cantidad:1);
      setUnidad(tr.querySelector('.c-uni'),it.unidad||'m2');
      tr.querySelector('.c-pu').value=(it.precio_unitario!=null?it.precio_unitario:0);
      tr.querySelector('.c-dl').value=(it.descuento_linea_pct!=null?it.descuento_linea_pct:0);
    });
    recalcCot();
  }else{agregarFila();}
}
function eliminarCot(id){confirmModal('¿Eliminar esta cotización? Se quitará de la lista y ya no será utilizable.','Sí, eliminar',function(){_eliminarCot(id);});}
async function _eliminarCot(id){var d=await api('/api/cotizaciones/'+id,{method:'DELETE'});if(d&&d.ok){toast('Cotización eliminada');go('cotizaciones');}else if(d){toast(d.error);}}
function setUnidad(sel,v){
  var found=false,i;
  for(i=0;i<sel.options.length;i++){if(sel.options[i].value===v)found=true;}
  if(!found){var o=document.createElement('option');o.value=v;o.textContent=v;sel.appendChild(o);}
  sel.value=v;
}
function agregarFila(){
  cotSeq++;
  var po='<option value="">— libre —</option>';
  po+='<optgroup label="Familias de material">';
  CAT_MATERIAL.forEach(function(m){po+='<option value="fam" data-precio="0" data-unidad="m2" data-nombre="'+escAttr(m)+'">'+escAttr(m)+'</option>';});
  po+='</optgroup>';
  po+='<optgroup label="Servicios">';
  CAT_SERVICIOS.forEach(function(s){po+='<option value="fam" data-precio="0" data-unidad="'+s[1]+'" data-nombre="'+escAttr(s[0])+'">'+escAttr(s[0])+'</option>';});
  po+='</optgroup>';
  if(COT_PROD.length){po+='<optgroup label="Inventario">';COT_PROD.forEach(function(p){po+='<option value="'+p.id+'" data-precio="'+(p.precio_venta||0)+'" data-unidad="'+(p.unidad||'m2')+'" data-nombre="'+escAttr(p.nombre)+'">'+escAttr(p.nombre)+'</option>';});po+='</optgroup>';}
  var tr=document.createElement('tr');tr.className='cotlin';
  tr.innerHTML='<td><select class="c-mat" onchange="autoProd(this)" style="min-width:150px">'+po+'</select></td>'+
    '<td><input class="c-desc" placeholder="Descripción" style="min-width:150px"></td>'+
    '<td><input class="c-cant" type="number" step="0.01" value="1" oninput="recalcCot()" style="width:70px"></td>'+
    '<td><select class="c-uni" style="width:70px"><option value="m2">m2</option><option value="ml">ml</option><option value="pza">pza</option></select></td>'+
    '<td><input class="c-pu" type="number" step="0.01" value="0" oninput="recalcCot()" style="width:95px"></td>'+
    '<td><input class="c-dl" type="number" step="0.01" value="0" oninput="recalcCot()" style="width:55px"></td>'+
    '<td class="c-sl" style="white-space:nowrap">$0.00</td>'+
    '<td><button class="btn err" style="padding:.25rem .55rem" onclick="this.closest(\\'tr\\').remove();recalcCot()">×</button></td>';
  document.getElementById('cotBody').appendChild(tr);
}
function autoProd(sel){
  var o=sel.options[sel.selectedIndex];var tr=sel.closest('tr');
  if(o&&o.value==='fam'){var dscF=tr.querySelector('.c-desc');if(!dscF.value)dscF.value=o.getAttribute('data-nombre')||'';setUnidad(tr.querySelector('.c-uni'),o.getAttribute('data-unidad')||'m2');}
  else if(o&&o.value){tr.querySelector('.c-pu').value=o.getAttribute('data-precio')||0;setUnidad(tr.querySelector('.c-uni'),o.getAttribute('data-unidad')||'m2');var dsc=tr.querySelector('.c-desc');if(!dsc.value)dsc.value=o.getAttribute('data-nombre')||'';}
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
  var monS=(document.getElementById('cotMoneda')||{}).value||'MXN';
  document.getElementById('cotSub').textContent=money(sub)+' '+monS;
  document.getElementById('cotIvaM').textContent=money(ivaM)+' '+monS;
  document.getElementById('cotTotal').textContent=money(total)+' '+monS;
}
function recogerLineas(){
  var items=[];
  document.querySelectorAll('#cotBody tr.cotlin').forEach(function(tr){
    var sel=tr.querySelector('select.c-mat');
    var pv=sel?sel.value:'';
    items.push({producto_id:(pv&&pv!=='fam')?pv:null,descripcion:tr.querySelector('.c-desc').value,cantidad:tr.querySelector('.c-cant').value,unidad:tr.querySelector('.c-uni').value,precio_unitario:tr.querySelector('.c-pu').value,descuento_linea_pct:tr.querySelector('.c-dl').value});
  });
  return items.filter(function(it){return it.descripcion||it.producto_id;});
}
async function guardarCotizacion(){
  var cliente=document.getElementById('cotCliente').value;
  if(!cliente){toast('Selecciona un cliente');return;}
  var items=recogerLineas();
  if(!items.length){toast('Agrega al menos una línea');return;}
  var body={cliente_id:cliente,items:items,
    descuento_global_pct:document.getElementById('cotDescG').value,
    iva_pct:document.getElementById('cotIva').value,
    vigencia_dias:document.getElementById('cotVig').value,
    moneda:(document.getElementById('cotMoneda')||{}).value||'MXN',
    notas:document.getElementById('cotNotas').value,
    entrega_direccion:document.getElementById('cotEntDir').value,
    entrega_referencias:document.getElementById('cotEntRef').value,
    entrega_telefono:document.getElementById('cotEntTel').value,
    cond_pago:document.getElementById('cotCondPago').value,
    cond_entrega:document.getElementById('cotCondEntrega').value,
    cond_no_incluye:document.getElementById('cotCondNoInc').value};
  if(COT_EDIT&&COT_EDIT.condiciones)body.condiciones=COT_EDIT.condiciones;
  if(COT_EDIT&&COT_EDIT.id){
    var d=await api('/api/cotizaciones/'+COT_EDIT.id,{method:'PUT',body:JSON.stringify(body)});
    if(d&&d.ok){toast('Cotización '+(COT_EDIT.folio||'')+' actualizada');COT_EDIT=null;go('cotizaciones');}else if(d){toast(d.error);}
  }else{
    var d2=await api('/api/cotizaciones',{method:'POST',body:JSON.stringify(body)});
    if(d2&&d2.ok){toast('Cotización '+d2.data.folio+' creada');go('cotizaciones');}else if(d2){toast(d2.error);}
  }
}
function escAttr(s){return String(s==null?'':s).replace(/"/g,'&quot;');}

async function pdfCotizacion(id){
  var d=await api('/api/cotizaciones/'+id);if(!d||!d.ok){toast('No se pudo cargar la cotización');return;}
  if(!window.jspdf||!window.jspdf.jsPDF){toast('Generador de PDF no cargó, reintenta');return;}
  var c=d.data;var gold=[139,109,63];var gris=[90,90,90];
  var doc=new window.jspdf.jsPDF();
  var L=14,R=196,W=R-L;
  // ----- Encabezado: logo (si esta cargado en Configuracion) o marca ASLAN + datos de la empresa -----
  var yTxt=30;
  var logoOk=false;
  if(CFG&&CFG.logo_data){
    try{
      var lp=doc.getImageProperties(CFG.logo_data);
      var lw=60,lh=lw*lp.height/lp.width;
      if(lh>22){lh=22;lw=lh*lp.width/lp.height;}
      doc.addImage(CFG.logo_data,(lp.fileType||'PNG'),L,9,lw,lh);
      yTxt=9+lh+6;logoOk=true;
    }catch(e){logoOk=false;}
  }
  if(!logoOk){
    doc.setFont('times','bold');doc.setFontSize(28);doc.setTextColor(gold[0],gold[1],gold[2]);
    doc.text((CFG&&CFG.nombre?CFG.nombre:${JSON.stringify(EMPRESA.nombre)}),L,22,{charSpace:2.5});
  }
  doc.setFont('helvetica','normal');
  doc.setFontSize(8.5);doc.setTextColor(gris[0],gris[1],gris[2]);
  var dir=doc.splitTextToSize((CFG&&CFG.direccion?CFG.direccion:${JSON.stringify(EMPRESA.direccion)}),96);
  doc.text(dir,L,yTxt);
  var yd=yTxt+dir.length*4;
  doc.text('Tel. '+(CFG&&CFG.telefono?CFG.telefono:${JSON.stringify(EMPRESA.telefono)}),L,yd);
  doc.text((CFG&&CFG.email?CFG.email:${JSON.stringify(EMPRESA.email)}),L,yd+4.5);
  // Folio / Fecha / Vigencia / Asesor (derecha)
  doc.setFontSize(15);doc.setTextColor(40);doc.text('COTIZACIÓN',R,18,{align:'right'});
  doc.setFontSize(9);doc.setTextColor(60);
  var hoy=new Date();var vig=new Date(hoy.getTime()+((c.vigencia_dias||7)*86400000));
  doc.text('Folio: '+(c.folio||''),R,26,{align:'right'});
  doc.text('Fecha: '+hoy.toLocaleDateString('es-MX').split('/').join('-'),R,31,{align:'right'});
  doc.text('Vigencia: '+vig.toLocaleDateString('es-MX').split('/').join('-'),R,36,{align:'right'});
  var monP=(c.moneda&&String(c.moneda).toUpperCase()==='USD')?'USD':'MXN';
  // Atiende: el asesor que genero la cotizacion (nombre, telefono y correo de su usuario)
  if(c.vendedor){
    doc.setFont(undefined,'bold');doc.text('Atiende: '+c.vendedor,R,41,{align:'right'});doc.setFont(undefined,'normal');
    doc.setFontSize(8.2);
    if(c.vendedor_telefono){doc.text('Tel. '+c.vendedor_telefono,R,45.5,{align:'right'});}
    if(c.vendedor_email){doc.text(String(c.vendedor_email),R,(c.vendedor_telefono?49.5:45.5),{align:'right'});}
    doc.setFontSize(9);
  }
  doc.setDrawColor(gold[0],gold[1],gold[2]);doc.setLineWidth(0.5);doc.line(L,55,R,55);
  // ----- Datos de Facturación / Datos de Entrega -----
  var yc=62;var midX=110;
  doc.setFontSize(10);doc.setTextColor(gold[0],gold[1],gold[2]);doc.setFont(undefined,'bold');
  doc.text('Datos de Facturación',L,yc);doc.text('Datos de Entrega',midX,yc);
  doc.setFont(undefined,'normal');doc.setFontSize(9);doc.setTextColor(40);
  function campo(et,va,x,y){doc.setTextColor(110);doc.text(et,x,y);doc.setTextColor(30);doc.text(va?String(va):'',x+doc.getTextWidth(et)+2,y);}
  var fy=yc+7;
  campo('Nombre del Cliente:',c.cliente||'',L,fy);
  campo('Razón Social:',c.cliente_razon||c.cliente_empresa||'',L,fy+5.5);
  campo('Dirección fiscal:',c.cliente_direccion||'',L,fy+11);
  campo('RFC:',c.cliente_rfc||'',L,fy+16.5);
  campo('Dirección:',c.entrega_direccion||c.cliente_direccion||'',midX,fy);
  campo('Referencias:',c.entrega_referencias||'',midX,fy+5.5);
  campo('Teléfono:',c.entrega_telefono||c.cliente_telefono||'',midX,fy+11);
  // ----- Tabla de partidas -----
  var body=(c.items||[]).map(function(it,i){return [String(i+1),it.descripcion||'',String(it.cantidad||0),(it.unidad||'m2'),money(it.precio_unitario),money(it.subtotal_linea)];});
  doc.autoTable({
    startY:fy+24,
    head:[['PARTIDA','MODELO','CANT.','UNIDAD','PRECIO UNITARIO ('+monP+')','TOTAL ('+monP+')']],
    body:body.length?body:[['','','','','','']],
    theme:'grid',
    headStyles:{fillColor:gold,textColor:255,fontSize:8.5,halign:'center'},
    styles:{fontSize:8.5,textColor:40,cellPadding:2},
    columnStyles:{0:{cellWidth:20,halign:'center'},1:{cellWidth:'auto'},2:{cellWidth:15,halign:'center'},3:{cellWidth:17,halign:'center'},4:{cellWidth:30,halign:'right'},5:{cellWidth:30,halign:'right'}}
  });
  var y=(doc.lastAutoTable?doc.lastAutoTable.finalY:90)+8;
  // ----- Totales (derecha) -----
  var base=c.subtotal*(1-(c.descuento_global_pct||0)/100);var ivaM=c.total-base;
  doc.setFontSize(9.5);doc.setTextColor(40);
  function tot(et,va,bold){doc.setFont(undefined,bold?'bold':'normal');doc.text(et,150,y,{align:'right'});doc.text(va,R,y,{align:'right'});y+=5.5;}
  tot('SUBTOTAL',money(c.subtotal),true);
  if(c.descuento_global_pct){tot('Descuento '+c.descuento_global_pct+'%','-'+money(c.subtotal-base),false);}
  tot('IVA ('+(c.iva_pct||16)+'%)',money(ivaM),false);
  doc.setDrawColor(gold[0],gold[1],gold[2]);doc.setLineWidth(0.3);doc.line(120,y-3.5,R,y-3.5);
  doc.setFontSize(11.5);doc.setTextColor(gold[0],gold[1],gold[2]);doc.setFont(undefined,'bold');
  doc.text('TOTAL '+monP,150,y+1,{align:'right'});doc.text(money(c.total),R,y+1,{align:'right'});
  doc.setFont(undefined,'normal');
  if(monP==='USD'){doc.setFontSize(8);doc.setTextColor(90);doc.text('Importes expresados en dólares americanos (USD).',R,y+6,{align:'right'});y+=5;}
  // ----- CONDICIONES / NOTAS / Términos / Firmas (formato original ASLAN) -----
  var yb=Math.max(y+12,(doc.lastAutoTable?doc.lastAutoTable.finalY:90)+14);
  doc.setFontSize(9.5);doc.setTextColor(40);doc.setFont(undefined,'bold');doc.text('CONDICIONES',L,yb);
  doc.setFont(undefined,'normal');doc.setFontSize(8.5);
  var cx1=L+28,cx2=L+152,cxm=(cx1+cx2)/2;
  function condLinea(et,val,yy){
    doc.setTextColor(40);doc.text(et,L,yy);
    doc.setTextColor(60);
    if(val)doc.text(String(val),cxm,yy,{align:'center'});
    doc.setDrawColor(80);doc.setLineWidth(0.3);doc.line(cx1,yy+1.3,cx2,yy+1.3);
  }
  var legacyCond=(!c.cond_pago&&!c.cond_entrega&&!c.cond_no_incluye&&c.condiciones);
  if(legacyCond){
    doc.setTextColor(60);var cc=doc.splitTextToSize(String(c.condiciones),W);doc.text(cc,L,yb+6);yb=yb+6+cc.length*4;
  }else{
    condLinea('Pago:',c.cond_pago||'',yb+7);
    condLinea('Entrega',c.cond_entrega||'',yb+13);
    condLinea('No incluye',c.cond_no_incluye||'',yb+19);
    yb=yb+23;
  }
  var yn=yb+7;
  doc.setTextColor(40);doc.setFont(undefined,'bold');doc.text('NOTAS:',L,yn);
  doc.setFont(undefined,'normal');doc.setTextColor(60);
  var nn=c.notas?doc.splitTextToSize(String(c.notas),118):[];
  if(nn.length)doc.text(nn,cxm,yn,{align:'center'});
  var ynEnd=yn+(nn.length?(nn.length-1)*4:0)+1.5;
  doc.setDrawColor(80);doc.setLineWidth(0.3);doc.line(cx1,ynEnd,cx2,ynEnd);
  yb=ynEnd+5;
  doc.setFontSize(8);doc.setTextColor(40);doc.setFont(undefined,'bold');doc.text('Términos y condiciones:',L,yb+5);
  doc.text('Una vez depositado el anticipo no hay cambios ni cancelaciones',L,yb+9.5);
  doc.setFont(undefined,'normal');doc.setTextColor(90);
  doc.text('El cliente es responsable por la solicitud del material, color y medidas',L,yb+13.5);
  doc.text('Al ser un material natural existirá cambio de tonalidades y relices naturales',L,yb+17.5);
  // Firmas: etiqueta arriba y línea abajo, como el formato original
  var yf=Math.min(yb+28,275);if(yf<yb+24)yf=yb+24;
  doc.setFontSize(8.5);doc.setTextColor(60);
  doc.text('Firma representante ASLAN',L+6,yf);
  doc.text('Firma de acuerdo Cliente',midX+6,yf);
  doc.setDrawColor(120);doc.setLineWidth(0.3);
  doc.line(L+6,yf+12,L+76,yf+12);doc.line(midX+6,yf+12,midX+76,yf+12);
  doc.save((c.folio||'cotizacion')+'.pdf');
}

var CFG=null;
async function cargarCFG(){try{var d=await api('/api/config');if(d&&d.ok)CFG=d.data;}catch(e){}}
cargarCFG();
renderNav();
refrescarBadgeAlertas();
document.addEventListener('keydown',xlsKey);document.addEventListener('mouseover',function(e){var t=e.target;var p=(t&&t.closest)?t.closest('.xls'):null;if(p)XLS_HOVER=p;});
if(USER.debe_cambiar){toast('Recuerda cambiar tu contraseña en Configuración');}
var _mat=null;try{_mat=sessionStorage.getItem('aslan_mat');if(_mat)sessionStorage.removeItem('aslan_mat');}catch(e){}
if(_mat){abrirMaterialControl(_mat);}else{go('dashboard');}
</script>${PWEYE}</body></html>`;
}

// ============================================================================
//  FRONTEND — CHECK-IN GPS (standalone móvil)
// ============================================================================
function matRedirectPage() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ASLAN · Material</title><style>body{background:#F4F1EA;color:#8B6D3F;font-family:'Montserrat',sans-serif;display:flex;align-items:center;justify-content:center;height:100vh;margin:0;letter-spacing:.06em}</style></head><body><div>Abriendo material…</div><script>try{var pp=location.pathname,ix=pp.indexOf('/m/');if(ix>=0){var sk=decodeURIComponent(pp.substring(ix+3).split('?')[0].split('#')[0]);if(sk)sessionStorage.setItem('aslan_mat',sk);}}catch(e){}var t=localStorage.getItem('aslan_token');location.replace(t?'/dashboard':'/login');</script></body></html>`;
}

function renderCheckin() {
  return `<!DOCTYPE html><html lang="es"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ASLAN · Check-in</title>${FONTS}<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"><script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script><style>${baseStyles(false)}
.wrap{max-width:460px;margin:0 auto;padding:1.4rem 1.1rem;text-align:center}
.clock{font-size:2.6rem;font-family:'Cormorant Garamond',serif;color:var(--gold);margin:.3rem 0 .2rem}
.big{width:172px;height:172px;border-radius:50%;font-size:1.02rem;font-weight:700;border:none;color:#fff;cursor:pointer;box-shadow:0 10px 30px rgba(90,70,35,.25);letter-spacing:.04em;padding:0 1rem;transition:.15s}
.big:disabled{opacity:.6;cursor:default}
.in{background:var(--ok)} .out{background:var(--err)}
#map{height:230px;border-radius:10px;overflow:hidden;margin:1.1rem 0;border:1px solid var(--bd);background:var(--inset)}
.zona{font-size:.86rem;padding:.45rem .8rem;border-radius:6px;display:inline-block;margin-top:.5rem}
</style></head><body>
<div class="wrap">
<h1 style="color:var(--gold);letter-spacing:.3em;font-size:1.8rem">ASLAN</h1>
<p class="muted" id="quien" style="font-size:.85rem;min-height:1rem"></p>
<div class="clock" id="clock">--:--</div>
<button class="big in" id="btn" onclick="accion()">REGISTRAR ENTRADA</button>
<div id="map"></div>
<p class="muted" id="estado">Pulsa para registrar tu ubicación</p>
<p style="margin-top:1rem"><a onclick="logout()" class="muted" style="cursor:pointer;font-size:.8rem">Cerrar sesión</a></p>
</div>
<script>
var TOKEN=localStorage.getItem('aslan_token');
var USER=JSON.parse(localStorage.getItem('aslan_user')||'null');
if(!TOKEN){location.href='/login';}
else if(USER&&USER.rol==='cliente'){location.href='/portal/dashboard';}
function H(){return {'Content-Type':'application/json','Authorization':'Bearer '+TOKEN};}
async function api(p,opt){opt=opt||{};opt.headers=H();var r=await fetch(p,opt);if(r.status===401){localStorage.clear();location.href='/login';return null;}return await r.json();}
function logout(){localStorage.clear();location.href='/login';}
var SIG='entrada',GEO=null,MAP=null,MARK=null;
function reloj(){document.getElementById('clock').textContent=new Date().toLocaleTimeString('es-MX',{hour:'2-digit',minute:'2-digit'});}
reloj();setInterval(reloj,1000);
if(USER)document.getElementById('quien').textContent=USER.nombre;
function setBtn(){var b=document.getElementById('btn');if(SIG==='salida'){b.textContent='REGISTRAR SALIDA';b.className='big out';}else{b.textContent='REGISTRAR ENTRADA';b.className='big in';}}
function initMap(lat,lon){
  if(typeof L==='undefined')return;
  if(!MAP){
    MAP=L.map('map').setView([lat,lon],16);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png',{maxZoom:19,attribution:'&copy; OpenStreetMap'}).addTo(MAP);
    if(GEO&&isFinite(GEO.lat))L.circle([GEO.lat,GEO.lon],{radius:GEO.radio,color:'#8B6D3F',weight:1.5,fillColor:'#8B6D3F',fillOpacity:.12}).addTo(MAP);
  }else{MAP.setView([lat,lon],16);}
  if(MARK)MARK.setLatLng([lat,lon]);else MARK=L.circleMarker([lat,lon],{radius:8,color:'#8B6D3F',weight:2,fillColor:'#A07D4A',fillOpacity:.9}).addTo(MAP);
  setTimeout(function(){try{MAP.invalidateSize();}catch(e){}},60);
}
async function cargarEstado(){
  var d=await api('/api/checkin/estado');if(!d||!d.ok)return;
  SIG=(d.data.ultimo_tipo==='entrada')?'salida':'entrada';
  GEO=d.data.geocerca;setBtn();
  if(GEO&&isFinite(GEO.lat))initMap(GEO.lat,GEO.lon);
}
function accion(){
  var b=document.getElementById('btn');b.disabled=true;
  var est=document.getElementById('estado');est.textContent='Obteniendo tu ubicación…';
  if(!navigator.geolocation){est.textContent='Tu dispositivo no permite ubicación.';b.disabled=false;return;}
  navigator.geolocation.getCurrentPosition(async function(pos){
    var lat=pos.coords.latitude,lon=pos.coords.longitude,prec=pos.coords.accuracy;
    initMap(lat,lon);
    var d=await api('/api/checkin',{method:'POST',body:JSON.stringify({tipo:SIG,lat:lat,lon:lon,precision:prec})});
    b.disabled=false;
    if(!d)return;
    if(!d.ok){est.textContent=d.error||'No se pudo registrar.';return;}
    var hora=new Date().toLocaleTimeString('es-MX',{hour:'2-digit',minute:'2-digit'});
    var msg=(d.data.tipo==='entrada'?'Entrada':'Salida')+' registrada a las '+hora+'.';
    if(d.data.dentro===true)est.innerHTML=msg+'<br><span class="zona" style="background:rgba(76,175,80,.15);color:var(--ok)">Dentro de la zona ('+d.data.distancia+' m del centro)</span>';
    else if(d.data.dentro===false)est.innerHTML=msg+'<br><span class="zona" style="background:rgba(229,57,53,.15);color:var(--err)">Fuera de la zona ('+d.data.distancia+' m del centro) — se notificó a tu supervisor</span>';
    else est.textContent=msg;
    SIG=(SIG==='entrada')?'salida':'entrada';setBtn();
  },function(){est.textContent='No se pudo obtener tu ubicación. Activa el GPS y permite el acceso.';b.disabled=false;},{enableHighAccuracy:true,timeout:10000,maximumAge:0});
}
cargarEstado();
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
.bar{height:8px;background:var(--inset);border-radius:99px;overflow:hidden;margin:.6rem 0}
.bar>i{display:block;height:100%;background:linear-gradient(90deg,var(--gold),var(--gold2))}
.etapa-pill{display:inline-block;padding:.25rem .8rem;border-radius:99px;font-size:.74rem;background:rgba(139,109,63,.18);color:var(--gold2);border:1px solid var(--bd)}
.tracker{display:flex;gap:.4rem;overflow-x:auto;padding:1rem 0}
.step{flex:0 0 auto;text-align:center;width:92px;opacity:.4}
.step.done{opacity:1} .step.current{opacity:1}
.step .dot{width:46px;height:46px;border-radius:50%;background:var(--inset);border:2px solid var(--bd);display:flex;align-items:center;justify-content:center;font-size:1.3rem;margin:0 auto .4rem}
.step.done .dot{border-color:var(--ok);background:rgba(76,175,80,.12)}
.step.current .dot{border-color:var(--gold);background:rgba(139,109,63,.2);animation:pulse 1.6s infinite}
@keyframes pulse{0%,100%{box-shadow:0 0 0 0 rgba(139,109,63,.5)}50%{box-shadow:0 0 0 8px rgba(139,109,63,0)}}
.step .nm{font-size:.66rem;color:var(--txt2);line-height:1.2}
.chat{max-height:300px;overflow-y:auto;padding:.5rem 0}
.msg{max-width:78%;padding:.6rem .9rem;border-radius:12px;margin:.4rem 0;font-size:.88rem}
.msg.aslan{background:var(--card2);border:1px solid var(--bd)}
.msg.cliente{background:var(--gold);color:#fff;margin-left:auto}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:4000;padding:1rem}
.modal.open{display:flex}
.modal .inner{background:var(--card);border:1px solid var(--gold);border-radius:10px;padding:1.4rem;max-width:380px;width:100%}
@media(max-width:768px){.nav{padding:.8rem 1rem}.nav h1{font-size:1.4rem;letter-spacing:.2em}.nav .right{gap:.6rem;font-size:.8rem}.container{padding:1rem}.serif-title{font-size:1.6rem}.modal{padding:0;align-items:flex-end}.modal .inner{max-width:none;width:100%;border-radius:14px 14px 0 0;max-height:92vh}.msg{max-width:86%}}
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
<div class="modal" id="revModal"><div class="inner">
<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.4rem">Solicitar revisión</h3>
<p class="muted" style="font-size:.86rem;margin-bottom:.5rem">Cuéntanos qué te gustaría revisar o cambiar de este material. Tu asesor lo recibirá.</p>
<label>Comentario</label><textarea id="revNota" rows="4" placeholder="Ej. El tono se ve más claro de lo que esperaba…"></textarea>
<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="enviarRevision()">Enviar solicitud</button><button class="btn sec" onclick="document.getElementById('revModal').classList.remove('open')">Cancelar</button></div>
</div></div>
<script>
var TOKEN=localStorage.getItem('aslan_token');
var USER=JSON.parse(localStorage.getItem('aslan_user')||'null');
if(!TOKEN||!USER){location.href='/login';}
else if(USER.rol!=='cliente'){location.href='/dashboard';} // el equipo va al sistema interno
function H(){return {'Content-Type':'application/json','Authorization':'Bearer '+TOKEN};}
async function api(p,opt){opt=opt||{};opt.headers=H();var r=await fetch(p,opt);if(r.status===401){localStorage.clear();location.href='/login';return null;}return await r.json();}
function logout(){localStorage.clear();location.href='/login';}
function ic(p,s){s=s||18;return "<svg viewBox='0 0 24 24' width='"+s+"' height='"+s+"' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'>"+p+"</svg>";}
function fecha(s){if(!s)return '—';var m=/^([0-9]{4})-([0-9]{2})-([0-9]{2})/.exec((''+s).trim());if(m)return m[3]+'-'+m[2]+'-'+m[1];try{return new Date(s.replace(' ','T')+'Z').toLocaleDateString('es-MX').split('/').join('-');}catch(e){return s;}}
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
       '<div style="display:flex;justify-content:space-between;align-items:start"><div><strong>'+(p.folio||'')+'</strong><br><span class="muted" style="font-size:.85rem">'+(p.descripcion||'')+'</span></div><span class="etapa-pill">'+ic(et.icono,15)+' '+et.nombre+'</span></div>'+
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
    h+='<div class="step '+cls+'"><div class="dot">'+ic(e.icono,22)+'</div><div class="nm">'+e.nombre+'</div></div>';
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
           '<div style="display:flex;gap:.5rem;flex-wrap:wrap"><button class="btn ok" onclick="aprobar('+id+','+l.id+')"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:.35rem"><path d="M5 12l4 4 10-10"/></svg>Aprobar este material</button>'+
           '<button class="btn sec" onclick="pedirRevision('+id+','+l.id+')">Solicitar revisión</button></div>';
      }else if(l.estado==='aprobado'){
        h+='<p style="color:var(--ok);font-size:.88rem;margin-top:.3rem"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:.3rem"><path d="M5 12l4 4 10-10"/></svg>Material aprobado'+(l.respondido_en?' el '+fecha(l.respondido_en):'')+'</p>';
      }else{
        h+='<p style="color:var(--warn);font-size:.88rem;margin-top:.3rem">Revisión solicitada — el equipo ASLAN se pondrá en contacto.</p>';
      }
      h+='</div>';
    });
    h+='</div>';
  }
  // Fotos del avance
  if((d.data.fotos_proyecto||[]).length){
    h+='<div class="card" style="margin-top:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Avance en fotos</h3>';
    h+='<div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(120px,1fr));gap:.5rem">';
    d.data.fotos_proyecto.forEach(function(f){
      var et=ETAPAS.find(function(x){return x.clave===f.etapa;});
      h+='<a href="'+f.url+'" target="_blank" style="display:block"><img src="'+f.url+'" loading="lazy" style="width:100%;height:100px;object-fit:cover;border-radius:8px;border:1px solid var(--bd)">'+(et?('<div class="muted" style="font-size:.68rem;margin-top:.2rem">'+et.nombre+'</div>'):'')+'</a>';
    });
    h+='</div></div>';
  }
  // Documentos
  h+='<div class="card" style="margin-top:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Documentos</h3>'+
     '<div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--bd)"><span><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.6" style="margin-right:.4rem;color:var(--gold2)"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>Cotización</span><span class="muted">Disponible</span></div>'+
     '<div style="display:flex;justify-content:space-between;padding:.4rem 0;border-bottom:1px solid var(--bd)"><span><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.6" style="margin-right:.4rem;color:var(--gold2)"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>Orden de trabajo</span><span class="muted">Disponible</span></div>'+
     '<div style="display:flex;justify-content:space-between;padding:.4rem 0"><span><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="1.6" style="margin-right:.4rem;color:var(--gold2)"><path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><path d="M14 3v5h5"/></svg>Remisión</span><span class="muted">Próximamente</span></div>'+
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
var REV_CTX=null;
function pedirRevision(proy,losa){REV_CTX={proy:proy,losa:losa};var t=document.getElementById('revNota');if(t)t.value='';document.getElementById('revModal').classList.add('open');}
async function enviarRevision(){
  if(!REV_CTX)return;
  var nota=(document.getElementById('revNota').value||'').trim();
  var d=await api('/api/portal/proyectos/'+REV_CTX.proy+'/losa/aprobar',{method:'POST',body:JSON.stringify({losa_id:REV_CTX.losa,aprobado:false,nota:nota})});
  document.getElementById('revModal').classList.remove('open');
  if(d&&d.ok){toast('Revisión solicitada');detalle(REV_CTX.proy);}else if(d){toast(d.error||'Error');}
}
async function aprobar(proy,losa){
  var d=await api('/api/portal/proyectos/'+proy+'/losa/aprobar',{method:'POST',body:JSON.stringify({losa_id:losa,aprobado:true})});
  if(d&&d.ok){toast('¡Material aprobado!');detalle(proy);}else if(d){toast(d.error||'Error');}
}
async function enviar(id){
  var inp=document.getElementById('msgInput');if(!inp.value.trim())return;
  var d=await api('/api/portal/proyectos/'+id+'/mensajes',{method:'POST',body:JSON.stringify({mensaje:inp.value})});
  if(d&&d.ok){inp.value='';detalle(id);}
}
function toast(t){var x=document.createElement('div');x.style.cssText='position:fixed;top:1rem;right:1rem;background:var(--card);color:var(--txt);border:1px solid var(--gold);box-shadow:0 6px 24px var(--cardsh);padding:.8rem 1.1rem;border-radius:6px;z-index:9999';x.textContent=t;document.body.appendChild(x);setTimeout(function(){x.remove();},2600);}
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
