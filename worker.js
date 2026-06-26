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
    "ALTER TABLE clientes ADD COLUMN propuesta_antes_iva REAL",
    "ALTER TABLE clientes ADD COLUMN moneda TEXT",
    "ALTER TABLE clientes ADD COLUMN facturado REAL"
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
async function dashboardStats(env) {
  const q = async (sql) => (await env.DB.prepare(sql).first()).n;
  const clientes = await q("SELECT COUNT(*) AS n FROM clientes WHERE deleted_at IS NULL");
  const cotizMes = await q("SELECT COUNT(*) AS n FROM cotizaciones WHERE deleted_at IS NULL AND created_at >= date('now','start of month')");
  const proyectos = await q("SELECT COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL AND estado NOT IN ('cerrado','entregado')");
  const stockCritico = await q("SELECT COUNT(*) AS n FROM productos WHERE deleted_at IS NULL AND stock_actual <= stock_minimo");
  const empleadosHoy = await q("SELECT COUNT(DISTINCT usuario_id) AS n FROM gps_checkins WHERE tipo='entrada' AND created_at >= date('now')");
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

async function dashboardCharts(env) {
  const cotiz = await env.DB.prepare(
    "SELECT strftime('%Y-%m', created_at) AS mes, COUNT(*) AS n, COALESCE(SUM(total),0) AS monto" +
    " FROM cotizaciones WHERE deleted_at IS NULL AND created_at >= date('now','-6 months') GROUP BY mes ORDER BY mes ASC"
  ).all();
  const proyEtapa = await env.DB.prepare(
    "SELECT etapa_portal AS etapa, COUNT(*) AS n FROM proyectos WHERE deleted_at IS NULL GROUP BY etapa_portal"
  ).all();
  const nombreEtapa = {};
  for (const e of ETAPAS) nombreEtapa[e.clave] = e.nombre;
  const proyectos_por_etapa = (proyEtapa.results || []).map((r) => ({ etapa: r.etapa, nombre: nombreEtapa[r.etapa] || r.etapa, n: r.n }));
  const cliEtapa = await env.DB.prepare(
    "SELECT COALESCE(etapa,'sin etapa') AS etapa, COUNT(*) AS n FROM clientes WHERE deleted_at IS NULL GROUP BY etapa ORDER BY n DESC"
  ).all();
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
async function handleClientes(request, env, payload, method, id) {
  if (method === "GET" && !id) {
    const r = await env.DB.prepare(
      "SELECT c.*, u.nombre AS empleado_nombre, (SELECT COUNT(*) FROM cotizaciones q WHERE q.cliente_id=c.id AND q.deleted_at IS NULL) AS num_cotizaciones FROM clientes c LEFT JOIN usuarios u ON u.id=c.empleado_asignado_id WHERE c.deleted_at IS NULL ORDER BY c.id DESC"
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
    if (!b.force) {
      const dcond = [], dbind = [];
      const dnom = (b.nombre || "").trim();
      if (dnom) { dcond.push("LOWER(TRIM(nombre)) = LOWER(?)"); dbind.push(dnom); }
      const dtel = (b.telefono || "").toString().replace(/[^0-9]/g, "");
      if (dtel) { dcond.push("REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(REPLACE(IFNULL(telefono,''),' ',''),'-',''),'(',''),')',''),'+',''),'.','') = ?"); dbind.push(dtel); }
      const dem = (b.email || "").trim();
      if (dem) { dcond.push("LOWER(TRIM(email)) = LOWER(?)"); dbind.push(dem); }
      if (dcond.length) {
        const dup = await env.DB.prepare("SELECT id,nombre,empresa,telefono,email,asesor FROM clientes WHERE deleted_at IS NULL AND (" + dcond.join(" OR ") + ") LIMIT 10").bind(...dbind).all();
        if ((dup.results || []).length) return ok({ duplicado: true, existentes: dup.results });
      }
    }
    const res = await env.DB.prepare(
      "INSERT INTO clientes (nombre,empresa,tipo,etapa,telefono,email,ciudad,direccion,rfc,notas,empleado_asignado_id,fecha_lead,origen,validacion,estatus_final,asesor,estatus_nota,fecha_contacto,propuesta_factura,notas_vero,notas_actualizacion,notas_seguimiento,material,propuesta_antes_iva,moneda,facturado) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)"
    ).bind(b.nombre, b.empresa || null, b.tipo || null, b.etapa || "prospecto", b.telefono || null,
           b.email || null, b.ciudad || null, b.direccion || null, b.rfc || null, b.notas || null,
           b.empleado_asignado_id || null,
           b.fecha_lead || null, b.origen || null, b.validacion || null, b.estatus_final || null,
           b.asesor || null, b.estatus_nota || null, b.fecha_contacto || null, b.propuesta_factura || null,
           b.notas_vero || null, b.notas_actualizacion || null, b.notas_seguimiento || null,
           b.material || null, (b.propuesta_antes_iva==null?null:b.propuesta_antes_iva), b.moneda || null,
           (b.facturado==null?null:b.facturado)).run();
    await audit(env, payload.sub, "crear", "clientes", res.meta.last_row_id, b, request);
    return ok({ id: res.meta.last_row_id });
  }
  if (method === "PUT" && id) {
    const b = await request.json().catch(() => ({}));
    const campos = ["nombre", "empresa", "tipo", "etapa", "telefono", "email", "ciudad", "direccion", "rfc", "notas", "empleado_asignado_id", "fecha_lead", "origen", "validacion", "estatus_final", "asesor", "estatus_nota", "fecha_contacto", "propuesta_factura", "notas_vero", "notas_actualizacion", "notas_seguimiento", "material", "propuesta_antes_iva", "moneda", "facturado", "telefono_alt", "sitio_web", "industria", "tipo_origen_lead", "proximo_seguimiento", "condiciones_pago", "linea_credito", "saldo_actual", "riesgo_credito", "probabilidad_cierre", "fecha_cierre_estimada", "proxima_accion", "cumpleanos", "referido_por"];
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
// ============================================================================
//  FICHA 360° — concentra TODO de un prospecto/cliente en una sola consulta
//  Datos + contacto + historial(notas) + cotizaciones + proyectos + trazabilidad
// ============================================================================
async function fichaCliente(env, id) {
  const c = await env.DB.prepare(
    "SELECT cl.*, u.nombre AS empleado_nombre FROM clientes cl LEFT JOIN usuarios u ON u.id=cl.empleado_asignado_id WHERE cl.id=? AND cl.deleted_at IS NULL"
  ).bind(id).first();
  if (!c) return fail("Cliente no encontrado.", 404);

  let contactos = { results: [] }, notas = { results: [] }, cortes = { results: [] };
  try { contactos = await env.DB.prepare("SELECT * FROM contactos_cliente WHERE cliente_id=? ORDER BY id DESC").bind(id).all(); } catch (e) {}
  try { notas = await env.DB.prepare("SELECT n.*, u.nombre AS usuario FROM notas_crm n LEFT JOIN usuarios u ON u.id=n.usuario_id WHERE n.cliente_id=? ORDER BY n.created_at DESC, n.id DESC").bind(id).all(); } catch (e) {}

  const cotis = await env.DB.prepare(
    "SELECT c.id, c.folio, c.estado, c.total, c.created_at, u.nombre AS vendedor," +
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

  const rc = cotis.results || [];
  const totalCotizado = rc.reduce((s, q) => s + (Number(q.total) || 0), 0);
  const totalAceptado = rc.filter((q) => q.estado === "aceptada").reduce((s, q) => s + (Number(q.total) || 0), 0);
  const m2 = (cortes.results || []).reduce((s, x) => s + (Number(x.cantidad) || 0), 0);

  return ok({
    cliente: c,
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
      saldo: Number(c.saldo_actual) || 0,
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

// Detecta posibles duplicados (telefono, correo o nombre) y los agrupa
async function duplicadosClientes(env) {
  const r = await env.DB.prepare("SELECT id,nombre,empresa,telefono,email,asesor FROM clientes WHERE deleted_at IS NULL").all();
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
    if (clienteFiltro) { sql += " AND c.cliente_id=?"; binds.push(clienteFiltro); }
    sql += " ORDER BY c.created_at DESC, c.id DESC";
    const r = await env.DB.prepare(sql).bind(...binds).all();
    return ok(r.results || []);
  }
  if (method === "GET" && id) {
    const c = await env.DB.prepare(
      "SELECT c.*, cl.nombre AS cliente, cl.empresa AS cliente_empresa, cl.rfc AS cliente_rfc, cl.direccion AS cliente_direccion, cl.telefono AS cliente_telefono FROM cotizaciones c LEFT JOIN clientes cl ON cl.id=c.cliente_id WHERE c.id=? AND c.deleted_at IS NULL"
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
    const existe = await env.DB.prepare("SELECT id FROM usuarios WHERE email=?").bind(b.email).first();
    if (existe) return fail("Ya existe un usuario con ese correo.");
    const rol = (b.rol === "gerente" || b.rol === "empleado") ? b.rol : "empleado";
    const pw = passwordTemporal();
    const ph = await hashPassword(pw);
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
  const r = await env.DB.prepare(
    "SELECT w.id,w.numero_wa,w.no_leidos,w.ultimo_mensaje_en,cl.nombre AS cliente," +
    " (SELECT m.contenido FROM wa_mensajes m WHERE m.conversacion_id=w.id ORDER BY m.created_at DESC, m.id DESC LIMIT 1) AS ultimo," +
    " (SELECT m.direction FROM wa_mensajes m WHERE m.conversacion_id=w.id ORDER BY m.created_at DESC, m.id DESC LIMIT 1) AS ultimo_dir" +
    " FROM wa_conversaciones w LEFT JOIN clientes cl ON cl.id=w.cliente_id" +
    " ORDER BY w.ultimo_mensaje_en DESC, w.id DESC LIMIT 100"
  ).all();
  return ok(r.results || []);
}
async function waVerConversacion(env, payload, id) {
  const conv = await env.DB.prepare("SELECT w.id,w.numero_wa,w.cliente_id,cl.nombre AS cliente FROM wa_conversaciones w LEFT JOIN clientes cl ON cl.id=w.cliente_id WHERE w.id=?").bind(id).first();
  if (!conv) return fail("Conversación no encontrada.", 404);
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
  const conv = await env.DB.prepare("SELECT id,numero_wa FROM wa_conversaciones WHERE id=?").bind(id).first();
  if (!conv) return fail("Conversación no encontrada.", 404);
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
async function getConfig(env) {
  const r = await env.DB.prepare("SELECT clave,valor FROM app_config").all();
  const map = {};
  for (const row of (r.results || [])) map[row.clave] = row.valor;
  return {
    nombre: map.nombre || EMPRESA.nombre || "ASLAN",
    direccion: map.direccion || EMPRESA.direccion || "",
    rfc: map.rfc || EMPRESA.rfc || "",
    telefono: map.telefono || EMPRESA.telefono || "",
    whatsapp: map.whatsapp || EMPRESA.whatsapp || "",
    email: map.email || EMPRESA.email || "",
    iva: map.iva != null ? Number(map.iva) : 16,
  };
}
async function handleConfig(request, env, payload, method) {
  if (method === "GET") {
    const cfg = await getConfig(env);
    cfg.sistema = { whatsapp: !!(env.WA_TOKEN && env.WA_PHONE_ID), fotos_r2: !!env.FILES, verify_token: !!env.WA_VERIFY_TOKEN };
    return ok(cfg);
  }
  if (!hasRole(payload, "admin")) return fail("Solo administración puede cambiar la configuración.", 403);
  const b = await request.json().catch(() => ({}));
  const campos = ["nombre", "direccion", "rfc", "telefono", "whatsapp", "email", "iva"];
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

async function handleRequest(request, env) {
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method;

  if (method === "OPTIONS") return new Response(null, { headers: CORS });

  await migrarV3(env);
  await migrarV4(env);
  await migrarV5(env);

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
    if (path === "/api/dashboard/charts") return await dashboardCharts(env);

    let m;
    if (path === "/api/clientes/duplicados" && method === "GET") return await duplicadosClientes(env);
    m = path.match(/^\/api\/clientes\/(\d+)\/ficha$/);
    if (m && method === "GET") return await fichaCliente(env, m[1]);
    m = path.match(/^\/api\/clientes\/(\d+)\/notas$/);
    if (m && method === "POST") return await agregarNotaCliente(request, env, payload, m[1]);
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
    if (path === "/api/config") return await handleConfig(request, env, payload, method);
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
  if (path.startsWith("/media/foto/")) return await serveFoto(request, env, path, url);
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
svg{vertical-align:middle;flex-shrink:0}
input[type=number]{-moz-appearance:textfield;appearance:textfield}
input[type=number]::-webkit-outer-spin-button,input[type=number]::-webkit-inner-spin-button{-webkit-appearance:none;margin:0}
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
<title>ASLAN · Panel</title>${FONTS}<script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf/2.5.1/jspdf.umd.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jspdf-autotable/3.8.2/jspdf.plugin.autotable.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcode-generator/1.4.4/qrcode.min.js"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"><script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.min.js"></script><style>${baseStyles(false)}
.crmtable{border-collapse:collapse;min-width:1980px;font-size:.8rem}
.crmtable th{position:sticky;top:0;background:#1d1a14;color:var(--gold);font-size:.7rem;letter-spacing:.02em;padding:.5rem .55rem;border:1px solid var(--bd);white-space:nowrap;text-align:left;z-index:2}
.crmtable td{border:1px solid var(--bd);padding:.4rem .55rem;vertical-align:top}
.crmc{min-width:110px;outline:none;cursor:text}
.crmc:focus{background:rgba(139,109,63,.16);box-shadow:inset 0 0 0 2px var(--gold)}
.crmnum{text-align:right;white-space:nowrap;color:var(--gold);font-weight:600}
.crmwide{min-width:260px;max-width:360px;white-space:normal;font-size:.76rem;color:var(--txt2)}
.ficha-head{display:flex;justify-content:space-between;align-items:flex-start;gap:1rem;flex-wrap:wrap;border-bottom:1px solid var(--bd);padding-bottom:.8rem;margin-top:.3rem}
.ficha-name{font-family:'Cormorant Garamond',serif;font-size:1.9rem;color:var(--gold);line-height:1.1}
.ficha-actions{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap}
.fsec{background:var(--card);border:1px solid var(--bd);border-radius:12px;padding:1rem;margin-top:1rem}
.fsec h3{font-family:'Cormorant Garamond',serif;color:var(--gold);font-size:1.25rem;margin-bottom:.7rem}
.fgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:.7rem}
.ffield{display:flex;flex-direction:column;gap:.2rem}
.ffield label,.fwide label{font-size:.72rem;text-transform:uppercase;letter-spacing:.04em;color:var(--txt2)}
.fwide{grid-column:1/-1;display:flex;flex-direction:column;gap:.2rem}
.fedit{background:#0f0f0f;border:1px solid var(--bd);border-radius:8px;padding:.45rem .6rem;font-size:.9rem;color:var(--txt);min-height:1.2rem;outline:none;word-break:break-word}
.fedit:focus{border-color:var(--gold);box-shadow:inset 0 0 0 1px var(--gold)}
.fedit:empty:before{content:attr(data-ph);color:var(--txt2);opacity:.45}
.fnum{font-variant-numeric:tabular-nums;color:var(--gold);font-weight:600}
.flink{color:var(--gold);cursor:pointer;text-decoration:underline;text-decoration-style:dotted;text-underline-offset:2px}
.tl{display:flex;flex-direction:column;gap:.5rem}
.tl-item{background:#0f0f0f;border-left:2px solid var(--gold);border-radius:6px;padding:.45rem .6rem;font-size:.86rem}
.crmfilt{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center;padding:.6rem;margin-bottom:.6rem}
.crmfilt input,.crmfilt select{width:auto;min-width:120px;padding:.4rem .55rem;font-size:.82rem;margin:0}
.crmfilt input[type=number]{min-width:110px}
.crmkpis{margin-bottom:.7rem}
.crmkpis .kpi{padding:.5rem .7rem}
.layout{display:flex;min-height:100vh}
.side{width:240px;background:#111;border-right:1px solid var(--bd);padding:1.2rem .8rem;flex-shrink:0;position:sticky;top:0;height:100vh;align-self:flex-start;display:flex;flex-direction:column;overflow-y:auto}
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
.tablero{display:flex;gap:.7rem;overflow-x:auto;padding:.3rem 0 .8rem}
.tcol{flex:0 0 250px;min-width:250px;background:#181818;border:1px solid var(--bd);border-radius:10px;padding:.5rem;display:flex;flex-direction:column}
.tcol h4{font-size:.74rem;letter-spacing:.04em;text-transform:uppercase;padding:.35rem .4rem;margin-bottom:.4rem;border-bottom:2px solid var(--bd);display:flex;justify-content:space-between;align-items:center}
.tcol .cnt{background:var(--gold);color:#1a1a1a;border-radius:99px;font-size:.66rem;padding:.04rem .42rem;font-weight:700}
.tcard{background:#222;border:1px solid var(--bd);border-radius:8px;padding:.55rem;margin-bottom:.5rem}
.tcard .nm{font-weight:600;font-size:.82rem;color:var(--txt)}
.tcard .mt{font-size:.74rem;color:var(--txt2);margin:.15rem 0}
.tcard select{font-size:.72rem;padding:.22rem .3rem;margin-top:.35rem}
.grid{display:grid;gap:1rem}
.charts-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(300px,1fr));gap:1rem;margin-bottom:1.4rem}
.wa{display:flex;gap:1rem}
.wa-list{width:300px;flex-shrink:0;max-height:72vh;overflow:auto}
.wa-thread{flex:1;display:flex;flex-direction:column;min-height:340px}
.wa-msgs{flex:1;max-height:58vh;overflow:auto;padding:.3rem}
.wa-conv{padding:.55rem .7rem;border:1px solid var(--bd);border-radius:8px;margin-bottom:.4rem;cursor:pointer}
.wa-conv:hover{border-color:var(--gold)}
.wa-conv.active{border-color:var(--gold);background:rgba(139,109,63,.12)}
.wa-b{max-width:80%;padding:.5rem .8rem;border-radius:12px;margin:.3rem 0;font-size:.9rem;word-wrap:break-word}
.wa-b.in{background:#222;border:1px solid var(--bd)}
.wa-b.out{background:var(--gold);color:#fff;margin-left:auto}
@media(max-width:768px){.wa{flex-direction:column}.wa-list{width:100%;max-height:40vh}}
@media(max-width:768px){.side{position:fixed;left:-260px;transition:.2s;z-index:50;height:100%}.side.open{left:0}.main{padding:1rem}.menu-btn{display:block!important}}
.menu-btn{display:none;background:none;border:1px solid var(--bd);color:var(--gold);padding:.4rem .7rem;border-radius:4px;font-size:1.2rem;cursor:pointer}
.modal{position:fixed;inset:0;background:rgba(0,0,0,.7);display:none;align-items:center;justify-content:center;z-index:99;padding:1rem}
.modal.open{display:flex}
.modal .inner{background:var(--card);border:1px solid var(--gold);border-radius:10px;padding:1.4rem;max-width:420px;width:100%;max-height:90vh;overflow:auto}
td[contenteditable]{cursor:text;border-bottom:1px dashed rgba(139,109,63,.4)}
td[contenteditable]:focus{outline:1px solid var(--gold);background:rgba(139,109,63,.08)}
@media(max-width:768px){.hd h2{font-size:1.5rem}.kpi .n{font-size:1.8rem}.kpis{grid-template-columns:1fr 1fr}.card{overflow-x:auto}.modal{padding:0;align-items:flex-end}.modal .inner{max-width:none;width:100%;border-radius:14px 14px 0 0;max-height:92vh}.side.open{box-shadow:0 0 40px rgba(0,0,0,.6)}}
</style></head><body>
<div class="layout">
<aside class="side" id="side">
<h1>ASLAN</h1>
<nav class="nav" id="nav"></nav>
<div class="user" id="userBox"></div>
</aside>
<main class="main">
<div class="hd"><button class="menu-btn" onclick="document.getElementById('side').classList.toggle('open')"><svg viewBox='0 0 24 24' width='22' height='22' fill='none' stroke='currentColor' stroke-width='1.8' stroke-linecap='round'><line x1='3' y1='6' x2='21' y2='6'/><line x1='3' y1='12' x2='21' y2='12'/><line x1='3' y1='18' x2='21' y2='18'/></svg></button><h2 id="titulo">Dashboard</h2><div id="acciones"></div></div>
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
function ic(p,s){s=s||18;return "<svg viewBox='0 0 24 24' width='"+s+"' height='"+s+"' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'>"+p+"</svg>";}
var ICONS={
  dashboard:"<rect x='3' y='3' width='7' height='9' rx='1'/><rect x='14' y='3' width='7' height='5' rx='1'/><rect x='14' y='12' width='7' height='9' rx='1'/><rect x='3' y='16' width='7' height='5' rx='1'/>",
  clientes:"<path d='M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2'/><circle cx='9' cy='7' r='4'/><path d='M23 21v-2a4 4 0 0 0-3-3.87'/><path d='M16 3.1a4 4 0 0 1 0 7.75'/>",
  cotizaciones:"<path d='M6 2h9l5 5v13a1 1 0 0 1-1 1H6a1 1 0 0 1-1-1V3a1 1 0 0 1 1-1z'/><path d='M14 2v6h6'/><path d='M9 13h6M9 17h4'/>",
  inventario:"<path d='M21 8l-9 4-9-4 9-4 9 4z'/><path d='M3 8v8l9 4 9-4V8'/><path d='M12 12v8'/>",
  proyectos:"<path d='M12 2l9 5-9 5-9-5 9-5z'/><path d='M3 12l9 5 9-5'/><path d='M3 17l9 5 9-5'/>",
  cortes:"<path d='M6 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'/><path d='M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6z'/><path d='M8.1 7.1L20 18M8.1 16.9L20 6'/>",
  trazabilidad:"<circle cx='5' cy='6' r='2.4'/><circle cx='19' cy='6' r='2.4'/><circle cx='12' cy='18' r='2.4'/><path d='M7 7l4 9M17 7l-4 9'/>",
  empleados:"<circle cx='12' cy='8' r='4'/><path d='M4 21v-1a6 6 0 0 1 6-6h4a6 6 0 0 1 6 6v1'/>",
  whatsapp:"<path d='M21 11.5a8.4 8.4 0 0 1-8.5 8.5 8.5 8.5 0 0 1-4-1L3 21l1.5-5.5a8.5 8.5 0 1 1 16.5-4z'/>",
  reportes:"<path d='M3 17l6-6 4 4 7-7'/><path d='M17 8h4v4'/>",
  config:"<circle cx='12' cy='12' r='3.2'/><path d='M12 2v3M12 19v3M4.2 4.2l2.1 2.1M17.7 17.7l2.1 2.1M2 12h3M19 12h3M4.2 19.8l2.1-2.1M17.7 6.3l2.1-2.1'/>"
};
function toast(t){var d=document.createElement('div');d.className='toast';d.textContent=t;document.body.appendChild(d);setTimeout(function(){d.remove();},2600);}

var MENU=[
  {id:'dashboard',label:'Dashboard',roles:['admin','gerente','empleado']},
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
    var a=document.createElement('a');a.innerHTML=ic(ICONS[m.id]||'')+'<span>'+m.label+'</span>';a.dataset.id=m.id;
    a.onclick=function(){go(m.id);};nav.appendChild(a);
  });
  document.getElementById('userBox').innerHTML=USER.nombre+'<br><span style="color:var(--gold)">'+USER.rol+'</span> · <a onclick="logout()" style="cursor:pointer">salir</a><br><a href="/check-in" style="color:var(--gold2);font-size:.8rem">Registrar entrada / salida</a>';
}
function logout(){localStorage.clear();location.href='/login';}
function setActive(id){var as=document.querySelectorAll('.nav a');as.forEach(function(a){a.classList.toggle('active',a.dataset.id===id);});}

async function go(id){
  setActive(id);document.getElementById('side').classList.remove('open');
  document.getElementById('acciones').innerHTML='';
  var t={dashboard:'Dashboard',clientes:'Clientes / CRM',cotizaciones:'Cotizaciones',inventario:'Inventario',proyectos:'Proyectos',cortes:'Cortes',trazabilidad:'Trazabilidad',empleados:'Empleados',whatsapp:'WhatsApp',reportes:'Reportes',config:'Configuración'};
  document.getElementById('titulo').textContent=t[id]||id;
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  if(id==='dashboard')return viewDashboard(c);
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
async function viewReportes(c){
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
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Parámetros</h3>';
  h+='<div style="max-width:240px"><label>IVA por defecto (%)</label><input id="cfgIva" type="number" step="0.01" value="'+(cfg.iva!=null?cfg.iva:16)+'"></div>';
  h+='<p class="muted" style="font-size:.8rem;margin-top:.4rem">Se aplica al crear una nueva cotización.</p>';
  h+='<div style="height:.6rem"></div><button class="btn" onclick="guardarConfigIva()">Guardar parámetros</button></div>';
  h+='<div class="card" style="margin-bottom:1rem"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Estado del sistema</h3>';
  h+=estadoLinea('WhatsApp (envío real por Meta)',!!sis.whatsapp);
  h+=estadoLinea('Almacenamiento de fotos (R2)',!!sis.fotos_r2);
  h+=estadoLinea('Token de verificación del webhook',!!sis.verify_token);
  h+='<p class="muted" style="font-size:.78rem;margin-top:.5rem">Lo «sin configurar» se activa definiendo las variables del Worker en Cloudflare (WA_TOKEN, WA_PHONE_ID, WA_VERIFY_TOKEN) y el binding R2 FILES.</p></div>';
  h+=tarjetaPassword();
  c.innerHTML=h;
}
async function guardarConfigEmpresa(){
  var d=await api('/api/config',{method:'PUT',body:JSON.stringify({nombre:val('cfgNombre'),rfc:val('cfgRfc'),direccion:val('cfgDir'),telefono:val('cfgTel'),whatsapp:val('cfgWa'),email:val('cfgEmail')})});
  if(d&&d.ok){CFG=d.data;toast('Datos guardados');}else if(d){toast(d.error||'No se pudo guardar');}
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
function fmtFechaHora(s){if(!s)return '—';try{return new Date(s.replace(' ','T')+'Z').toLocaleString('es-MX',{day:'2-digit',month:'short',hour:'2-digit',minute:'2-digit'});}catch(e){return s;}}
function empEstadoBadge(tipo,checkin){
  if(!checkin)return '<span class="pill" style="background:rgba(255,255,255,.06);color:var(--txt2)">Sin registro</span>';
  var dt=new Date(checkin.replace(' ','T')+'Z'),hoy=new Date();
  var mismoDia=(dt.getFullYear()===hoy.getFullYear()&&dt.getMonth()===hoy.getMonth()&&dt.getDate()===hoy.getDate());
  if(!mismoDia)return '<span class="pill" style="background:rgba(255,255,255,.06);color:var(--txt2)">Sin registro hoy</span>';
  if(tipo==='entrada')return '<span class="pill" style="background:rgba(76,175,80,.18);color:var(--ok)">En sitio</span>';
  return '<span class="pill" style="background:rgba(255,255,255,.08);color:var(--txt2)">Salió</span>';
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
  h+='<div class="card" style="padding:.6rem;margin-bottom:1rem"><div id="empMap" style="height:340px;border-radius:8px;overflow:hidden;background:#111"></div>';
  h+='<p class="muted" style="font-size:.74rem;margin-top:.45rem">Verde = entrada · Rojo = salida · Círculo dorado = geocerca'+(geo?(' («'+(geo.nombre||'Sitio')+'», radio '+geo.radio_metros+' m)'):' — sin configurar, usa «Configurar geocerca»')+'</p></div>';
  var pend=alertas.filter(function(a){return !a.revisada;});
  if(alertas.length){
    h+='<div class="card" style="margin-bottom:1rem"><h3 class="serif" style="color:var(--gold);font-size:1.3rem;margin-bottom:.5rem">Alertas de geocerca'+(pend.length?(' · '+pend.length+' sin revisar'):'')+'</h3>';
    alertas.slice(0,12).forEach(function(a){
      h+='<div style="display:flex;justify-content:space-between;align-items:center;gap:.6rem;border-bottom:1px solid var(--bd);padding:.45rem 0"><div><strong>'+(a.nombre||('Usuario '+a.usuario_id))+'</strong><br><span class="muted" style="font-size:.78rem">'+fmtFechaHora(a.created_at)+' · '+a.distancia_metros+' m fuera del centro</span></div>'+(a.revisada?'<span class="pill" style="background:rgba(255,255,255,.06);color:var(--txt2)">Revisada</span>':'<button class="btn sec" style="padding:.25rem .6rem" onclick="revisarAlertaUI('+a.id+')">Revisar</button>')+'</div>';
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
async function configGeocerca(){
  var d=await api('/api/geofencing'),g=(d&&d.ok)?d.data:null;
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.4rem">Geocerca del sitio</h3>'+
    '<p class="muted" style="font-size:.82rem;margin-bottom:.3rem">Define el centro y el radio del sitio de trabajo. Los registros fuera de esta zona generan una alerta.</p>'+
    '<label>Nombre del sitio</label><input id="gcNom" value="'+escAttr(g&&g.nombre?g.nombre:'')+'">'+
    '<div class="g2"><div><label>Latitud</label><input id="gcLat" type="number" step="0.000001" value="'+(g&&isFinite(g.lat_centro)?g.lat_centro:'')+'"></div><div><label>Longitud</label><input id="gcLon" type="number" step="0.000001" value="'+(g&&isFinite(g.lon_centro)?g.lon_centro:'')+'"></div></div>'+
    '<label>Radio (metros)</label><input id="gcRad" type="number" value="'+(g&&isFinite(g.radio_metros)?g.radio_metros:150)+'">'+
    '<button class="btn sec block" style="margin-top:.5rem" onclick="ubicarmeGeocerca()">Usar mi ubicación actual</button>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="guardarGeocerca()">Guardar</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
}
function ubicarmeGeocerca(){
  if(!navigator.geolocation){toast('Sin GPS disponible');return;}
  toast('Obteniendo ubicación…');
  navigator.geolocation.getCurrentPosition(function(pos){
    document.getElementById('gcLat').value=pos.coords.latitude.toFixed(6);
    document.getElementById('gcLon').value=pos.coords.longitude.toFixed(6);
    toast('Ubicación tomada');
  },function(){toast('No se pudo ubicar');},{enableHighAccuracy:true,timeout:10000});
}
async function guardarGeocerca(){
  var b={nombre:val('gcNom')||'Sitio ASLAN',lat_centro:parseFloat(val('gcLat')),lon_centro:parseFloat(val('gcLon')),radio_metros:parseFloat(val('gcRad'))};
  if(!isFinite(b.lat_centro)||!isFinite(b.lon_centro)||!isFinite(b.radio_metros)){toast('Completa latitud, longitud y radio');return;}
  var d=await api('/api/geofencing',{method:'POST',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Geocerca guardada');go('empleados');}else if(d){toast(d.error||'Error');}
}
async function editarEmpleado(id){
  var d=await api('/api/empleados/'+id);if(!d||!d.ok){toast('No se pudo cargar');return;}
  var e=d.data.empleado;
  function v(x){return (x===null||x===undefined)?'':x;}
  openModal('<h3 class="serif" style="color:var(--gold);font-size:1.4rem;margin-bottom:.5rem">'+escAttr(e.nombre)+'</h3>'+
    '<div class="g2"><div><label>Cargo</label><input id="edCargo" value="'+escAttr(v(e.cargo))+'"></div><div><label>Área</label><input id="edArea" value="'+escAttr(v(e.area))+'"></div></div>'+
    '<label>Teléfono</label><input id="edTel" value="'+escAttr(v(e.telefono))+'">'+
    '<div class="g2"><div><label>Rol</label><select id="edRol"><option value="empleado"'+(e.rol==='empleado'?' selected':'')+'>Empleado</option><option value="gerente"'+(e.rol==='gerente'?' selected':'')+'>Gerente</option><option value="admin"'+(e.rol==='admin'?' selected':'')+'>Admin</option></select></div><div><label>Estado</label><select id="edAct"><option value="1"'+(e.activo?' selected':'')+'>Activo</option><option value="0"'+(!e.activo?' selected':'')+'>Inactivo</option></select></div></div>'+
    '<div class="g2"><div><label>CURP</label><input id="edCurp" value="'+escAttr(v(e.curp))+'"></div><div><label>RFC</label><input id="edRfc" value="'+escAttr(v(e.rfc))+'"></div></div>'+
    '<div class="g2"><div><label>Fecha de ingreso</label><input id="edIng" type="date" value="'+escAttr(v(e.fecha_ingreso))+'"></div><div><label>Tipo de contrato</label><input id="edCon" value="'+escAttr(v(e.tipo_contrato))+'"></div></div>'+
    '<label>Salario mensual</label><input id="edSal" type="number" value="'+(e.salario!=null?e.salario:'')+'">'+
    '<label style="text-transform:none;display:flex;align-items:center;gap:.5rem;margin-top:.7rem"><input type="checkbox" id="edGps" style="width:auto"'+(e.consentimiento_gps?' checked':'')+'> Consentimiento de ubicación GPS</label>'+
    '<div style="display:flex;gap:.5rem;margin-top:.9rem"><button class="btn" onclick="guardarEmpleadoEdit('+id+')">Guardar</button><button class="btn sec" onclick="closeModal()">Cancelar</button></div>');
}
async function guardarEmpleadoEdit(id){
  var b={cargo:val('edCargo'),area:val('edArea'),telefono:val('edTel'),rol:val('edRol'),activo:val('edAct')==='1',curp:val('edCurp'),rfc:val('edRfc'),fecha_ingreso:val('edIng'),tipo_contrato:val('edCon'),consentimiento_gps:document.getElementById('edGps').checked};
  var sal=val('edSal');if(sal!=='')b.salario=parseFloat(sal);
  var d=await api('/api/empleados/'+id,{method:'PUT',body:JSON.stringify(b)});
  if(d&&d.ok){closeModal();toast('Guardado');go('empleados');}else if(d){toast(d.error||'Error');}
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
  Chart.defaults.color='#999';Chart.defaults.borderColor='rgba(255,255,255,.07)';
  try{Chart.defaults.font.family="Montserrat, system-ui, sans-serif";}catch(e){}
  var pal=dashPaleta();
  var meses=ultimosMeses(6),mapC={};(cd.cotiz_por_mes||[]).forEach(function(r){mapC[r.mes]=r.monto;});
  mkChart('chCotiz',{type:'bar',data:{labels:meses.map(mesCorto),datasets:[{label:'Monto cotizado',data:meses.map(function(m){return mapC[m]||0;}),backgroundColor:'#8B6D3F',borderRadius:4}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{callbacks:{label:function(ctx){return money(ctx.parsed.y);}}}},scales:{y:{ticks:{callback:function(v){return abreviaMonto(v);}}}}}});
  var pe=cd.proyectos_por_etapa||[];
  mkChart('chProy',{type:'doughnut',data:{labels:pe.map(function(r){return r.nombre;}),datasets:[{data:pe.map(function(r){return r.n;}),backgroundColor:pal,borderColor:'#1a1a1a',borderWidth:2}]},options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{position:'bottom',labels:{boxWidth:12,font:{size:11}}}}}});
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
  h+='<div class="charts-grid">'+chartCard('Monto cotizado por mes','chCotiz')+chartCard('Proyectos por etapa','chProy')+chartCard('Pipeline de clientes','chCli')+chartCard('Valor de inventario por categoría','chInv')+chartCard('Asistencia · entradas (7 días)','chAsis')+'</div>';
  h+='<div class="card" style="overflow-x:auto"><h3 style="color:var(--gold);font-size:1.3rem;margin-bottom:.6rem">Cotizaciones recientes</h3><table><thead><tr><th>Folio</th><th>Cliente</th><th>Total</th><th>Estado</th></tr></thead><tbody>';
  (d.data.recientes||[]).forEach(function(r){h+='<tr><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+money(r.total)+'</td><td>'+estadoPill(r.estado)+'</td></tr>';});
  if(!d.data.recientes.length)h+='<tr><td colspan="4" class="muted">Sin cotizaciones aún.</td></tr>';
  h+='</tbody></table></div>';
  destruirCharts();
  c.innerHTML=h;
  setTimeout(function(){initDashCharts(cd);},40);
}
function estadoPill(e){
  var map={aceptada:'var(--ok)',enviada:'var(--gold)',borrador:'#666',rechazada:'var(--err)',expirada:'#888'};
  return '<span class="pill" style="background:'+(map[e]||'#666')+'">'+(e||'—')+'</span>';
}

var CRM_ROWS=[];
function crmCell(r,campo,val,num){
  return '<td contenteditable="true" class="crmc'+(num?' crmnum':'')+'" data-id="'+r.id+'" data-campo="'+campo+'" data-num="'+(num?1:0)+'" onblur="guardarCeldaCRM(this)">'+escAttr(val==null?'':(num?String(val):String(val)))+'</td>';
}
function crmCellWide(r,campo,val){
  return '<td contenteditable="true" class="crmc crmwide" data-id="'+r.id+'" data-campo="'+campo+'" data-num="0" onblur="guardarCeldaCRM(this)">'+escAttr(val==null?'':String(val))+'</td>';
}
var CRM_VISTA='tabla';
var CRM_ESTATUS=['SIN RESPUESTA','SEGUIMIENTO','PRECIO','MATERIAL','OTRO'];
async function viewClientes(c){
  document.getElementById('acciones').innerHTML=
    '<button class="btn" id="cvTabla" data-v="tabla" onclick="setVistaCRM(this.dataset.v)">📋 Tabla</button> '+
    '<button class="btn sec" id="cvTablero" data-v="tablero" onclick="setVistaCRM(this.dataset.v)">📊 Tablero</button> '+
    '<button class="btn sec" onclick="nuevoCliente()">+ Nuevo registro</button> '+
    '<button class="btn sec" onclick="verDuplicados()" title="Buscar registros repetidos">🔍 Duplicados</button> '+
    '<button class="btn sec" onclick="exportarCRMCSV()">Exportar CSV</button>';
  var cont=document.getElementById('content');
  cont.innerHTML='<div id="crmFiltros"></div><div id="crmResumen"></div><div id="crmBody">Cargando…</div>';
  var d=await api('/api/clientes');if(!d||!d.ok)return;
  CRM_ROWS=d.data;
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
function filasCRMFiltradas(){
  var q=valFil('crmq').toLowerCase().trim();
  var as=valFil('fAsesor'),es=valFil('fEstatus'),an=valFil('fAnio'),me=valFil('fMes'),fa=valFil('fFact');
  var mn=parseFloat(valFil('fMin')),mx=parseFloat(valFil('fMax'));
  return CRM_ROWS.filter(function(r){
    if(q && JSON.stringify(r).toLowerCase().indexOf(q)<0)return false;
    if(as && (r.asesor||'').trim()!==as)return false;
    if(es){var st=(r.estatus_nota||'').trim().toUpperCase();if(es==='__SIN__'){if(st!=='')return false;}else if(st!==es.toUpperCase())return false;}
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
function pintarCRM(rows){
  var c=document.getElementById('crmBody')||document.getElementById('content');
  var nota='<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Doble clic en una celda para editar (estilo Excel); se guarda solo al salir de la celda. Desliza horizontalmente para ver todas las columnas. Registros: '+rows.length+'.</p>';
  var h=nota+'<div class="card" style="overflow-x:auto;padding:.4rem"><table class="crmtable"><thead><tr>'+
    '<th>FECHA</th><th>ORIGEN</th><th>VALIDACIÓN</th><th>ESTATUS FINAL</th><th>ASESOR</th><th>ESTATUS/NOTA</th><th>F. CONTACTO</th><th>PROP/FACT</th><th>COMPAÑÍA</th><th>CONTACTO</th><th>NOTAS VERO</th><th>NOTAS ACTUALIZACIÓN</th><th>SEGUIMIENTO</th><th>TELÉFONO</th><th>MAIL</th><th>MATERIAL</th><th>PROP. S/IVA</th><th>MONEDA</th><th>FACTURADO</th><th>COTIZACIONES</th></tr></thead><tbody>';
  rows.forEach(function(r){
    h+='<tr>'+
      crmCell(r,'fecha_lead',r.fecha_lead)+
      crmCell(r,'origen',r.origen)+
      crmCell(r,'validacion',r.validacion)+
      crmCell(r,'estatus_final',r.estatus_final)+
      crmCell(r,'asesor',r.asesor)+
      crmCell(r,'estatus_nota',r.estatus_nota)+
      crmCell(r,'fecha_contacto',r.fecha_contacto)+
      crmCell(r,'propuesta_factura',r.propuesta_factura)+
      crmCell(r,'empresa',r.empresa)+
      crmCell(r,'nombre',r.nombre)+
      crmCellWide(r,'notas_vero',r.notas_vero)+
      crmCellWide(r,'notas_actualizacion',r.notas_actualizacion)+
      crmCellWide(r,'notas_seguimiento',r.notas_seguimiento)+
      crmCell(r,'telefono',r.telefono)+
      crmCell(r,'email',r.email)+
      crmCell(r,'material',r.material)+
      crmCell(r,'propuesta_antes_iva',(r.propuesta_antes_iva==null?'':money(r.propuesta_antes_iva)),true)+
      crmCell(r,'moneda',r.moneda)+
      crmCell(r,'facturado',(r.facturado==null?'':money(r.facturado)),true)+
      '<td style="white-space:nowrap;text-align:center"><button class="btn" style="padding:.25rem .5rem;font-size:.72rem" onclick="abrirFicha('+r.id+')" title="Ficha 360 del cliente">👤</button> <button class="btn sec" style="padding:.25rem .5rem;font-size:.72rem" onclick="verCotizacionesCliente('+r.id+')" title="Ver cotizaciones ligadas a este cliente">📄 '+(r.num_cotizaciones||0)+'</button> <button class="btn" style="padding:.25rem .5rem;font-size:.72rem" onclick="cotizarCliente('+r.id+')" title="Crear cotización para este cliente">+ Cotizar</button></td>'+
      '</tr>';
  });
  if(!rows.length)h+='<tr><td colspan="20" class="muted">Sin registros. Crea el primero con «+ Nuevo registro».</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
function filtrarCRM(){ renderCRM(); }
function tcardCRM(r){
  var opts='<option value="">(Sin estatus)</option>';
  CRM_ESTATUS.forEach(function(s){opts+='<option value="'+s+'"'+(((r.estatus_nota||'').trim().toUpperCase()===s)?' selected':'')+'>'+s+'</option>';});
  var monto=(r.propuesta_antes_iva!=null)?money(r.propuesta_antes_iva):((r.facturado!=null)?money(r.facturado):'');
  var sub=(r.empresa||r.material||'');
  return '<div class="tcard">'+
    '<div class="nm">'+escAttr(r.nombre||'—')+'</div>'+
    (sub?'<div class="mt">'+escAttr(sub)+'</div>':'')+
    '<div class="mt">'+(r.asesor?('Asesor: '+escAttr(r.asesor)):'Sin asesor')+(monto?(' · '+monto):'')+'</div>'+
    '<select onchange="cambiarEstatusCRM('+r.id+',this.value)">'+opts+'</select> '+
    '<button class="btn" style="padding:.18rem .45rem;font-size:.68rem;margin-top:.35rem" onclick="abrirFicha('+r.id+')" title="Ficha 360">👤 Ficha</button> <button class="btn sec" style="padding:.18rem .45rem;font-size:.68rem;margin-top:.35rem" onclick="verCotizacionesCliente('+r.id+')" title="Cotizaciones del cliente">📄 '+(r.num_cotizaciones||0)+'</button>'+
    '</div>';
}
function pintarTableroCRM(rows){
  var c=document.getElementById('crmBody')||document.getElementById('content');
  var cols=CRM_ESTATUS.concat(['(Sin estatus)']);
  var color={'SIN RESPUESTA':'var(--err)','SEGUIMIENTO':'var(--gold)','PRECIO':'#5B8DEF','MATERIAL':'var(--ok)','OTRO':'#9C7BD6','(Sin estatus)':'#888'};
  var grupos={};cols.forEach(function(k){grupos[k]=[];});
  rows.forEach(function(r){var s=(r.estatus_nota||'').trim().toUpperCase();var key=(CRM_ESTATUS.indexOf(s)>=0)?s:'(Sin estatus)';grupos[key].push(r);});
  var nota='<p class="muted" style="font-size:.8rem;margin-bottom:.5rem">Tablero por estatus: cambia el estatus en el menú de cada tarjeta y el cliente se reacomoda en su columna. Desliza horizontalmente para ver todas las columnas. Registros: '+rows.length+'.</p>';
  var h=nota+'<div class="tablero">';
  cols.forEach(function(k){
    var lista=grupos[k];
    h+='<div class="tcol"><h4 style="color:'+(color[k]||'var(--gold)')+'">'+k+'<span class="cnt">'+lista.length+'</span></h4>';
    if(!lista.length)h+='<p class="muted" style="font-size:.74rem;padding:.3rem">—</p>';
    lista.forEach(function(r){h+=tcardCRM(r);});
    h+='</div>';
  });
  h+='</div>';c.innerHTML=h;
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
  var id=el.dataset.id, campo=el.dataset.campo, num=el.dataset.num==='1';
  var raw=el.textContent.trim();
  var body={};
  if(num){ body[campo]=(raw===''?null:(parseFloat(raw.replace(/[^0-9.-]/g,''))||0)); }
  else { body[campo]=raw; }
  var d=await api('/api/clientes/'+id,{method:'PUT',body:JSON.stringify(body)});
  if(d&&d.ok){
    toast('Guardado');
    var row=CRM_ROWS.find(function(x){return String(x.id)===String(id);});
    if(row)row[campo]=body[campo];
    if(num)el.textContent=(body[campo]==null?'':money(body[campo]));
  } else if(d){ toast(d.error||'Error al guardar'); }
}
var PEND_CLIENTE=null;
async function nuevoCliente(){
  var nombre=prompt('Nombre del contacto:');if(!nombre)return;
  var tel=prompt('Teléfono (opcional, ayuda a evitar duplicados):')||'';
  crearCliente(nombre, tel, false);
}
async function crearCliente(nombre, tel, force){
  var hoy=new Date().toISOString().slice(0,10);
  var body={nombre:nombre,etapa:'prospecto',fecha_lead:hoy,moneda:'MXN'};
  if(tel)body.telefono=tel;
  if(force)body.force=true;
  var d=await api('/api/clientes',{method:'POST',body:JSON.stringify(body)});
  if(!d)return;
  if(d.ok && d.data && d.data.duplicado){ PEND_CLIENTE={nombre:nombre,tel:tel}; mostrarDuplicadoAviso(d.data.existentes); return; }
  if(d.ok){ if(typeof closeModal==='function')closeModal(); toast('Registro creado'); viewClientes(document.getElementById('content')); }
  else { toast(d.error||'Error'); }
}
function crearClienteForzado(){ if(PEND_CLIENTE)crearCliente(PEND_CLIENTE.nombre, PEND_CLIENTE.tel, true); }
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
  if(!grupos.length){ h+='<p class="muted">No se encontraron repetidos por teléfono, correo ni nombre. 👍</p>'; }
  else{
    h+='<p class="muted" style="font-size:.84rem;margin-bottom:.7rem">'+grupos.length+' grupo(s). Abre cada ficha para revisar y consolidar.</p>';
    grupos.forEach(function(g){
      h+='<div class="card" style="margin-bottom:.6rem;padding:.6rem .8rem"><div class="muted" style="font-size:.74rem;margin-bottom:.3rem">'+escAttr(g.tipo)+': '+escAttr(g.clave)+'</div>';
      (g.miembros||[]).forEach(function(x){ h+='<div style="display:flex;justify-content:space-between;align-items:center;gap:.5rem;padding:.25rem 0;border-top:1px solid var(--bd)"><div><strong>'+escAttr(x.nombre||'—')+'</strong>'+(x.empresa?(' · '+escAttr(x.empresa)):'')+(x.asesor?('<span class="muted" style="font-size:.74rem"> · '+escAttr(x.asesor)+'</span>'):'')+'</div><button class="btn sec" style="padding:.25rem .55rem" onclick="abrirFicha('+x.id+')">Abrir</button></div>'; });
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
  box.innerHTML='<div class="card crmfilt">'+
    '<input id="crmq" placeholder="Buscar texto..." oninput="renderCRM()">'+
    '<select id="fAsesor" onchange="renderCRM()">'+aopts+'</select>'+
    '<select id="fEstatus" onchange="renderCRM()">'+eopts+'</select>'+
    '<select id="fAnio" onchange="renderCRM()">'+yopts+'</select>'+
    '<select id="fMes" onchange="renderCRM()">'+mopts+'</select>'+
    '<select id="fFact" onchange="renderCRM()"><option value="">Facturación: todas</option><option value="con">Con factura</option><option value="sin">Sin factura</option></select>'+
    '<input id="fMin" type="number" placeholder="Monto min" oninput="renderCRM()">'+
    '<input id="fMax" type="number" placeholder="Monto max" oninput="renderCRM()">'+
    '<button class="btn sec" onclick="soloMios()" title="Filtrar mis registros">Solo míos</button>'+
    '<button class="btn sec" onclick="limpiarFiltros()">Limpiar</button>'+
    '</div>';
}
function pintarResumen(rows){
  var box=document.getElementById('crmResumen');if(!box)return;
  var n=rows.length,sumP=0,sumF=0,conF=0;
  rows.forEach(function(r){if(r.propuesta_antes_iva!=null)sumP+=Number(r.propuesta_antes_iva)||0;var f=Number(r.facturado)||0;sumF+=f;if(f>0)conF++;});
  box.innerHTML='<div class="kpis crmkpis">'+kpiCard('Registros',n)+kpiCard('Propuesta s/IVA',money(sumP))+kpiCard('Facturado',money(sumF))+kpiCard('Con factura',conF)+'</div>';
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
  ['fAsesor','fEstatus','fAnio','fMes','fFact'].forEach(function(id){var e=document.getElementById(id);if(e)e.selectedIndex=0;});
  renderCRM();
}
function exportarCRMCSV(){
  var cols=[['fecha_lead','FECHA'],['origen','ORIGEN'],['validacion','VALIDACIÓN'],['estatus_final','ESTATUS FINAL'],['asesor','ASESOR'],['estatus_nota','ESTATUS/NOTA'],['fecha_contacto','FECHA CONTACTO'],['propuesta_factura','PROPUESTA/FACTURA'],['empresa','COMPAÑÍA'],['nombre','CONTACTO'],['notas_vero','NOTAS VERO'],['notas_actualizacion','NOTAS ACTUALIZACION'],['notas_seguimiento','SEGUIMIENTO'],['telefono','TELEFONO'],['email','MAIL'],['material','MATERIAL'],['propuesta_antes_iva','PROPUESTA ANTES IVA'],['moneda','MONEDA'],['facturado','FACTURADO']];
  function esc(v){v=(v==null?'':String(v));return '"'+v.replace(/"/g,'""')+'"';}
  var lines=[cols.map(function(x){return esc(x[1]);}).join(',')];
  CRM_ROWS.forEach(function(r){lines.push(cols.map(function(x){return esc(r[x[0]]);}).join(','));});
  var csv='\\ufeff'+lines.join('\\r\\n');
  var blob=new Blob([csv],{type:'text/csv;charset=utf-8'});
  var a=document.createElement('a');a.href=URL.createObjectURL(blob);a.download='CRM_ASLAN.csv';document.body.appendChild(a);a.click();a.remove();
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
  h+='<div class="ficha-head"><div><div class="ficha-name">'+escAttr(c.nombre||'—')+'</div>'+
     '<div class="muted" style="font-size:.85rem">'+escAttr(c.empresa||'Sin empresa')+(c.industria?(' · '+escAttr(c.industria)):'')+'</div></div>'+
     '<div class="ficha-actions">'+etapaBadge+
     ' <button class="btn" onclick="cotizarClienteFicha()">+ Cotización</button>'+
     ' <button class="btn sec" onclick="toggleEtapaFicha()">'+(c.etapa==='cliente'?'Marcar prospecto':'Marcar cliente')+'</button></div></div>';
  h+='<div class="kpis" style="margin:1rem 0">'+
     kpiCard('Cotizaciones',(R.num_cotizaciones||0))+
     kpiCard('Total cotizado',money(R.total_cotizado))+
     kpiCard('Total aceptado',money(R.total_aceptado))+
     kpiCard('Facturado',money(R.facturado))+
     kpiCard('Saldo pendiente',money(R.saldo))+
     kpiCard('m² cortados',(R.m2_cortados||0))+'</div>';
  h+='<div class="fsec"><h3>Datos de contacto</h3><div class="fgrid">'+
     fField('Teléfono','telefono',c.telefono)+
     fField('Teléfono alterno','telefono_alt',c.telefono_alt)+
     fField('Correo','email',c.email)+
     fField('Sitio web','sitio_web',c.sitio_web)+
     fField('Ciudad','ciudad',c.ciudad)+
     fField('RFC','rfc',c.rfc)+
     fField('Asesor','asesor',c.asesor)+
     fField('Origen del lead','origen',c.origen)+
     fWide('Dirección','direccion',c.direccion)+'</div></div>';
  h+='<div class="fsec"><h3>Comercial y oportunidad</h3><div class="fgrid">'+
     fField('Validación','validacion',c.validacion)+
     fField('Estatus','estatus_nota',c.estatus_nota)+
     fField('Estatus final','estatus_final',c.estatus_final)+
     fField('Material de interés','material',c.material)+
     fField('Probabilidad de cierre','probabilidad_cierre',c.probabilidad_cierre)+
     fField('Cierre estimado','fecha_cierre_estimada',c.fecha_cierre_estimada)+
     fField('Próximo seguimiento','proximo_seguimiento',c.proximo_seguimiento)+
     fField('Próxima acción','proxima_accion',c.proxima_accion)+'</div></div>';
  h+='<div class="fsec"><h3>Financiero</h3><div class="fgrid">'+
     fField('Condiciones de pago','condiciones_pago',c.condiciones_pago)+
     fField('Línea de crédito','linea_credito',c.linea_credito,'num')+
     fField('Saldo actual','saldo_actual',c.saldo_actual,'num')+
     fField('Riesgo de crédito','riesgo_credito',c.riesgo_credito)+
     fField('Facturado','facturado',c.facturado,'num')+
     fField('Moneda','moneda',c.moneda)+'</div></div>';
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
  else { h+='<div style="overflow-x:auto"><table style="font-size:.82rem"><thead><tr><th>Folio</th><th>Total</th><th>Estado</th><th>Vendedor</th><th>Proyecto</th><th>PDF</th></tr></thead><tbody>';
    cots.forEach(function(q){ var proy=q.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+q.proyecto_folio+'</span>'):'—';
      h+='<tr><td>'+(q.folio||'—')+'</td><td>'+money(q.total)+'</td><td>'+estadoPill(q.estado)+'</td><td>'+escAttr(q.vendedor||'—')+'</td><td>'+proy+'</td><td><button class="btn sec" style="padding:.2rem .5rem" onclick="pdfCotizacion('+q.id+')">PDF</button></td></tr>'; });
    h+='</tbody></table></div>'; }
  h+='</div>';
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
  if(!bajos.length)h+='<tr><td colspan="5" class="muted">Todo el inventario está por encima del mínimo.</td></tr>';
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
  var h='<div style="background:#111;border:1px solid var(--bd);border-radius:6px;padding:.7rem;font-size:.85rem">';
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
  var h='<div class="card"><table><thead><tr><th>Folio</th><th>Cliente</th><th>Total</th><th>Estado</th><th>Vendedor</th><th>Proyecto</th><th>Acciones</th></tr></thead><tbody>';
  d.data.forEach(function(r){
    var conv=(r.estado==='aceptada'&&!r.proyecto_folio)?' <button class="btn" style="padding:.3rem .6rem" onclick="convertirCot('+r.id+')"><svg viewBox="0 0 24 24" width="14" height="14" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:.3rem"><path d="M5 12h14M13 6l6 6-6 6"/></svg>Proyecto</button>':'';
    var proy=r.proyecto_folio?('<span class="pill" style="background:var(--ok)">'+r.proyecto_folio+'</span>'):'—';
    h+='<tr><td>'+(r.folio||'—')+'</td><td>'+(r.cliente||'—')+'</td><td>'+money(r.total)+'</td><td>'+estadoCotSel(r.estado,r.id)+'</td><td>'+(r.vendedor||'—')+'</td><td>'+proy+'</td>'+
       '<td style="white-space:nowrap"><button class="btn sec" style="padding:.3rem .6rem" onclick="pdfCotizacion('+r.id+')">PDF</button>'+conv+'</td></tr>';
  });
  if(!d.data.length)h+='<tr><td colspan="7" class="muted">Sin cotizaciones. Crea la primera.</td></tr>';
  h+='</tbody></table></div>';c.innerHTML=h;
}
function estadoCotSel(e,id){
  var ops=['borrador','enviada','aceptada','rechazada','expirada'].map(function(s){return '<option value="'+s+'"'+(s===e?' selected':'')+'>'+s+'</option>';}).join('');
  return '<select style="width:auto;padding:.25rem .4rem;font-size:.78rem" onchange="cambiarEstadoCot('+id+',this.value)">'+ops+'</select>';
}
async function cambiarEstadoCot(id,estado){var d=await api('/api/cotizaciones/'+id,{method:'PUT',body:JSON.stringify({estado:estado})});if(d&&d.ok)toast('Estado: '+estado);}
async function convertirCot(id){if(!confirm('¿Convertir esta cotización en proyecto?'))return;var d=await api('/api/cotizaciones/'+id+'/convertir',{method:'POST',body:JSON.stringify({})});if(d&&d.ok){toast('Proyecto '+d.data.folio+' creado');go('proyectos');}else if(d){toast(d.error);}}

var COT_PROD=[];var cotSeq=0;
async function nuevaCotizacion(preselectId){
  document.getElementById('acciones').innerHTML='';
  document.getElementById('titulo').textContent='Nueva cotización';
  var c=document.getElementById('content');c.innerHTML='Cargando…';
  var dc=await api('/api/clientes');var dp=await api('/api/productos');
  if(!dc||!dp)return;
  COT_PROD=dp.data;
  var cliOpts='<option value="">— Selecciona cliente —</option>';
  dc.data.forEach(function(cl){var sel=(preselectId&&String(cl.id)===String(preselectId))?' selected':'';cliOpts+='<option value="'+cl.id+'"'+sel+'>'+escAttr(cl.nombre)+(cl.empresa?(' · '+escAttr(cl.empresa)):'')+'</option>';});
  var h='<span class="back" onclick="volverCot()" style="cursor:pointer;color:var(--gold2)">‹ Volver</span>';
  h+='<div class="card" style="margin-top:.5rem">';
  h+='<label>Cliente</label><select id="cotCliente">'+cliOpts+'</select>';
  h+='<div style="overflow-x:auto;margin-top:1rem"><table><thead><tr><th>Material</th><th>Descripción</th><th>Cant.</th><th>Unidad</th><th>P. Unit.</th><th>Desc%</th><th>Importe</th><th></th></tr></thead><tbody id="cotBody"></tbody></table></div>';
  h+='<button class="btn sec" style="margin-top:.6rem" onclick="agregarFila()">+ Agregar línea</button>';
  h+='<div class="g2" style="margin-top:1rem;max-width:430px;margin-left:auto"><div><label>Descuento global %</label><input id="cotDescG" type="number" value="0" oninput="recalcCot()"></div><div><label>IVA %</label><input id="cotIva" type="number" value="'+((CFG&&CFG.iva!=null)?CFG.iva:16)+'" oninput="recalcCot()"></div><div><label>Vigencia (días)</label><input id="cotVig" type="number" value="15"></div></div>';
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

var LOGO_ASLAN="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAggAAACzCAIAAABjDHOrAAAyXElEQVR42u19WXMb17Xu7sY8EwAnUBRFibKkSLJljZY1K/6Jt+rek+PknHt/QR5dqcpDKk4lrqSiRD6usiRLsiSTFDhBmGeg78Mitzb31LsBkATJ9T2wQKCH3d2717fXbG0WygSBQCAQ4wGLWN62tzQ/bf/mKE/hSHf042NAIBCI8YGjENYq8nAcJUk4jgP0wPEAnMIiFtk+Dn9Gv+Pgg0AgEIiD0g9EYuC/sASlgCUPKUmwe1B6gNM5zEF29rW40/oJMgMCgUAcmH5ACGPzkdGGJQrpXXJ/R6aLDCGlBxNu8BOZ6kGGIQsLnzUCgUAY0wIVvNtfWUrtgUp6Z3s7h1EpRIaQ0gPneABusCyL5Qa/03fYQdi2HfD7iWX1+/3xun2WoCzJNKCxnwCHcOjjOQ0Gu+/WcJuNcGDHGHTmsx8O4fAZSb2HE+DjHdq11KfS3vr4heM4DAdYVOGA3Sz6BXHINg9YDnEcyyKO0+12d1wODiHEzyoWtmW1Ws38+0K/70QiYcuy+n3HQHztfr6WToUY9AZaJi+tRT6yqDXUg9eO25FvMtw8Y5+5xf5iWcQRBsdd5kinJXNIL+ewxvEFHlj59bqvEct7fUxSoelIZSs3P/lTjWZZohq/ZKX2cdo4u2/mgMsh5fU4wishuXNDLSUd06GQUdxSS/OwFMLNEnSJXaRhKW1Q22TjOMT22anUBHs6fyoZAS1mW8VwOu/evvrmm2+ePn3a7XYjkYht2/1+3+EOtntElsxMZtk2YZweu7cllmXx28s2E7dUfTY/OLcl+5vrkBzHYY9ubbO0wbVYFtm9JTzgj4el3qHdY6MaEv2VVQbhX8P7yZ2a24aO5+Ngdh/RsiyHmQCO49js7ztDtbgvd5Q8bndW+ds1POFX8aplktmSKZSjohijgztidMjONw73QXbAjz8Je8Gt2X5POQPBzsvLjWS3ju1wc+zjNxaxiOUIB9klE9T/sgPjdoSN2Qunjw+sETAfdoYLKyCHHfmuw+5sxg5A/MCdVHwuqiuVPMGdceo30xxcNQx2s+2nCQLc2fXoHKcPj2v7pmzvQ5+/s60iMJYUlhuI2YrOsqx2uz2by/3Hb35n2XBAixDLarfb7AXYtu33+xuNxj//+c/f//73//jHPxqNRigU8vv9O09tt+RSyqBdXMUKUFaS6uT1bmLgpKG7uGdPyhEld/BtjjUaj+M4tm2LEorOV/E4H0X2DqnIRkJlpqW5HHoK1Q3hBiDylpTGNEQivSIiWyVojibeHxOa50SijhUEAb37sOYqjTMws+y8Gspgw52Fl+PIRAbcam7kKjHHfSnu7kjYwiFEciiVqKUH3GWSlm2vF3ya4X38lRBn9/Z0F45axMvnDsWNVpTeKt5SSfl+v6/ajL0c9miwy8ej7QhsbjMFfziOQ1QXLr2rQ9pigBjm5uZ++7v/Z9n29tMXicFxiOP0fT5fIBAghDx9+vSbb7757rvv8vm8bduhUGhbgWDWetJVs4YziEwKD68usIc12Uy+QndjKU/qiOH4VTqH1ws3ubda+as7giBt5QeB9Q73o2pjjaw3pwHpXi7qxUBC3+sxHTXDOIplviiDNIfSiGbVKeS6BSPgRMrRLKgNF8X6LYfckXOFugp6/SnEC6THNzmyeNOG3MxEHXGGU5EpMXz92/9r23Z/52h+UWm2LNtxnGazSQi5cuXKlStX3r59++233/7pT396/vx5q9WKRCKsAqF/jQd4RaVrYUOJMLAo0XwvjsdwhCrZxy6IPN09bsfR+7l2L7gGeKz6gWmURYFdhnqUo70/A7OU/kK4dbTqLOwS3pCH2BdTpYi4LoBcn4JeuHuVBiZ7iduotAfzU7CsL1XFqAZg8qA1Y9AoOl4XGc6o7aWiFmv1er1er6c6U6/XI4QEg0Gfz1cul//nf/7nD3/4w3fffVcsFoPBYDAY5NYaquWqaOIwWXR7cxVo19qiRcW2bdVBNGt5c4sTu6PUFmSyHtfsyNmUVGfk1oMqhYN1VKjGo1ca9HoMd88NKdlEsuwRR+oHoDGge5V3UouNV/1AY2WSmG52Yg7FS1BZqPQWJKkJi+5rQh6u1nmpt0OleLmqR3pNyKtuoVEFXHcx9HlwV62xpw2mMeTm5r7++r/p6+kQ4geLea/Xk8anwqadTqfdbofD4bt37969e/fVq1d//OMf//rXv759+7bVagWDwUAgwM42E4OS5l1SrZFdRYBmwatZMYmjUslQPStw81VcgHi15PAcLhuhucJhYmIyZAVxR06+SEWMKyu4Pl86BwbTZoZXSkxuo2peaa6Xu2OaaeMIDnnpbec+sNKEYzWpb1m6jGC/4ZhMOlvoBrzNfffgpesbUe/RPEeprFQt0sVbxF2R6g5r5K/06kTnBHdGlblPOhNUISd7ZzP4eAJQHfT6KYj+cDhs23axWPz3v//9l7/85cmTJ2tra/C9z+fTmJiGURdcXQUsk7laGDyJS0OhIKojhk6UARwY3HsrVRcG8Ey4OlcMzX3cuw2LD8OlwEiMOSNRI7y+e4bbu7ptvXoXVM4Jc8M9tadzD858WS393lXh0K+sXU9h4gjRqyZS0iJaR7rhTXDVZjx5I4jHeCrPGkNu7j+//m+fz/64qOWO3u12Xd1N4HwOBALBYLDX662srDx58uTbb7/9/vvvq9UqfA+SUbrmNXH5epKtIpdojFqi/DWRmHrTk97iZO6pFolNbwXiWIEdqmqh4coEJtsb2oJcPQom4tvcybSnrhfpMk16xgFMxqKw0JhuDI1L0qW0PiBVZYZidzcJlJIG7YgxPCrpZi4rNRwmPYWeclylvKchmbCaSuIb2p1G4nhgicG2bZpFIVlosKqDfhkCd9/v9wcCgW63+/Llyz//+c/ffffdL7/80mg04HsQUuxzgm9cMwA8JTpITQ2uwawmkloaX2t4fL1AN5Ghmh05Cc6djrvDKtM8SyqGFiSNkUGqNo2QFTQ2wP33MZhLfxV/aJb5KrkgXdGrnBMiN+g9BK6yTwwBcg1m1SccuO6ocoFoMic8KTqGQhaWwvrwVvFo0lBXFYUYekoMKWdgYqC505ZKqVR5HVQ6hGVZYGIql8s//vjj3//+96dPn759+7Zer/v9fvhJdEJIpbyoLgxmRzKkHMMoVcpnere2VEybmIZEe4vJwNh7paIB1XHoZir7m+ElSPcSj+lVAxh4G9G2q1ECNDPchABcI4VYiaxxUEulMxcPYyIIVEqDVLjrrUCudhgVXakWkebE4MlF7GpQMvT6DqA0DC/BvR7Z8DIHIIbffP1fPttHiUHej8G2bdu2u92u6HWQHhqkQKPRcBwnGAzeunXr1q1bhULhxYsXT548+de//vXmzZtqtRoKhSCQSfW2qCww5kH0JjJLs+x1dXPpxZNrCJBe1mvMONwLI24vXdpTm5L4r7m32dXToP/G0OVrYgtSBUepHI/m/7qyhUr2yTO2tM4eld4jehdFbVsvwbk7r1knaVysKkWBzkCaxiQV9yraUPlRXVXhgeWd1Lcsdcub3BOvJzU/iHkgshgvsHfQNerx+/0+n6/b7RoW1IOJ2O/3a7UaISQWi926dev27duVSuWnn37629/+9uTJk9XV1UajAfnVPp8Ppj7n9TJZLboWotDrCtJYC/PzSs/F2fo1ws7cJEKlg4osNV50dkdXp4s0FtZVYnJMw+o9mltnrgFwwTOioBEjPbiBeTI0ieVJNMwhVUpcn6yGFahKrXLLUdVQ+i/naXNdS+nNUHrFiCWAfr9PmaO/A/qZ/UAxmKCUKoKs6NBHcErNklyAlioCmCjCmQylv2ZgXnfnFCnXYDZvZlJaocNy6+BmWVYgENDnOqgUiF6v1+12CSGBQODq1avXr18vl8s//fTT06dPf/jhhzdv3pRKpX6/D64I/TupDw3iAuQ1b7XJS6vXDEzM5dIVPTEIhRLFt6H9Sm8SMeQAjTtaZW7ixkYjDrx6AgxNhVKdUqThAShBb9jUq4YmigVxC3YEQvX5fKxwF9cZmvdfE9ys2tjEly4afzRTVJU4zXIG2KjhL/1AFRFR7FpMpWdXvdBE4KpUTFdx7EqZGsKQxgd7VR1cOWxI5xnZKcHtOGatPWFpL41n1V8GvQv1et1xHL/f//nnn1+7dq1Wqy0vLz9//vyHH354/vx5Pp9vt9s+nw8y6bzqSvoluWt6mvirYQipKJ0HCG9XyXeN1UhPmSrZrRmna74Fywoqd7ShN0JVbstc49bYkVwzyQemCjEKXiNfpKtCEP0U0vW+eY6bNCLeqxvGq8JN1Fk7qgAb+kRohTHRQ0sZQgRVNThlSCWIXS1IekFsTjxEkWs5ZEyaV2Ya3vylPLunY0E8qz7dQT+tgfxt2w4EAmCnKhaLb968+f77758+ffru3btarQaRTsBG3GRSTWWNxqCpDWeYIO3JT2AS7GSS8SAV6FKblUkwq+Y+iBYnTjypTEwqxhWtPSaGOEONwdxEY5IKN8zbK+b3clKeYwJzIuSOrLKBqHQX9iHqbXrS3DfpxqrMLH0VDU04r2Z9QC1OYMTudrvtdrvb7XY6HWq20nhHPLmg9XuJm0nzHvRH1pThE90zGqOTNL5reL2BOp//4z//y7ZpvUnL7/UoEIGqilky9EMQQmjxvmQyef369S+++KJer7979+758+fPnj37+eef19bWarWa4zhQ0e9jurZZLrFemhj6qD0laRuKG2mSp8pwoc/H1gS5StV/KTu6xkG5soLIyip7jj6swPUSXB+EYbE/r/4GlTasWf5rjNTShaGo8UhZWXQkSBUIc0OZOO31Sdri8lyvwKkmOXdPxHW6ZVm04g5sAKbpTqcDfzudDti3xWh4qenJU4FCVwXCfHmuf/quBiJPisVQGoOzXX+Xz3z2ClAdTBL8TNQIIACortHpdEql0srKyqtXr16+fPnmzZv379/X6/V+vx8IBECZcPVCq1bcrlH5xKyuOFEkLWvW7xolgHipOEu0CXSe1BrN2Fw1D9HZbmj2HaAiNxm0ttJgtC0SAEcGRFsh0UTKuBKGSUCtqzjQWMallSe82g9clz6qEinEoK4JUTic4UuwNQFJtNttIAxWpTBJaRaX3uaZdMM0dRhYZSHeE9pNNYbf/M72fTQe+Ad+i0BAUw/zMAZcuuRstVpQ1TUajV68ePHy5cvdbrdSqaytrb158+bFixcvX74EkgAi8fl8fr8fjqB3keklvlfXqDiJpVUfDEOnNEGrqhfPNYJClPhiyJBJRIrYBEJvZHP1nhmyzmBW8iFVAXpFou9X9WhUcV+anH+NoiMKQfH4+jJK0iW89Jh61UpTGUn/uDVGM42S4WpLFJnGtm1YSlLBSkmi1Wq1Wi1WLmkySLwGHRlW4pIWW/Tk3jA8/mAHUQiXQX0MeseDqvCIyfpC/J5mw0Fsq9/vJ4TUarV8Pv/q1avXr1+/fft2fX29XC632+1+v+/bAecpdVUCzLspEIPqEa7Wdk9lmkRxo8qDc2UF0c+pcS1IsxOIokCISzMfoTKa+Cq6igNDy57Ui6OKLmX9oiwruNqRDEUb8VjszzzGVxVMrIr8lkpksRODSlkx0UhcCykSWR6f3k3iKkCktlCqT7R2APoEZ4gTV9/mWdAmrgWTRf2QKdDErHyIocbwf37zW0hwg+ZlfjI0wPHg9/up1W8kx6Sip9/vt9tt0CRs215YWFhaWnIcp9FoFAqFfD6/vLz87t271dXVjY2NSqVC9QmgE1FhHzj51qv+oYmtdF1eiXvp6+e4Hl9KBprrUlVmFWtdeCqU7XpPpDfQ0G2gSW6grmD2s0mcsXjzuewNqVg0mWmq265ZiLjqoGx9AS6Zw1MAmKFRW0y91IgnkzQj4haApwlCY4nH5/NFo9FYLAbxTlSNaLfbsI4kTG1HE02Ifbhihwa93qPJ+jZxbLj+NFgjKZnC8PHgIyAGOuhgMOg4zgjpgb25rNe61WrB+zk1NZXL5a5du9btdhuNRqlUWl9fX1lZWV1dXV5e3tjY+PDhQ6vVooon8IQmZsO88aRhtxPDd89kYagvpqTX3A0jbvVFW1W6gqENzSv7umYkiItcVmBJ7UJ6ISUNctOUwNKPVpNH4lUiu+bfSH3CJpGsJk9K7yFQdRbxKnM9SQNpPT5RIQAJDiQRjUbBtgECpNFotFotkFSu98rEn6xydLt6411Nc4bx0EN72HaORohpHsM40IPo4yU7jSKoz2N6ejqXy129ehXcFZVKZX19/f379+/evcvn81tbW8ViEVYNvV6PsgXU/yDqiH59xpZX/4TeBU3MUgE0MUsmIsbEA69SHVxba7jm97nazYhBDRIuvJ2LDR2gNR4x60EmlhoVKUGsOm5YfI1oE6b0fCONZVKVTuGSrcwjZ4g6JMncz2TS4EjFSaoYLak9gH6mWhSk08ZiMZBRzWazVqs1m022voOmPcbwmQqeOvG5Gu4GMIQYKA3DOZ9N6KHb7XJ1vPeCJOhbyvKEbdvJZDKdTl+8eBEopFarlUqlQqGwtra2sbGxublZKBQqlUq1Wm00GjSeAXjC7/dTwnB9cp6C7qUzewCNXrV4VLXfMVx+DvOr/m4Y5jSoclOIovyD1D9J3HJf6F+aLsP+hQ8qcOoI/czuSy+B1bFU9eZg4nF1I+i/XG0JNmGY/SBuI1Y3UtXPED1S0qdmGKzp6qpR6YKqNBqV0Ncko2kKKVJGhx6UyWSy2+02m81Go9FoNJrNJmWRgctgGHKJYUcmFferamOMQHWw9oYYON9Dr9ejzp89BScBQW2kP4VCoVwuNz8/Dzex0+m0Wq1arVYulz98+PDhw4etra2tra1SqVQqlarVKjg2ut0urVXAigZ90yFXG8gAQt+kKKym2IbefmJi2DWxq0oj8Yk6tFekW1aiEVlhOFGIg3AHlxINQKDBCP4d0C/pc6T0zz1ZVViqSZ0JjafUVW/Ql79maw2JFMJSAizIaP4wDeiEGEKaDcBWpJDOIrHw1wALF9cZ7pq+ym0sJp9rdFBWqxNVbTiUz+eLx+PxeBy8EfV6vVar0bgmMU1nYKHveh80DeZGqJTItZGPLgaHeE1wG+zBw2tJcxf3rqGKxoNNdmqJs7c7EAhkMpnJyUn6AsBbBApmpVIpFAqFQqFYLBaLxVKpBBFQADgU69/j3JtcSjNXR0jvdpaG63A2fXPTk2v+mjQBW+q7Nrfyi3JNVeCIldFUpoPKD2s6yHCEWQQfaDoLZD5Sic/ZlKQeS30hB32laFdz0wC/mhgW6A3k3J6UFzUmJu44MG/ZJABYIYGJFT4AbbAVKUTzlKrTjsrVJAZBcfqTGHGut6V4sujqxTcdm23b4XA4EolkMpl2u12tViuVSqvVEnUIQ4ewqxJgJrOdvfUubHsWdp3ST/YL8GKD5KU+H7KPEJeu1HzEmRcjkUgsFsvlciB0gFHg/Wk0GrVaDWYMrCyq1Wq1Wm02m6Bh0PA4sUYYFx8pXZ0ZdsmW9iYi2kAXVV6+iU9F7OrDiWBaA44uyen6nX4OBAKsWKcbwPd0dU+5gdPMRNlKZRZXF1r6pav7jqibvYx8mTwShVj1HMUaDKJCwFau5N4INmuMRnzCxKb5xpz7kJ3Srp0wNI4uQ0OQ10oH+igG8Uu4gaFQKBwOp9PpVqtVrVapK0Ks00M81k0aTJmQrhpHb4bZdjEQ/z5Pbnj/qbZrUoZ3r6lC1BZp9AK38IG5ks1mKWHQVRj3OoFWwb1XtOQLrMjov/RWsJZi1krA2UZZkafqDGppAYtr1iZD1910wQ5LeM4+498NKsrZ9T5nn3GtGMEZRtjaauK1mzDZHpXSOywwLyDPTiTOQRgMBuPxOBveAzMcJnaTQaPR4N5l+tylzh5Xw7ond7Thits8qIQdDDBEJBIBHYIaEkCHYK/Rk/d+AMOURpMYsqKG4HneLrDqP5C5a9s2VL84QAXC3AxFxyZ2PGVNQ7AKi0ajKsMLJ/LE+vWsI1HqS2RVe2kavbR+AxX9+vU+V/lHaj3QFxIQx8ZesqvlZOCqGIghF0ZSd4iKMFjtjXosGo1GvV6HOA7Qnll5J7rH9NnOAy/G9S66AQrM0bth23YsFovFYtlsFiLjy+UyOCDZqDONoKeWQJNCA+aaxGgKJYkGnoOdl7Dw7Pf7QA/76YEY5kVSzWB2kUvVUo2CTM0vhl6HAWyRUklNFKmehsb0AebikK8o4mBpQzWLKFskEgk25Rh4olar1ev1RqNB325VJLGmXKumEt/AssI130LPEIlEIpFItFqtcrlcLpchppFjCL0NbY/i+EcYpOQfhylo23YoFKIFFMefIcyXYKrWx1JNwlDWk4GKjqjk+14Up0O5fxwIgyUJCOCByRYKhSKRSDabhTcaTE/AE7VajWaWEaFPg2F6jaHRyZwP9GJUHBhIp0AgMDU1lclk6vV6uVwGE5N5Xqen/gp6RUTlSPNmRvpoR7LHhRg4BYLWw9qjFLnDpdeP85ERCKl6QXkCjMahUCiVSoFKDTwB4RsQtUGr3Un9utIct4FXx65JoIb9i6ht2bIsCHWFKKYPHz5AHWhpwzGpNUnUfjRl8rhLFpMNh4h9Ym/BOBEDe9kQqQImJraaLso4BOLQ8QR1zoHpKRwOT0xMgJ5Rr9crlQpLEtQsw1pm9DUiRwXXXG4uYpg1MQWDwWw2m06nq9VqoVCoVqtAG+bVVcmgmcx74Gaw/OM8vcDEFAqFKENwiQhoskAgDqk+Ad/H4/FUKgU25EajUa1Wy+UyWJwg0okyhGvFAX3nO3Mrk+GWotYCnJFMJhOJRKPRgOSnZrPJ5ppoKhDrLUua76UaxnDi0fEfiolFGYIGhtLwONQhEIhDzROdTocQ4vP5EolEMpnM5XIQ5lSpVEqlUqVSaTabXLNCVWK5xicxWLNFok7VVBEVqEcQ5JrNZsvl8tbWVqPR0HinTSS4qqit3uQ1MPyHa0pBDE8wGGR1iMGajCIQiLHiCRrUR0libm4ObPeFQqFcLtfrddZrPVrJqKn86DUfjRIVdVAXi8XNzU2IX5K2sh+mZp8JlxgQ4a7L9B/SycRamWgsEyUJVCMQiKNBEn6/P5vNZrPZTqcDhiYIAYL8Uy7fSL/2H1itGYwkWAd1NpudmJgA7aFSqXD5ceI4Dev0uTbrNr9c7l//YZ9JYIIMBAJg4+vuANUIBOJokESn0wE7UiqVmpiY6PV6jUajXC4Xi8VyuQwtvGjrRtHaIxbR88QHZLgsHJYeMplMKpUql8ubm5vlcpnrtuvKClzF8uG1hKNjStI/ADA0sSkRNOYV3dQIxOF9tWn2HPwL3dlmZ2dbrVapVAI5C74KzlAzitX0UKYblo1g/KlUKpVKQSv7crlM1L3kiHH/Bq+NqY8RMXB3E1IiwuEwtTXROsOjbW2BQCD2WYeghZ6CweDMzMz09HSj0YDi+WBlooFARFGDctiyQsYthsSUNxg5BC8Vi8X19fVqtTqwONLUnvJ6pO1LI47lHFFiYEFtTWSnFhjrkxhVu1QEArH/JEGDX8Ph8IkTJ2ZnZ+v1erFYBIagmQSujTQGSKLWLN71y382eCmdTqdSKaCHSqUCfGYYpWqiWAxKgZb/WE0mliRo3Tra1USsdIRAIA4FQ9Ac2Gg0Go/HgSGg9Va9XmdrbxAv/TC4zfTdUziXBjs8sSwNNY5R30OxWHz//n29XueS+0QuJAa1yr1d3XZJDOuIm5IM5xMNfiW7q2fTACexahgCgRjbNxpeWNAhoNTdiRMnoDkjdUJAsQq2ARErRl0L4RF1a1JVqoFGHYHTAT1MTk6mUqmNjY2NjQ0ou6Rf9UujWoeVVA6xDqQfwzjPKnBLhEIhyhPU9MRSBZsTjzYoBGKcdQifzzc9PT05OQkKxIcPH2q1Gq1lJHbEU73XHGGoai55il/iMrd7vZ5t2ydOnMhkMuvr6xsbG51Oh3pKNPyk6RZnbkpyCHEcYm3rDQ4Sg44n2G+AFShDiC1zB6v4iNg70UB2569KSz3vVScsxXhM7BWIUQGkOXRNiEaj0Wh0dna2XC5vbGyUSqVOpyPmmknViIGd1ZrnLnYzhbN0u91gMLiwsJDJZFZXVz98+MDSkokjYQBDGXOsY29KGmCSgR7KPV1OsWD76ojPEgOizF8bcwEqhiNzL7PmpVLRg/maS9XJWTyaqrWqdMkp7UkntZIjDBUIx3F8Pl8mk8lkMtVqdWNjo1AoQAiTqhyT+Kz1fmwT4odz6R96r9eLRqOffPLJ1tbWysoKdTwQtzy+UYXnIjGMWLEgTAMsriObqhebVLRxywFNM2dOfomGzsE6Xnmd7oZCk+0OJhWUoi4sFY6qXnX679lfpY3qpO2ITRrNixfItiml/4qTAULjNP37iKylmthcD19Gw+kN4UBQKzuXyxUKha2trVqtRtPNNNUThr/PKl1E2nqaEAKOh7W1tXw+3+l0QNp48oIMRhJIDHsy/+AxS+2DYoNPSiGUMFiJICof0taedJ5xKd+cTDGp4aXpBKdaQKlmP+32zN4W+iXbUpTspPlIe5GyXaM5ES82lD50UpJ9oCxDUKMldMClWf3sZ5ZIuBmo6ZWGryfcsVAoNDc3NzU1VSwWNzY2yuWyay82tpzfYIsnVVs66VC73a7P5zt58mQ6nV5ZWdna2lIN71gX0Tsyyxba0dN1PnHNk8UVqHQZzvZYllq09LNTs3DWLMk54a5a2B6s4B4TySi1FMHEgHBq16ugtNFut1utVrvdph9ofUk2WYd7oGLnzmP4JsIb5PP5Jicns9lsqVTK5/OQAKHKRh5JM1GibeXLbQMFaMGylE6nl5eXG40G1whI1aVxAKUBvM9IDIdD+QCYcAliL8xl40NgVGSAVSEYDEajUdEKAYoFZYtms0nJgybusITBhvkfK6pg7UsTExNQy2hjY6NYLHa7XdBc2U7DqsbUhtww8AhB7k9PTyeTyZWVlfX19V6vt3cCAYkBMdQSG63bB05gYtsWaKgZDAZjsRhHGKBMNJtN6L3caDSazWaz2ex0Op1Oh9pJWBvgceAJlh5SqVQikaDeaTDmaJ6Lqk3bkC+LVNXudruBQODMmTOZTObdu3eVSoWmZRBFAKvXZ2chMSCO0hIbH5AJYUCxepYwIEQS6KFardZqtVqtBlTBdb+hOKo8QbORHcdJJBLxeHxmZiafzxcKBa4SKtdz1DUDeeQENjExkUgkfvnll/fv34M1jDUlDd/UAYkBgTi+hAGCHlqsJxKJqakp2ACsTyxPtFotWs1eU2HiyNw3MB9Fo9GlpaWpqam1tbVSqUStN9K4832r5GpZFiRLnz59OpVKvX37tlqt+v3+gU9tITEgEEgYrmwRDofD4fDExAR8A7026/V6tVoFtgCVAhrO0BD7I0YSVIGIx+OxWKxSqayvrxeLRciH4IpqcJ6GPa2JQLWWTqeTyWRisdjy8vLa2hoMbCStaJAYEAiEvE8y/QlUimQySXmi2WxWKpVyuVwqlarVKvRTI0xY2pEhCVo5Awpll8vl9+/fl8tlzl3P0cneUQLndej1en6//8yZMxMTE69fv4aAJSJYk7jiH0gMCARiBFQh8kQikZibmyOEQD+1UqlUKpVqtRoYnbg45kNNEqxxCVzTW1tba2trjUaDZhVwwd8atUxTotWEEoisIlO/35+cnIzH469fv97Y2BDrs3pVX5AYEAjEUDwRiUQikcjMzAwhBDwTxWKxVCpVKpVmswkk4VrR4bDcBDDuT01NTUxM0EqoNKtAI81Vt9E1r56tX0Cd/2L1ViiydP78+WQy+fbtWwimGvhuIzEgEIjR8AR1TkxOTlKSKBQKhUKhXC63Wi2y0xPl8KoRNC7I5/Plcrl0Or22tra5uQmhQYTJLRW1AU04gFgIT8wG5VqWSlUHx3Hm5+fj8fjLly8rlYpYsAeJAYFAHABPSEmiVqsVCoXNzc1isQiO60OtRlB6CIVCp06dSqfTq6ur1WpV2qVHJAkuCFh1CulxXFuKdjqdZDL52WefvXr1Kp/P+3w+WiLQ3KCExIBAIPacJGKxWCwWO3nyZLvdLpVKULoO+jMTQkB4HTqGoPb9ZDIZi8XA8dBqtdgYLZEJDKskcfRgrmOBvcvn850/fz4ej7958wYqfHi6t0gMCARi/0giGAxOTU1NTU31+/1KpVIoFCDBGHqW+f3+Q2dlAkFMCIF6FWBZgshR4tamxdURrSrQbcJYjuOcPHkyHo+/ePGiXq97SnRAYkAgEPtKErQtQSqVSqVSp0+frtfr6+vr+Xy+WCxCgwRaluNQMAS1LEGPnYmJCSh1p6rER8z8DcNkQsC+nU4nnU5fuXLl2bNnhULB3OVgYRleBAJxIBDFX6VS2djYgDwycFZTWaavGK/KOpZ2BBG31PyqqTwv/QZ0hW63u76+TkvdcSZ+lTVpVF0guXP5fL5er/f69euVlRUuktWyrHa7ncvl/tf//tpn25blWMQixEKNAYFAjIUOYVlWIpFIJBJnzpwpl8tUh4AGNYdFgQDLkm3bc3NzyWSSZsNx4tj1hgyvLlBAiO0nn3wSjUZfvXpFuUpzBCQGBAIxdgyRTCaTyeTS0lKxWFxeXs7n8/V6nexEu445Q1DLUjQaPXPmzMbGRj6fNxHHGt3IRDnQjAec5PPz85FI5McffwSu1ZwIiQGBQIwvQ6TT6XQ6ff78+bW1tdXVVXBT27bNFbMbT0BOw+zsbCwWg3hWGrA0jKDnNuaiYKURULBZr9ebnJz8/PPPf/zxR6i7pzqyjXMRgUCMIUOwDWqCweDJkye/+OKLO3fuXLhwIZlMQiciMt5l4akHGFSHXC6nCVdVVWx1PT63oyasC7Ic4vH4Z599lslkIJsENQYEAnGIdQjLsiCQ6ezZs+vr6+/evVtfX4faD+PcKILWsJuZmYnH48vLy/V6nWv+wy3zpZevavVM1QVp1SbxIBA9denSpRcvXuTX1pAYEAjE4WYIEIJ+v39ubm5ubq5QKLx79y6fz0Ns6Ni6H2gZvlgstrS0lM/nt7a2gMxUVbL1NiWxZZBJqVfKPVAv/eLFi6FQ+NWrl0RoyYDEgEAgDqsCkclkMplMrVZbWVlZXl4ulUqO4wQCgbGlBwhYmp+fj8Vi+XweCvARRSc4FROIJZJoRptYgVVFGEBUZ88uEeI0Gk3ubiExIBCIw61AxGKxc+fOLS4uvn///s2bN1tbW4SQ8aQHsPZAb85oNLq6uloqlagTWPS9c6YhsV0rEcpmEGO/C4xkcXGx2+1xR0ZiQCAQR4EegsHgqVOnFhYWVlZWXr9+XSgU+v0+yNxxowcw5sCA19fXNzY2iKIrg/ilqivDwGPp93uTU5O2bSExIBCIo0YPZMfMMj8/f+LEiXw+//PPP29sbHS7XSjBNFb0QL0LMzMz4XCYmpWk3KD5d8gxwMH6vR73ExIDAoE4agqEZVm5XC6Xy62vr798+TKfz/f7/TE0LgE9pFKpcDi8urpaqVTYaCUpRt5NWlr6G4kBgUAcWXqYnp6enp5eW1t79uzZ5uYmIQRiW8eKHiB+9NSpU/l8fnNzk63aTSOXxL49o7pb0m+RGBAIxBGnh5mZmenp6ZWVlZcvX25ublqWNUzbyz3SGyzLmpubC4VCa2trbAcFryoCSyQGugJBYkAgEMeXHubn53O53C+//PLixYtisQiF+caEHmh5pUwmEwqFVldXm82mvuyHawb1MMCSGAgE4rjQg8/nW1xcfPz48ZUrVwKBAPSPG5+iGrDYj0aji4uL8Xi8J/iExYtiyUBMdtPXKme+QWJAIBDHmx4CgcD58+cfP3585swZQgiUDBoTegBu8Pl8p06dymazqrxocS/qkFCRB/el/nqRGBAIxHGkh3g8fuPGjfv378/Ozna7XWhaMA4jpAauubm52dlZ4sXNwLXo8XRjkBgQCMRxpweQm5OTk/fu3bt582YkEhkTyxIV7v1+P5vNnjhxwrZt1p/M5jmz5iNDvYfbTMo6SAwIBOJYqw6WZS0uLn711VdLS0uEkG63Oz5eB8hyWFhYCAQCnE4j9gFV5UiLxCNjBQeJAYFAIHbRQzgcvnHjxt27d6FRARkPpzTU3YtGowsLC5FIBPQG0UnAqguq3tRsxx7pqZAYEAgEQkIPs7OzDx8+/PTTTy3LAtXhwOkBOigEAoGTJ09CqJLXUamaVXz8RjgYEgMCgUBsC1DHcfx+/8WLFx8+fJjNZjudzshLUAw8MJ/PNz8/PzExAXqDvhODyAHSmKVtNYIQNCUhEAiEi+qQzWYfPXp0+fJl27Y7nY5rr+b9GRghZG5uLpPJmOgNhpRmWRbmMSAQCITpCv3SpUsPHjzIZrPNZnMczEqO4/T7/enp6cnJSUhxMOnyRrQJDfQ/JAYEAoEwUh0mJycfP378q1/9qtfrGdYg2gd6mJqampmZMa+JpP1Jku6AxIBAIBC6Rbff77969eqdO3cikQikSR/4qPr9fiaTmZ2dFYNWOUVBM9qdQhrwAX0MCAQC4VF1OHny5OPHj+fn58chDw7CWNPpNE2NZsW9YY3u3aFKaEpCIBAI76pDPB6/d+/elStX+v3+gZfQAG5IpVK5XI7lME+Et00qFkGNAYFAIAbkBsuyLl26dO/evXEwKwE3JBIJ4AY2JtUw7ZkQIvUyIDEgEAiEh1W24zgnTpz49a9/ncvl2u32mHADW25PwwoK2rDQlIRAIBDDqg7xePzBgwcXLlw4cJcDcEMymaR6g8leTAuHbb5DYkAgEIhhucHn812/fv3mzZuEkIN1OUD5Vao3qEaiHiHPJUgMCAQCMQg3wIr73LlzDx48AJfDwSZIg01pZmZGrzTIgpHQlIRAIBAjVR1mZ2cfPXpEE6QPcDD9fj+ZTIrcQEcllEui7ICmJAQCgRgpN6RSqcePHy8sLBysO5rGsE5PT4OrWVdUdYcbxOEiMSAQCMQIuCEYDN6/f//ChQsH284BCoZPTExAPSVWV1CFJDlIDAgEArFH3GDb9o0bN65evdrtdg+wXjfNi85kMuIwWI1BNUIkBgQCgRiNOAaxe/Hixbt374J0PkBugJbRtH+DyAoaIDEgEAjEiFWHxcXF+/fvh8PhXq93UKFKwA2Tk5OJRKLX66mYDIkBgUAg9okb5ubmHj58GI/HD7ByBoxkamoqGo1C/wZDIDEgEAjEnkjkbDb71VdfpdPpgw1Vsm17eno6FAqx3PBxPI6DtZIQCARi/7ghHo8/fvx4ZmbmALkBkrRnZmYCgYC6mBImuCEQCMR+cUM0Gn348OH8/Hyr1TpAbggGg1NTU6LDw9lOc8MENwQCgdhHbgiHww8ePDh9+vQBckOv14tEIlNTU7KuPvyQkBgQCARiz7nB7/ffu3fv7NmzB2VTgiClRCKRzWZpAOvOSBw0JSEQCMQBcINt219++eX58+eBG/afHmjBjFQqBY7oHe0BNQYEAoE4OG64ffv2pUuXWq3WQQ2j3++n0+lIJALjsQgW0UMgEIiD4wb4cOPGjUuXLh2gTcm27cnJSQhSIrIxIDEgEAjEvsJxnJs3b4LecCDc4DhOIBCAICXHcbC6KgKBQIyF6nDz5s3Lly8flN7Q7/dDoVA2myUEzEjofEYgEIgx0Btu3Lhx8eLFA+SGWCyWSqUc4nDuZz8+HgQCgTgobrh582a/33/27FkwGDQsfTpCxaXf709MTHQ6XaffJz4fagwIBAJxkLB28MUXX5w7d+6g/A0WIRMTKcuCdj0WEgMCgUCMBUN8+eWXZ8+eBW7YT3rY5gNIfmbUFSQGBAKBGAtuWFhYOBi9AaurIhAIxLiB1szI5XLNZnO/uUGoloTEgEAgEAevMTiOEwqFHj16dLA1upEYEAgEYry4IRwOP3r0KJ1Od7vdg+ztg88DgUAgxocbYrHYo0ePotHoAXIDEgMCgUCMFzdMTEw8fPgwEAj0ej0kBgQCgUBusBzHmZ6evn//PvlYGRuJAYFAII49N5w8efL27dvQOAGJAYFAIJAbLMdxzp07d+XKlU6ns8/OBiQGBAKBGF9u+Pzzzy9cuLDPiW9IDAgEAjG+3EAIuX379qlTp9rttm3vk8RGYkAgEIjxheM4Pp/v3r17U1NTnU5nf7gBiQGBQCDGWmlwHCcSidy/fz8cDu9PcgMSAwKBQBwCbkin048ePbJtex/ilJAYEAgE4nBww9zc3O3btyHrbU/1BiQGBAKBODTccP78+X3oFI3EgEAgEIeGGwghN27cgM4Ne+eIRmJAIBCIQwPHcWzbvn//fjab3Tu9AYkBgUAgDpPSAEFKDx48CIVCvV5vL7gBiQGBQCAOHzdks9m9q6SExIBAIBCHkhvOnj372Wef7UW1DCQGBAKBOKzccP369dOnT4+cG5AYEAgE4rByg23bd+/enZiYGG1GNBIDAoFAHFY4jhONRu/evev3+0fY0geJAYFAIA6x0gAZ0deuXRth9CoSAwKBQBx6brh8+fK5c+dGlfWGxIBAIBBHgR6+/PLLbDY7ktLcSAwIBAJxFJSGUCh07969QCDQ7/eHtCkhMSAQCMQR4YaZmZnr1693Oh3UGBAIBALx0dlw5syZITMbkBgQCATiSOHevXvpdHqYzAYkBgQCgThSSkM4HL5z545t247jDMYNSAwIBAJx1Lhhfn7+008/HTizAYkBgUAgjiA3XL16NZfLDcYNSAwIBAJxBOH3++/fvx8OhwcozY3EgEAgEEdTaUin01988cUAzXyQGBAIBOLIcsO5c+eWlpa8GpSQGBAIBOIo08OtW7cSiYQnvQGJAYFAII6y0pBIJLw2AUViQCAQiCPODUtLSxcuXDBPh0ZiQCAQiKPPDbdu3cpkMobp0EgMCAQCcfQRiURu3bpFCDFJh0ZiQCAQiGOhNJw+ffr8+fMmEUpIDAgEAnFccOvWrVQq1el09NyAxIBAIBDHRWmIRCJ37txx3RiJAYFAII4RNywuLoJBSdMBFIkBgUAgjheuX7+eSqW63S4SAwKBQKDSsJ3ydv36dU0uNBIDAoFAHDtuOHfu3OLiYrPZsm0LiQGBQCAQxLKsO3fuRKORXq9vEUIcJAYEAoE49kpDKpW6du2aNBcaiQGBQCCOKTdcvHhxbm6u3ea5AYkBgUAgjin8fv+NGzd8PttxHJYakBgQCATi+CoNCwsLFy5c6HQ7rMpgOY6DNwiBQCCOLdrtztaHimVZtg1qg4UaAwKBQBxr+Hx+zsfw/wGqHaGOSmdvOQAAAABJRU5ErkJggg==";
async function pdfCotizacion(id){
  var d=await api('/api/cotizaciones/'+id);if(!d||!d.ok){toast('No se pudo cargar la cotización');return;}
  if(!window.jspdf||!window.jspdf.jsPDF){toast('Generador de PDF no cargó, reintenta');return;}
  var c=d.data;var gold=[139,109,63];var gris=[90,90,90];
  var doc=new window.jspdf.jsPDF();
  var L=14,R=196,W=R-L;
  // ----- Encabezado: logo + datos de la empresa -----
  try{ doc.addImage(LOGO_ASLAN,'PNG',L,11,58,20); }catch(e){ doc.setFontSize(24);doc.setTextColor(gold[0],gold[1],gold[2]);doc.text((CFG&&CFG.nombre?CFG.nombre:${JSON.stringify(EMPRESA.nombre)}),L,22); }
  doc.setFontSize(11);doc.setTextColor(40);
  doc.text((CFG&&CFG.nombre?CFG.nombre:${JSON.stringify(EMPRESA.nombre)}),L,38);
  doc.setFontSize(8.5);doc.setTextColor(gris[0],gris[1],gris[2]);
  var dir=doc.splitTextToSize((CFG&&CFG.direccion?CFG.direccion:${JSON.stringify(EMPRESA.direccion)}),96);
  doc.text(dir,L,43);
  var yd=43+dir.length*4;
  doc.text('Tel. '+(CFG&&CFG.telefono?CFG.telefono:${JSON.stringify(EMPRESA.telefono)}),L,yd);
  doc.text((CFG&&CFG.email?CFG.email:${JSON.stringify(EMPRESA.email)}),L,yd+4.5);
  // Folio / Fecha / Vigencia (derecha)
  doc.setFontSize(15);doc.setTextColor(40);doc.text('COTIZACIÓN',R,18,{align:'right'});
  doc.setFontSize(9);doc.setTextColor(60);
  var hoy=new Date();var vig=new Date(hoy.getTime()+((c.vigencia_dias||15)*86400000));
  doc.text('Folio: '+(c.folio||''),R,26,{align:'right'});
  doc.text('Fecha: '+hoy.toLocaleDateString('es-MX'),R,31,{align:'right'});
  doc.text('Vigencia: '+vig.toLocaleDateString('es-MX'),R,36,{align:'right'});
  doc.setDrawColor(gold[0],gold[1],gold[2]);doc.setLineWidth(0.5);doc.line(L,55,R,55);
  // ----- Datos de Facturación / Datos de Entrega -----
  var yc=62;var midX=110;
  doc.setFontSize(10);doc.setTextColor(gold[0],gold[1],gold[2]);doc.setFont(undefined,'bold');
  doc.text('Datos de Facturación',L,yc);doc.text('Datos de Entrega',midX,yc);
  doc.setFont(undefined,'normal');doc.setFontSize(9);doc.setTextColor(40);
  function campo(et,va,x,y){doc.setTextColor(110);doc.text(et,x,y);doc.setTextColor(30);doc.text(va?String(va):'',x+doc.getTextWidth(et)+2,y);}
  var fy=yc+7;
  campo('Nombre del Cliente:',c.cliente||'',L,fy);
  campo('Razón Social:',c.cliente_empresa||'',L,fy+5.5);
  campo('Dirección:',c.cliente_direccion||'',L,fy+11);
  campo('RFC:',c.cliente_rfc||'',L,fy+16.5);
  campo('Dirección:',c.cliente_direccion||'',midX,fy);
  campo('Referencias:','',midX,fy+5.5);
  campo('Teléfono:',c.cliente_telefono||'',midX,fy+11);
  // ----- Tabla de partidas -----
  var body=(c.items||[]).map(function(it,i){return [String(i+1),it.descripcion||'',String(it.cantidad||0),money(it.precio_unitario),money(it.subtotal_linea)];});
  doc.autoTable({
    startY:fy+24,
    head:[['PARTIDA','MODELO','METROS','PRECIO UNITARIO','TOTAL']],
    body:body.length?body:[['','','','','']],
    theme:'grid',
    headStyles:{fillColor:gold,textColor:255,fontSize:8.5,halign:'center'},
    styles:{fontSize:8.5,textColor:40,cellPadding:2},
    columnStyles:{0:{cellWidth:18,halign:'center'},1:{cellWidth:'auto'},2:{cellWidth:22,halign:'center'},3:{cellWidth:34,halign:'right'},4:{cellWidth:34,halign:'right'}}
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
  doc.text('TOTAL',150,y+1,{align:'right'});doc.text(money(c.total),R,y+1,{align:'right'});
  doc.setFont(undefined,'normal');
  // ----- Condiciones / Notas / Términos / Firmas -----
  var yb=Math.max(y+12,(doc.lastAutoTable?doc.lastAutoTable.finalY:90)+14);
  doc.setFontSize(9.5);doc.setTextColor(gold[0],gold[1],gold[2]);doc.setFont(undefined,'bold');doc.text('CONDICIONES',L,yb);
  doc.setFont(undefined,'normal');doc.setFontSize(8.5);doc.setTextColor(60);
  if(c.condiciones){var cc=doc.splitTextToSize(c.condiciones,W);doc.text(cc,L,yb+5);yb=yb+5+cc.length*4;}else{doc.text('Pago:',L,yb+5);doc.text('Entrega:',L,yb+10);doc.text('No incluye:',L,yb+15);yb=yb+20;}
  if(c.notas){doc.setFontSize(9.5);doc.setTextColor(gold[0],gold[1],gold[2]);doc.setFont(undefined,'bold');doc.text('NOTAS',L,yb+3);doc.setFont(undefined,'normal');doc.setFontSize(8.5);doc.setTextColor(60);var nn=doc.splitTextToSize(c.notas,W);doc.text(nn,L,yb+8);yb=yb+8+nn.length*4;}
  doc.setFontSize(8);doc.setTextColor(40);doc.setFont(undefined,'bold');doc.text('Términos y condiciones:',L,yb+5);
  doc.setFont(undefined,'normal');doc.setTextColor(90);
  doc.text('Una vez depositado el anticipo no hay cambios ni cancelaciones.',L,yb+9.5);
  doc.text('El cliente es responsable por la solicitud del material, color y medidas.',L,yb+13.5);
  // Firmas
  var yf=Math.min(yb+34,285);if(yf<yb+24)yf=yb+24;
  doc.setDrawColor(120);doc.setLineWidth(0.3);
  doc.line(L+6,yf,L+76,yf);doc.line(midX+6,yf,midX+76,yf);
  doc.setFontSize(8.5);doc.setTextColor(60);
  doc.text('Firma representante ASLAN',L+41,yf+5,{align:'center'});
  doc.text('Firma de acuerdo Cliente',midX+41,yf+5,{align:'center'});
  doc.save((c.folio||'cotizacion')+'.pdf');
}

var CFG=null;
async function cargarCFG(){try{var d=await api('/api/config');if(d&&d.ok)CFG=d.data;}catch(e){}}
cargarCFG();
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
<title>ASLAN · Check-in</title>${FONTS}<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"><script src="https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"></script><style>${baseStyles(false)}
.wrap{max-width:460px;margin:0 auto;padding:1.4rem 1.1rem;text-align:center}
.clock{font-size:2.6rem;font-family:'Cormorant Garamond',serif;color:var(--gold);margin:.3rem 0 .2rem}
.big{width:172px;height:172px;border-radius:50%;font-size:1.02rem;font-weight:700;border:none;color:#fff;cursor:pointer;box-shadow:0 8px 40px rgba(0,0,0,.5);letter-spacing:.04em;padding:0 1rem;transition:.15s}
.big:disabled{opacity:.6;cursor:default}
.in{background:var(--ok)} .out{background:var(--err)}
#map{height:230px;border-radius:10px;overflow:hidden;margin:1.1rem 0;border:1px solid var(--bd);background:#111}
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
<script>
var TOKEN=localStorage.getItem('aslan_token');
var USER=JSON.parse(localStorage.getItem('aslan_user')||'null');
if(!TOKEN||!USER){location.href='/login';}
else if(USER.rol!=='cliente'){location.href='/dashboard';} // el equipo va al sistema interno
function H(){return {'Content-Type':'application/json','Authorization':'Bearer '+TOKEN};}
async function api(p,opt){opt=opt||{};opt.headers=H();var r=await fetch(p,opt);if(r.status===401){localStorage.clear();location.href='/login';return null;}return await r.json();}
function logout(){localStorage.clear();location.href='/login';}
function ic(p,s){s=s||18;return "<svg viewBox='0 0 24 24' width='"+s+"' height='"+s+"' fill='none' stroke='currentColor' stroke-width='1.6' stroke-linecap='round' stroke-linejoin='round'>"+p+"</svg>";}
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
           '<div style="display:flex;gap:.5rem;flex-wrap:wrap"><button class="btn ok" onclick="aprobar('+id+','+l.id+',true)"><svg viewBox="0 0 24 24" width="15" height="15" fill="none" stroke="currentColor" stroke-width="2" style="margin-right:.35rem"><path d="M5 12l4 4 10-10"/></svg>Aprobar este material</button>'+
           '<button class="btn sec" onclick="aprobar('+id+','+l.id+',false)">Solicitar revisión</button></div>';
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
