const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const cookieParser = require("cookie-parser");
const rateLimit = require("express-rate-limit");
const { z } = require("zod");
const { createClient } = require("@supabase/supabase-js");

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);

const PORT = process.env.PORT || 3000;
const NODE_ENV = process.env.NODE_ENV || "development";
const IS_PROD = NODE_ENV === "production";

const requiredEnv = [
  "SUPABASE_URL",
  "SUPABASE_PUBLISHABLE_KEY",
  "SUPABASE_SECRET_KEY",
  "FRONTEND_ORIGIN",
  "ADMIN_EMAIL",
];

for (const key of requiredEnv) {
  if (!process.env[key]) {
    console.error(`Variável obrigatória ausente: ${key}`);
    if (IS_PROD) process.exit(1);
  }
}

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_PUBLISHABLE_KEY = process.env.SUPABASE_PUBLISHABLE_KEY;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || "").trim().toLowerCase();

const allowedOrigins = (process.env.FRONTEND_ORIGIN || "")
  .split(",")
  .map((origin) => origin.trim().replace(/\/$/, ""))
  .filter(Boolean);

const COOKIE_NAME = "finance_refresh";
const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: IS_PROD,
  sameSite: IS_PROD ? "none" : "lax",
  path: "/api/auth",
  maxAge: 30 * 24 * 60 * 60 * 1000,
};

function createPublicClient() {
  return createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } }
  );
}

const supabaseAdmin = createClient(
  SUPABASE_URL || "http://127.0.0.1:54321",
  SUPABASE_SECRET_KEY || "missing-secret-key",
  { auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false } }
);

function createUserClient(accessToken) {
  return createClient(
    SUPABASE_URL,
    SUPABASE_PUBLISHABLE_KEY,
    {
      global: { headers: { Authorization: `Bearer ${accessToken}` } },
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    }
  );
}

app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    // Permite chamadas sem Origin (ex.: health check/CLI); autenticação continua exigida nas rotas privadas.
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ""))) {
      return callback(null, true);
    }
    return callback(new Error("Origem não autorizada pelo CORS."));
  },
  credentials: true,
  methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization", "X-Requested-With"],
  maxAge: 86400,
}));
app.use(express.json({ limit: "100kb" }));
app.use(cookieParser());

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "Muitas tentativas. Aguarde alguns minutos." },
});
app.use(generalLimiter);

function asyncHandler(fn) {
  return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
}

function getBearerToken(req) {
  const header = req.headers.authorization || "";
  const match = header.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

function requireSameOrigin(req, res, next) {
  // Operações com cookie de refresh exigem origem autorizada e header não-simple.
  const origin = (req.headers.origin || "").replace(/\/$/, "");
  if (!origin || !allowedOrigins.includes(origin) || !req.headers["x-requested-with"]) {
    return res.status(403).json({ error: "Requisição de origem não autorizada." });
  }
  next();
}

const requireAuth = asyncHandler(async (req, res, next) => {
  const token = getBearerToken(req);
  if (!token) return res.status(401).json({ error: "Token de acesso não informado." });

  const { data, error } = await supabaseAdmin.auth.getUser(token);
  if (error || !data.user) return res.status(401).json({ error: "Sessão inválida ou expirada." });

  const { data: profile, error: profileError } = await supabaseAdmin
    .from("profiles")
    .select("id, name, email, role, status, created_at")
    .eq("id", data.user.id)
    .maybeSingle();

  if (profileError || !profile) return res.status(403).json({ error: "Perfil não encontrado." });
  if (profile.status !== "active") return res.status(403).json({ error: "Usuário inativo." });

  req.auth = { user: data.user, profile, token };
  req.supabase = createUserClient(token);
  next();
});

function requireAdmin(req, res, next) {
  if (req.auth?.profile?.role !== "admin") {
    return res.status(403).json({ error: "Acesso restrito ao administrador." });
  }
  next();
}

function parse(schema, value) {
  const result = schema.safeParse(value);
  if (!result.success) {
    const error = new Error("Dados inválidos.");
    error.status = 400;
    error.details = result.error.flatten();
    throw error;
  }
  return result.data;
}

function writeRefreshCookie(res, refreshToken) {
  res.cookie(COOKIE_NAME, refreshToken, COOKIE_OPTIONS);
}

function clearRefreshCookie(res) {
  res.clearCookie(COOKIE_NAME, {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: IS_PROD ? "none" : "lax",
    path: "/api/auth",
  });
}

async function writeAudit({ actorId, action, entity, entityId = null, metadata = {} }) {
  const { error } = await supabaseAdmin.from("audit_logs").insert({
    user_id: actorId,
    action,
    entity,
    entity_id: entityId,
    metadata,
  });
  if (error) console.error("Falha ao gravar auditoria:", error.message);
}

const registerSchema = z.object({
  name: z.string().trim().min(2).max(120),
  email: z.string().trim().email().max(254),
  password: z.string().min(10).max(128),
}).strict();

const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(1).max(128),
}).strict();

const transactionSchema = z.object({
  description: z.string().trim().min(1).max(180),
  amount: z.number().finite().positive().max(999999999),
  type: z.enum(["income", "expense"]),
  category: z.string().trim().min(1).max(80),
  transaction_date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  payment_method: z.string().trim().max(80).optional().nullable(),
  notes: z.string().trim().max(2000).optional().nullable(),
}).strict();

const statusSchema = z.object({
  status: z.enum(["active", "inactive"]),
}).strict();

function setNoStore(res) {
  res.set("Cache-Control", "no-store");
}

app.get("/", (req, res) => {
  res.json({ name: "API Sistema Financeiro", status: "online", version: "1.0.0" });
});

app.get("/api/health", (req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

// -------------------- AUTENTICAÇÃO --------------------

app.post("/api/auth/register", authLimiter, asyncHandler(async (req, res) => {
  const body = parse(registerSchema, req.body);
  const email = body.email.toLowerCase();

  // O e-mail administrativo fica reservado; cadastro público nunca define role.
  if (email === ADMIN_EMAIL) {
    return res.status(403).json({ error: "Este e-mail é reservado para a administração." });
  }

  const { data, error } = await createPublicClient().auth.signUp({
    email,
    password: body.password,
    options: { data: { name: body.name } },
  });

  if (error) {
    const status = /already registered|already been registered/i.test(error.message) ? 409 : 400;
    return res.status(status).json({ error: status === 409 ? "E-mail já cadastrado." : error.message });
  }

  // A trigger do banco cria o perfil com role=user. Não aceitamos role do cliente.
  setNoStore(res);
  return res.status(201).json({
    message: "Cadastro recebido. Verifique seu e-mail para confirmar a conta, caso a confirmação esteja habilitada.",
    user: data.user ? { id: data.user.id, email: data.user.email } : null,
    confirmationRequired: !data.session,
  });
}));

app.post("/api/auth/login", authLimiter, asyncHandler(async (req, res) => {
  const body = parse(loginSchema, req.body);
  const { data, error } = await createPublicClient().auth.signInWithPassword({
    email: body.email.toLowerCase(),
    password: body.password,
  });
  if (error || !data.session) return res.status(401).json({ error: "E-mail ou senha inválidos." });

  const { data: profile, error: profileError } = await supabaseAdmin
    .from("profiles")
    .select("id, name, email, role, status")
    .eq("id", data.user.id)
    .maybeSingle();

  if (profileError || !profile || profile.status !== "active") {
    return res.status(403).json({ error: "Conta sem perfil ativo. Entre em contato com o administrador." });
  }

  writeRefreshCookie(res, data.session.refresh_token);
  setNoStore(res);
  res.json({
    access_token: data.session.access_token,
    expires_at: data.session.expires_at,
    user: profile,
  });
}));

app.post("/api/auth/refresh", requireSameOrigin, authLimiter, asyncHandler(async (req, res) => {
  const refreshToken = req.cookies?.[COOKIE_NAME];
  if (!refreshToken) return res.status(401).json({ error: "Refresh token ausente. Faça login novamente." });

  const { data, error } = await supabaseAdmin.auth.refreshSession({ refresh_token: refreshToken });
  if (error || !data.session) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: "Não foi possível renovar a sessão. Faça login novamente." });
  }

  writeRefreshCookie(res, data.session.refresh_token);
  setNoStore(res);
  res.json({ access_token: data.session.access_token, expires_at: data.session.expires_at });
}));

app.post("/api/auth/logout", requireSameOrigin, asyncHandler(async (req, res) => {
  const token = getBearerToken(req);
  const refreshToken = req.cookies?.[COOKIE_NAME];

  if (token && refreshToken) {
    const client = createClient(SUPABASE_URL, SUPABASE_PUBLISHABLE_KEY, {
      auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
    });
    await client.auth.setSession({ access_token: token, refresh_token: refreshToken });
    await client.auth.signOut();
  }
  clearRefreshCookie(res);
  res.json({ message: "Sessão encerrada." });
}));

app.get("/api/auth/me", requireAuth, (req, res) => {
  setNoStore(res);
  res.json({ user: req.auth.profile });
});

app.post("/api/auth/forgot-password", authLimiter, asyncHandler(async (req, res) => {
  const body = parse(z.object({ email: z.string().trim().email() }).strict(), req.body);
  const redirectTo = process.env.PASSWORD_RESET_REDIRECT;
  const { error } = await createPublicClient().auth.resetPasswordForEmail(body.email.toLowerCase(), {
    ...(redirectTo ? { redirectTo } : {}),
  });
  if (error) console.error("Solicitação de recuperação:", error.message);
  // Resposta genérica para não revelar se o e-mail existe.
  res.json({ message: "Se o e-mail estiver cadastrado, você receberá as instruções de recuperação." });
}));

app.post("/api/auth/reset-password", requireAuth, asyncHandler(async (req, res) => {
  const body = parse(z.object({ password: z.string().min(10).max(128) }).strict(), req.body);
  const { error } = await req.supabase.auth.updateUser({ password: body.password });
  if (error) return res.status(400).json({ error: error.message });
  res.json({ message: "Senha atualizada com sucesso." });
}));

// -------------------- TRANSAÇÕES DO USUÁRIO --------------------

app.get("/api/transactions", requireAuth, asyncHandler(async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page || "1", 10));
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit || "20", 10)));
  const from = (page - 1) * limit;
  const to = from + limit - 1;

  let query = req.supabase.from("transactions")
    .select("id, description, amount, type, category, transaction_date, payment_method, notes, created_at, updated_at", { count: "exact" });

  if (req.query.type && ["income", "expense"].includes(req.query.type)) query = query.eq("type", req.query.type);
  if (req.query.category) query = query.eq("category", String(req.query.category).slice(0, 80));
  if (req.query.search) query = query.ilike("description", `%${String(req.query.search).slice(0, 100)}%`);

  const order = req.query.order === "asc" ? true : false;
  const { data, error, count } = await query
    .order("transaction_date", { ascending: order })
    .range(from, to);

  if (error) return res.status(400).json({ error: error.message });
  res.json({ data, pagination: { page, limit, total: count || 0, pages: Math.ceil((count || 0) / limit) } });
}));

app.get("/api/transactions/:id", requireAuth, asyncHandler(async (req, res) => {
  const { data, error } = await req.supabase.from("transactions")
    .select("*").eq("id", req.params.id).maybeSingle();
  if (error) return res.status(400).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "Transação não encontrada." });
  res.json({ data });
}));

app.post("/api/transactions", requireAuth, asyncHandler(async (req, res) => {
  const body = parse(transactionSchema, req.body);
  const { data, error } = await req.supabase.from("transactions")
    .insert({ ...body, user_id: req.auth.user.id })
    .select("*").single();
  if (error) return res.status(400).json({ error: error.message });
  res.status(201).json({ data });
}));

app.put("/api/transactions/:id", requireAuth, asyncHandler(async (req, res) => {
  const body = parse(transactionSchema, req.body);
  const { data, error } = await req.supabase.from("transactions")
    .update(body).eq("id", req.params.id).select("*").maybeSingle();
  if (error) return res.status(400).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "Transação não encontrada ou sem permissão." });
  res.json({ data });
}));

app.delete("/api/transactions/:id", requireAuth, asyncHandler(async (req, res) => {
  const { data, error } = await req.supabase.from("transactions")
    .delete().eq("id", req.params.id).select("id").maybeSingle();
  if (error) return res.status(400).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "Transação não encontrada ou sem permissão." });
  res.json({ message: "Transação excluída." });
}));

app.get("/api/dashboard/summary", requireAuth, asyncHandler(async (req, res) => {
  // Paginação interna para somar todas as transações sem depender do limite padrão do PostgREST.
  let offset = 0;
  const batchSize = 1000;
  let totalIncome = 0;
  let totalExpenses = 0;
  let transactionCount = 0;

  while (true) {
    const { data, error } = await req.supabase.from("transactions")
      .select("amount, type")
      .range(offset, offset + batchSize - 1);
    if (error) return res.status(400).json({ error: error.message });

    for (const item of data) {
      const amount = Number(item.amount);
      if (item.type === "income") totalIncome += amount;
      if (item.type === "expense") totalExpenses += amount;
    }
    transactionCount += data.length;
    if (data.length < batchSize) break;
    offset += batchSize;
  }

  res.json({
    totalIncome: Number(totalIncome.toFixed(2)),
    totalExpenses: Number(totalExpenses.toFixed(2)),
    balance: Number((totalIncome - totalExpenses).toFixed(2)),
    transactionCount,
  });
}));

// -------------------- ADMINISTRAÇÃO --------------------

app.get("/api/users", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const page = Math.max(1, Number.parseInt(req.query.page || "1", 10));
  const limit = Math.min(100, Math.max(1, Number.parseInt(req.query.limit || "20", 10)));
  const from = (page - 1) * limit;
  const to = from + limit - 1;

  let query = supabaseAdmin.from("profiles")
    .select("id, name, email, role, status, created_at", { count: "exact" });
  if (req.query.status && ["active", "inactive"].includes(req.query.status)) {
    query = query.eq("status", req.query.status);
  }
  if (req.query.search) {
    const term = String(req.query.search).replace(/[,%()]/g, "").slice(0, 100);
    query = query.or(`name.ilike.%${term}%,email.ilike.%${term}%`);
  }

  const { data, error, count } = await query.order("created_at", { ascending: false }).range(from, to);
  if (error) return res.status(400).json({ error: error.message });
  res.json({ data, pagination: { page, limit, total: count || 0, pages: Math.ceil((count || 0) / limit) } });
}));

app.get("/api/users/:id", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const { data, error } = await supabaseAdmin.from("profiles")
    .select("id, name, email, role, status, created_at, updated_at")
    .eq("id", req.params.id).maybeSingle();
  if (error) return res.status(400).json({ error: error.message });
  if (!data) return res.status(404).json({ error: "Usuário não encontrado." });
  res.json({ data });
}));

app.patch("/api/users/:id/status", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const body = parse(statusSchema, req.body);
  if (req.params.id === req.auth.user.id && body.status === "inactive") {
    return res.status(400).json({ error: "Você não pode desativar a própria conta administrativa." });
  }

  const { data: target, error: lookupError } = await supabaseAdmin.from("profiles")
    .select("id, role, status").eq("id", req.params.id).maybeSingle();
  if (lookupError) return res.status(400).json({ error: lookupError.message });
  if (!target) return res.status(404).json({ error: "Usuário não encontrado." });
  if (target.role === "admin") return res.status(403).json({ error: "O status de uma conta administrativa não pode ser alterado por esta rota." });

  const { data, error } = await supabaseAdmin.from("profiles")
    .update({ status: body.status, updated_at: new Date().toISOString() })
    .eq("id", req.params.id)
    .select("id, name, email, role, status")
    .single();
  if (error) return res.status(400).json({ error: error.message });

  await writeAudit({
    actorId: req.auth.user.id,
    action: body.status === "active" ? "user_activated" : "user_deactivated",
    entity: "profiles",
    entityId: req.params.id,
    metadata: { previousStatus: target.status, newStatus: body.status },
  });
  res.json({ data });
}));

app.get("/api/admin/dashboard", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  const [total, active, inactive] = await Promise.all([
    supabaseAdmin.from("profiles").select("id", { count: "exact", head: true }),
    supabaseAdmin.from("profiles").select("id", { count: "exact", head: true }).eq("status", "active"),
    supabaseAdmin.from("profiles").select("id", { count: "exact", head: true }).eq("status", "inactive"),
  ]);
  const failure = total.error || active.error || inactive.error;
  if (failure) return res.status(400).json({ error: failure.message });
  res.json({
    totalUsers: total.count || 0,
    activeUsers: active.count || 0,
    inactiveUsers: inactive.count || 0,
  });
}));

app.get("/api/admin/users", requireAuth, requireAdmin, asyncHandler(async (req, res) => {
  // Alias administrativo explícito para a listagem paginada.
  req.url = `/api/users?${new URLSearchParams(req.query).toString()}`;
  return res.redirect(307, req.url);
}));

// -------------------- ERROS --------------------

app.use((req, res) => res.status(404).json({ error: "Endpoint não encontrado." }));

app.use((err, req, res, next) => {
  console.error("Erro na API:", err.message);
  if (res.headersSent) return next(err);
  if (err.message === "Origem não autorizada pelo CORS.") {
    return res.status(403).json({ error: err.message });
  }
  res.status(err.status || 500).json({
    error: err.status ? err.message : "Erro interno do servidor.",
    ...(err.details ? { details: err.details } : {}),
  });
});

// Exporta o Express para a Vercel. Localmente, inicia o servidor HTTP.
if (require.main === module) {
  app.listen(PORT, () => console.log(`API executando em http://localhost:${PORT}`));
}
module.exports = app;
