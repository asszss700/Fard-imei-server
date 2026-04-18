const crypto = require("crypto");
const bcrypt = require("bcryptjs");

const SUPABASE_URL = "https://bsmqkufsxjsmnzmtpejz.supabase.co";
const SUPABASE_KEY = "sb_publishable_RC3EuJ7p_qO6aTvIZCoq9w_4WA40jqv";

const SERVICE_PRICES = { check_fard: 1, check_kg: 2, check_imei: 1 };

// ═══════════════════════════════
// دوال Supabase
// ═══════════════════════════════
const headers = {
  apikey: SUPABASE_KEY,
  Authorization: `Bearer ${SUPABASE_KEY}`,
  "Content-Type": "application/json",
};

async function dbGet(table, filters = {}) {
  let url = `${SUPABASE_URL}/rest/v1/${table}?`;
  Object.entries(filters).forEach(([k, v]) => { url += `${k}=eq.${encodeURIComponent(v)}&`; });
  url += "limit=1";
  const res = await fetch(url, { headers });
  const data = await res.json();
  return Array.isArray(data) && data.length > 0 ? data[0] : null;
}

async function dbAll(table, filters = {}, order = "") {
  let url = `${SUPABASE_URL}/rest/v1/${table}?`;
  Object.entries(filters).forEach(([k, v]) => { url += `${k}=eq.${encodeURIComponent(v)}&`; });
  if (order) url += `order=${order}&`;
  url += "limit=100";
  const res = await fetch(url, { headers });
  return await res.json();
}

async function dbInsert(table, body) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/${table}`, {
    method: "POST",
    headers: { ...headers, Prefer: "return=representation" },
    body: JSON.stringify(body),
  });
  const data = await res.json();
  return Array.isArray(data) ? data[0] : data;
}

async function dbUpdate(table, filters, body) {
  let url = `${SUPABASE_URL}/rest/v1/${table}?`;
  Object.entries(filters).forEach(([k, v]) => { url += `${k}=eq.${encodeURIComponent(v)}&`; });
  await fetch(url, { method: "PATCH", headers, body: JSON.stringify(body) });
}

async function dbDelete(table, filters) {
  let url = `${SUPABASE_URL}/rest/v1/${table}?`;
  Object.entries(filters).forEach(([k, v]) => { url += `${k}=eq.${encodeURIComponent(v)}&`; });
  await fetch(url, { method: "DELETE", headers });
}

async function getAuthUser(token, device_id) {
  if (!token || !device_id) return null;
  const tok = await dbGet("tokens", { token, device_id });
  if (!tok) return null;
  const user = await dbGet("users", { username: tok.username });
  if (!user || new Date(user.expire_date) < new Date()) return null;
  return user;
}

function respond(res, data) {
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.status(200).json(data);
}

// ═══════════════════════════════
// Handler الرئيسي
// ═══════════════════════════════
module.exports = async function handler(req, res) {
  if (req.method === "OPTIONS") { respond(res, { ok: true }); return; }

  const action = (req.query && req.query.action) || "";
  const input = req.method === "POST" ? req.body || {} : req.query || {};

  // ══ تسجيل الدخول ══
  if (action === "login") {
    const { username, password, device_id } = input;
    if (!username || !password || !device_id)
      return respond(res, { success: false, message: "بيانات ناقصة" });

    const user = await dbGet("users", { username });
    if (!user || !bcrypt.compareSync(password, user.password))
      return respond(res, { success: false, message: "اسم المستخدم أو كلمة المرور خاطئة" });

    if (new Date(user.expire_date) < new Date())
      return respond(res, { success: false, message: "انتهت صلاحية الحساب" });

    const existingTok = await dbGet("tokens", { username });
    if (existingTok && existingTok.device_id !== device_id)
      return respond(res, { success: false, message: "هذا الحساب مسجّل على جهاز آخر" });

    await dbDelete("tokens", { username });
    const token = crypto.randomBytes(16).toString("hex") + crypto.randomBytes(16).toString("hex");
    await dbInsert("tokens", { username, token, device_id });

    return respond(res, {
      success: true, token,
      username: user.username,
      expire_date: user.expire_date,
      credits: user.credits,
      message: "تم تسجيل الدخول بنجاح",
    });
  }

  // ══ التحقق من التوكن ══
  if (action === "verify") {
    const user = await getAuthUser(input.token, input.device_id);
    if (!user) return respond(res, { success: false, message: "توكن غير صالح أو جهاز مختلف" });
    return respond(res, { success: true, username: user.username, expire_date: user.expire_date, credits: user.credits, message: "التوكن صالح" });
  }

  // ══ جلب الرصيد ══
  if (action === "get_balance") {
    const user = await getAuthUser(input.token, input.device_id);
    if (!user) return respond(res, { success: false, message: "غير مصرح" });
    return respond(res, { success: true, credits: user.credits, username: user.username });
  }

  // ══ خصم الكريدت ══
  if (action === "deduct_credit") {
    const user = await getAuthUser(input.token, input.device_id);
    const service = input.service || "";
    if (!user) return respond(res, { success: false, message: "غير مصرح" });
    if (!SERVICE_PRICES[service]) return respond(res, { success: false, message: "خدمة غير معروفة" });
    const price = SERVICE_PRICES[service];
    if (user.credits < price)
      return respond(res, { success: false, message: "رصيدك غير كافٍ", credits: user.credits, required: price });
    await dbUpdate("users", { username: user.username }, { credits: user.credits - price });
    await dbInsert("transactions", { username: user.username, amount: -price, type: "deduct", description: service });
    return respond(res, { success: true, credits: user.credits - price, deducted: price, message: `تم خصم ${price} كريدت` });
  }

  // ══ إضافة رصيد (admin) ══
  if (action === "add_credits") {
    const { admin_token, username, amount } = input;
    const tok = await dbGet("tokens", { token: admin_token });
    if (!tok || tok.username !== "admin") return respond(res, { success: false, message: "غير مصرح" });
    const target = await dbGet("users", { username });
    if (!target) return respond(res, { success: false, message: "المستخدم غير موجود" });
    const amt = parseInt(amount);
    if (!amt || amt <= 0) return respond(res, { success: false, message: "مبلغ غير صحيح" });
    await dbUpdate("users", { username }, { credits: target.credits + amt });
    await dbInsert("transactions", { username, amount: amt, type: "add", description: "admin_add" });
    return respond(res, { success: true, message: `تم إضافة ${amt} كريدت لـ ${username}`, credits: target.credits + amt });
  }

  // ══ إنشاء مستخدم (admin) ══
  if (action === "create_user") {
    const { admin_token, username, password } = input;
    const days = parseInt(input.days) || 30;
    const credits = parseInt(input.credits) || 0;
    const tok = await dbGet("tokens", { token: admin_token });
    if (!tok || tok.username !== "admin") return respond(res, { success: false, message: "غير مصرح" });
    if (!username || !password) return respond(res, { success: false, message: "بيانات ناقصة" });
    const existing = await dbGet("users", { username });
    if (existing) return respond(res, { success: false, message: "اسم المستخدم موجود مسبقاً" });
    const hash = bcrypt.hashSync(password, 8);
    const expire = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().split("T")[0];
    await dbInsert("users", { username, password: hash, expire_date: expire, credits });
    return respond(res, { success: true, message: `تم إنشاء ${username} بصلاحية ${days} يوم ورصيد ${credits} كريدت` });
  }

  // ══ تسجيل الخروج ══
  if (action === "logout") {
    if (input.token) await dbDelete("tokens", { token: input.token });
    return respond(res, { success: true, message: "تم تسجيل الخروج" });
  }

  // ══ حذف مستخدم ══
  if (action === "delete_user") {
    const { admin_token, username } = input;
    const tok = await dbGet("tokens", { token: admin_token });
    if (!tok || tok.username !== "admin") return respond(res, { success: false, message: "غير مصرح" });
    if (username === "admin") return respond(res, { success: false, message: "لا يمكن حذف admin" });
    const target = await dbGet("users", { username });
    if (!target) return respond(res, { success: false, message: "المستخدم غير موجود" });
    await dbDelete("tokens", { username });
    await dbDelete("users", { username });
    return respond(res, { success: true, message: "تم حذف " + username });
  }

  // ══ عرض المستخدمين ══
  if (action === "list_users") {
    const tok = await dbGet("tokens", { token: input.admin_token });
    if (!tok || tok.username !== "admin") return respond(res, { success: false, message: "غير مصرح" });
    const users = await dbAll("users");
    const list = Array.isArray(users) ? users.map(u => ({
      username: u.username,
      expire_date: u.expire_date,
      credits: u.credits,
      active: new Date(u.expire_date) > new Date()
    })) : [];
    return respond(res, { success: true, users: list });
  }

  // ══ سجل المعاملات ══
  if (action === "transactions") {
    const user = await getAuthUser(input.token, input.device_id);
    if (!user) return respond(res, { success: false, message: "غير مصرح" });
    const rows = await dbAll("transactions", { username: user.username }, "id.desc");
    return respond(res, { success: true, transactions: Array.isArray(rows) ? rows.slice(0, 20) : [], credits: user.credits });
  }

  return respond(res, { success: true, message: "IMEI Server is running", version: "2.0" });
};
