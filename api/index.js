const crypto = require("crypto");
const bcrypt = require("bcryptjs");

// ═══════════════════════════════
// قاعدة بيانات بسيطة في الذاكرة
// ═══════════════════════════════
const DB = {
  users: {},
  tokens: {},
};

// إنشاء admin افتراضي
const adminHash = bcrypt.hashSync("kkee700", 8);
const adminExpire = new Date(Date.now() + 365 * 24 * 60 * 60 * 1000)
  .toISOString()
  .split("T")[0];
DB.users["admin"] = {
  username: "admin",
  password: adminHash,
  expire_date: adminExpire,
  credits: 100,
};

const SERVICE_PRICES = {
  check_fard: 1,
  check_kg: 2,
  check_imei: 1,
};

// ═══════════════════════════════
// دوال مساعدة
// ═══════════════════════════════
function getAuthUser(token, device_id) {
  if (!token || !device_id) return null;
  const tok = DB.tokens[token];
  if (!tok || tok.device_id !== device_id) return null;
  const user = DB.users[tok.username];
  if (!user) return null;
  if (new Date(user.expire_date) < new Date()) return null;
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
  if (req.method === "OPTIONS") {
    respond(res, { ok: true });
    return;
  }

  const action = (req.query && req.query.action) || "";
  const input = req.method === "POST" ? req.body || {} : req.query || {};

  // ══ تسجيل الدخول ══
  if (action === "login") {
    const { username, password, device_id } = input;
    if (!username || !password || !device_id)
      return respond(res, { success: false, message: "بيانات ناقصة" });

    const user = DB.users[username];
    if (!user || !bcrypt.compareSync(password, user.password))
      return respond(res, { success: false, message: "اسم المستخدم أو كلمة المرور خاطئة" });

    if (new Date(user.expire_date) < new Date())
      return respond(res, { success: false, message: "انتهت صلاحية الحساب" });

    // التحقق من الجهاز
    const existingEntry = Object.entries(DB.tokens).find(
      ([, v]) => v.username === username
    );
    if (existingEntry && existingEntry[1].device_id !== device_id)
      return respond(res, { success: false, message: "هذا الحساب مسجّل على جهاز آخر" });

    // حذف التوكن القديم
    if (existingEntry) delete DB.tokens[existingEntry[0]];

    const token =
      crypto.randomBytes(16).toString("hex") +
      crypto.randomBytes(16).toString("hex");
    DB.tokens[token] = { username, device_id };

    return respond(res, {
      success: true,
      token,
      username: user.username,
      expire_date: user.expire_date,
      credits: user.credits,
      message: "تم تسجيل الدخول بنجاح",
    });
  }

  // ══ التحقق من التوكن ══
  if (action === "verify") {
    const user = getAuthUser(input.token, input.device_id);
    if (!user)
      return respond(res, { success: false, message: "توكن غير صالح أو جهاز مختلف" });
    return respond(res, {
      success: true,
      username: user.username,
      expire_date: user.expire_date,
      credits: user.credits,
      message: "التوكن صالح",
    });
  }

  // ══ جلب الرصيد ══
  if (action === "get_balance") {
    const user = getAuthUser(input.token, input.device_id);
    if (!user) return respond(res, { success: false, message: "غير مصرح" });
    return respond(res, { success: true, credits: user.credits, username: user.username });
  }

  // ══ خصم الكريدت ══
  if (action === "deduct_credit") {
    const user = getAuthUser(input.token, input.device_id);
    const service = input.service || "";
    if (!user) return respond(res, { success: false, message: "غير مصرح" });
    if (!SERVICE_PRICES[service])
      return respond(res, { success: false, message: "خدمة غير معروفة" });
    const price = SERVICE_PRICES[service];
    if (user.credits < price)
      return respond(res, {
        success: false,
        message: "رصيدك غير كافٍ",
        credits: user.credits,
        required: price,
      });
    user.credits -= price;
    return respond(res, {
      success: true,
      credits: user.credits,
      deducted: price,
      message: `تم خصم ${price} كريدت`,
    });
  }

  // ══ إضافة رصيد (admin) ══
  if (action === "add_credits") {
    const { admin_token, username, amount } = input;
    const tok = DB.tokens[admin_token];
    if (!tok || tok.username !== "admin")
      return respond(res, { success: false, message: "غير مصرح" });
    const target = DB.users[username];
    if (!target) return respond(res, { success: false, message: "المستخدم غير موجود" });
    const amt = parseInt(amount);
    if (!amt || amt <= 0)
      return respond(res, { success: false, message: "مبلغ غير صحيح" });
    target.credits += amt;
    return respond(res, {
      success: true,
      message: `تم إضافة ${amt} كريدت لـ ${username}`,
      credits: target.credits,
    });
  }

  // ══ إنشاء مستخدم (admin) ══
  if (action === "create_user") {
    const { admin_token, username, password } = input;
    const days = parseInt(input.days) || 30;
    const credits = parseInt(input.credits) || 0;
    const tok = DB.tokens[admin_token];
    if (!tok || tok.username !== "admin")
      return respond(res, { success: false, message: "غير مصرح" });
    if (!username || !password)
      return respond(res, { success: false, message: "بيانات ناقصة" });
    if (DB.users[username])
      return respond(res, { success: false, message: "اسم المستخدم موجود مسبقاً" });
    const hash = bcrypt.hashSync(password, 8);
    const expire = new Date(Date.now() + days * 24 * 60 * 60 * 1000)
      .toISOString()
      .split("T")[0];
    DB.users[username] = { username, password: hash, expire_date: expire, credits };
    return respond(res, {
      success: true,
      message: `تم إنشاء ${username} بصلاحية ${days} يوم ورصيد ${credits} كريدت`,
    });
  }

  // ══ تسجيل الخروج ══
  if (action === "logout") {
    if (input.token && DB.tokens[input.token]) delete DB.tokens[input.token];
    return respond(res, { success: true, message: "تم تسجيل الخروج" });
  }

  // الصفحة الرئيسية
  return respond(res, {
    success: true,
    message: "IMEI Server is running",
    version: "2.0",
  });
};
