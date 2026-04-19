const crypto  = require("crypto");
const bcrypt  = require("bcryptjs");
const { MongoClient } = require("mongodb");

const MONGO_URI = process.env.MONGODB_URI;
const DB_NAME   = "imei_checker";

const SERVICE_PRICES = { check_fard: 1, check_kg: 2, check_imei: 1 };

// استخدام global لتجنب إعادة الاتصال في كل طلب
let cachedClient = global._mongoClient || null;

async function getDB() {
  if (!cachedClient) {
    cachedClient = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 5000 });
    await cachedClient.connect();
    global._mongoClient = cachedClient;
    // إنشاء admin افتراضي
    const db = cachedClient.db(DB_NAME);
    const exists = await db.collection("users").findOne({ username: "admin" });
    if (!exists) {
      const hash = bcrypt.hashSync("admin123", 8);
      const expire = new Date(Date.now() + 365*24*60*60*1000).toISOString().split("T")[0];
      await db.collection("users").insertOne({ username:"admin", password:hash, expire_date:expire, credits:999 });
    }
  }
  return cachedClient.db(DB_NAME);
}

function respond(res, data) {
  res.setHeader("Content-Type","application/json");
  res.setHeader("Access-Control-Allow-Origin","*");
  res.setHeader("Access-Control-Allow-Methods","GET,POST,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers","Content-Type");
  res.status(200).json(data);
}

async function getAuthUser(db, token, device_id) {
  if (!token || !device_id) return null;
  const tok = await db.collection("tokens").findOne({ token });
  if (!tok || tok.device_id !== device_id) return null;
  const user = await db.collection("users").findOne({ username: tok.username });
  if (!user || new Date(user.expire_date) < new Date()) return null;
  return user;
}

async function isAdmin(db, admin_token) {
  const tok = await db.collection("tokens").findOne({ token: admin_token });
  return tok && tok.username === "admin";
}

module.exports = async function handler(req, res) {
  if (req.method === "OPTIONS") { respond(res, { ok:true }); return; }

  let db;
  try { db = await getDB(); }
  catch(e) { return respond(res, { success:false, message:"فشل الاتصال بقاعدة البيانات: " + e.message }); }

  const action = (req.query && req.query.action) || "";
  const input  = req.method === "POST" ? (req.body || {}) : (req.query || {});

  // ══ تسجيل الدخول ══
  if (action === "login") {
    const { username, password, device_id } = input;
    if (!username || !password || !device_id)
      return respond(res, { success:false, message:"بيانات ناقصة" });
    const user = await db.collection("users").findOne({ username });
    if (!user || !bcrypt.compareSync(password, user.password))
      return respond(res, { success:false, message:"اسم المستخدم أو كلمة المرور خاطئة" });
    if (new Date(user.expire_date) < new Date())
      return respond(res, { success:false, message:"انتهت صلاحية الحساب" });
    if (username === "admin" && device_id !== "web-admin")
      return respond(res, { success:false, message:"اسم المستخدم أو كلمة المرور خاطئة" });
    if (username !== "admin") {
      const existing = await db.collection("tokens").findOne({ username });
      if (existing && existing.device_id !== device_id) {
        const lockDays = user.device_lock_days || 30;
        const lockedUntil = user.device_locked_until ? new Date(user.device_locked_until) : null;
        if (lockedUntil && new Date() < lockedUntil) {
          const remaining = Math.ceil((lockedUntil - new Date()) / (1000*60*60*24));
          return respond(res, { success:false, message:`الحساب مقيّد بجهاز آخر — يمكن تغييره بعد ${remaining} يوم` });
        }
        const newLockedUntil = new Date(Date.now() + lockDays*24*60*60*1000).toISOString();
        await db.collection("users").updateOne({ username }, { $set: { device_locked_until: newLockedUntil } });
      }
    }
    await db.collection("tokens").deleteMany({ username });
    const token = crypto.randomBytes(32).toString("hex");
    await db.collection("tokens").insertOne({ token, username, device_id });
    return respond(res, { success:true, token, username:user.username, expire_date:user.expire_date, credits:user.credits, message:"تم تسجيل الدخول" });
  }

  // ══ التحقق من التوكن ══
  if (action === "verify") {
    const user = await getAuthUser(db, input.token, input.device_id);
    if (!user) return respond(res, { success:false, message:"توكن غير صالح" });
    return respond(res, { success:true, username:user.username, expire_date:user.expire_date, credits:user.credits });
  }

  // ══ خصم كريدت ══
  if (action === "deduct_credit") {
    const user = await getAuthUser(db, input.token, input.device_id);
    if (!user) return respond(res, { success:false, message:"غير مصرح" });
    const price = SERVICE_PRICES[input.service] || 1;
    if (user.credits < price) return respond(res, { success:false, message:"رصيدك غير كافٍ", credits:user.credits });
    await db.collection("users").updateOne({ username:user.username }, { $inc:{ credits:-price } });
    return respond(res, { success:true, credits:user.credits - price, deducted:price });
  }

  // ══ إنشاء مستخدم ══
  if (action === "create_user") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    const { username, password } = input;
    const days = parseInt(input.days) || 30;
    const credits = parseInt(input.credits) || 0;
    if (!username || !password) return respond(res, { success:false, message:"بيانات ناقصة" });
    if (await db.collection("users").findOne({ username })) return respond(res, { success:false, message:"المستخدم موجود مسبقاً" });
    const hash = bcrypt.hashSync(password, 8);
    const expire = new Date(Date.now() + days*24*60*60*1000).toISOString().split("T")[0];
    await db.collection("users").insertOne({ username, password:hash, expire_date:expire, credits });
    return respond(res, { success:true, message:`تم إنشاء ${username} - ${days} يوم - ${credits} كريدت` });
  }

  // ══ إضافة رصيد ══
  if (action === "add_credits") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    const amt = parseInt(input.amount);
    if (!amt || amt <= 0) return respond(res, { success:false, message:"مبلغ غير صحيح" });
    const user = await db.collection("users").findOne({ username:input.username });
    if (!user) return respond(res, { success:false, message:"المستخدم غير موجود" });
    await db.collection("users").updateOne({ username:input.username }, { $inc:{ credits:amt } });
    return respond(res, { success:true, message:`تم إضافة ${amt} كريدت`, credits:user.credits + amt });
  }

  // ══ خصم رصيد admin ══
  if (action === "deduct_credits_admin") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    const amt = parseInt(input.amount);
    const user = await db.collection("users").findOne({ username:input.username });
    if (!user) return respond(res, { success:false, message:"المستخدم غير موجود" });
    if (user.credits < amt) return respond(res, { success:false, message:`رصيد غير كافٍ (${user.credits})` });
    await db.collection("users").updateOne({ username:input.username }, { $inc:{ credits:-amt } });
    return respond(res, { success:true, message:`تم خصم ${amt}`, credits:user.credits - amt });
  }

  // ══ حذف مستخدم ══
  if (action === "delete_user") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    if (input.username === "admin") return respond(res, { success:false, message:"لا يمكن حذف admin" });
    if (!await db.collection("users").findOne({ username:input.username })) return respond(res, { success:false, message:"المستخدم غير موجود" });
    await db.collection("users").deleteOne({ username:input.username });
    await db.collection("tokens").deleteMany({ username:input.username });
    return respond(res, { success:true, message:"تم الحذف" });
  }

  // ══ عرض المستخدمين ══
  if (action === "list_users") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    const users = await db.collection("users").find({}, { projection:{ password:0 } }).toArray();
    return respond(res, { success:true, users: users.map(u => ({
      username:u.username, expire_date:u.expire_date, credits:u.credits, active: new Date(u.expire_date) > new Date()
    }))});
  }

  // ══ تسجيل الخروج ══
  if (action === "logout") {
    if (input.token) await db.collection("tokens").deleteOne({ token:input.token });
    return respond(res, { success:true, message:"تم تسجيل الخروج" });
  }



  return respond(res, { success:true, message:"IMEI Server is running", version:"3.0" });
};

  // ══ تحديث مدة قفل الجهاز (admin) ══
  if (action === "set_device_lock") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    const lockDays = parseInt(input.lock_days);
    if (!input.username || isNaN(lockDays) || lockDays < 0)
      return respond(res, { success:false, message:"بيانات ناقصة" });
    const target = await db.collection("users").findOne({ username: input.username });
    if (!target) return respond(res, { success:false, message:"المستخدم غير موجود" });
    await db.collection("users").updateOne(
      { username: input.username },
      { $set: { device_lock_days: lockDays, device_locked_until: null } }
    );
    return respond(res, { success:true, message:`تم تعيين مدة القفل ${lockDays} يوم للمستخدم ${input.username}` });
  }

  // ══ فك قفل الجهاز يدوياً (admin) ══
  if (action === "unlock_device") {
    if (!await isAdmin(db, input.admin_token)) return respond(res, { success:false, message:"غير مصرح" });
    if (!input.username) return respond(res, { success:false, message:"بيانات ناقصة" });
    await db.collection("users").updateOne(
      { username: input.username },
      { $set: { device_locked_until: null }, $unset: { device_lock_days: "" } }
    );
    await db.collection("tokens").deleteMany({ username: input.username });
    return respond(res, { success:true, message:`تم فك قفل الجهاز للمستخدم ${input.username}` });
  }

  return respond(res, { success:true, message:"IMEI Server is running", version:"3.0" });
};
