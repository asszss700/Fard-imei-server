const http = require('http');
const url = require('url');
const crypto = require('crypto');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');

const db = new Database('/tmp/imei_server.db');
const PORT = process.env.PORT || 3000;

// ═══════════════════════════════
// إنشاء الجداول
// ═══════════════════════════════
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    expire_date TEXT NOT NULL,
    credits INTEGER DEFAULT 0,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP
  );
  CREATE TABLE IF NOT EXISTS tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    token TEXT UNIQUE NOT NULL,
    device_id TEXT NOT NULL,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    amount INTEGER NOT NULL,
    type TEXT NOT NULL,
    description TEXT,
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(user_id) REFERENCES users(id)
  );
`);

// إنشاء admin افتراضي
const adminExists = db.prepare("SELECT id FROM users WHERE username='admin'").get();
if (!adminExists) {
  const hash = bcrypt.hashSync('admin123', 10);
  const expire = new Date(Date.now() + 30 * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
  db.prepare("INSERT INTO users (username, password, expire_date, credits) VALUES (?, ?, ?, ?)").run('admin', hash, expire, 100);
}

// أسعار الخدمات
const SERVICE_PRICES = {
  check_fard: 1,
  check_kg:   2,
  check_imei: 1,
};

// ═══════════════════════════════
// دوال مساعدة
// ═══════════════════════════════
function getAuthUser(token, device_id) {
  if (!token || !device_id) return null;
  const row = db.prepare(`
    SELECT t.*, u.id as uid, u.username, u.expire_date, u.credits
    FROM tokens t JOIN users u ON t.user_id = u.id
    WHERE t.token = ? AND t.device_id = ?
  `).get(token, device_id);
  if (!row) return null;
  if (new Date(row.expire_date) < new Date()) return null;
  return row;
}

function send(res, data, status = 200) {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try { resolve(JSON.parse(body)); }
      catch { resolve({}); }
    });
  });
}

// ═══════════════════════════════
// السيرفر
// ═══════════════════════════════
const server = http.createServer(async (req, res) => {

  // CORS preflight
  if (req.method === 'OPTIONS') {
    send(res, {});
    return;
  }

  const parsed = url.parse(req.url, true);
  const action = parsed.query.action || '';
  const input  = req.method === 'POST' ? await readBody(req) : parsed.query;

  // ═══ تسجيل الدخول ═══
  if (action === 'login') {
    const { username, password, device_id } = input;
    if (!username || !password || !device_id)
      return send(res, { success: false, message: 'بيانات ناقصة' });

    const user = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
    if (!user || !bcrypt.compareSync(password, user.password))
      return send(res, { success: false, message: 'اسم المستخدم أو كلمة المرور خاطئة' });

    if (new Date(user.expire_date) < new Date())
      return send(res, { success: false, message: 'انتهت صلاحية الحساب' });

    // التحقق من الجهاز
    const existing = db.prepare("SELECT device_id FROM tokens WHERE user_id = ? ORDER BY id DESC LIMIT 1").get(user.id);
    if (existing && existing.device_id !== device_id)
      return send(res, { success: false, message: 'هذا الحساب مسجّل على جهاز آخر' });

    // إنشاء توكن جديد
    db.prepare("DELETE FROM tokens WHERE user_id = ?").run(user.id);
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare("INSERT INTO tokens (user_id, token, device_id) VALUES (?, ?, ?)").run(user.id, token, device_id);

    return send(res, {
      success: true, token,
      username: user.username,
      expire_date: user.expire_date,
      credits: user.credits,
      message: 'تم تسجيل الدخول بنجاح'
    });
  }

  // ═══ التحقق من التوكن ═══
  if (action === 'verify') {
    const { token, device_id } = input;
    const user = getAuthUser(token, device_id);
    if (!user) return send(res, { success: false, message: 'توكن غير صالح أو جهاز مختلف' });
    return send(res, {
      success: true,
      username: user.username,
      expire_date: user.expire_date,
      credits: user.credits,
      message: 'التوكن صالح'
    });
  }

  // ═══ جلب الرصيد ═══
  if (action === 'get_balance') {
    const user = getAuthUser(input.token, input.device_id);
    if (!user) return send(res, { success: false, message: 'غير مصرح' });
    return send(res, { success: true, credits: user.credits, username: user.username });
  }

  // ═══ خصم الكريدت ═══
  if (action === 'deduct_credit') {
    const user    = getAuthUser(input.token, input.device_id);
    const service = input.service || '';
    if (!user) return send(res, { success: false, message: 'غير مصرح' });
    if (!SERVICE_PRICES[service]) return send(res, { success: false, message: 'خدمة غير معروفة' });

    const price = SERVICE_PRICES[service];
    if (user.credits < price)
      return send(res, { success: false, message: 'رصيدك غير كافٍ', credits: user.credits, required: price });

    db.prepare("UPDATE users SET credits = credits - ? WHERE id = ?").run(price, user.uid);
    db.prepare("INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, 'deduct', ?)").run(user.uid, -price, service);

    return send(res, {
      success: true,
      credits: user.credits - price,
      deducted: price,
      message: `تم خصم ${price} كريدت`
    });
  }

  // ═══ إضافة رصيد (admin) ═══
  if (action === 'add_credits') {
    const { admin_token, username, amount } = input;
    const tokenRow = db.prepare(`
      SELECT u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?
    `).get(admin_token);
    if (!tokenRow || tokenRow.username !== 'admin')
      return send(res, { success: false, message: 'غير مصرح' });

    const target = db.prepare("SELECT id, credits FROM users WHERE username = ?").get(username);
    if (!target) return send(res, { success: false, message: 'المستخدم غير موجود' });
    if (!amount || amount <= 0) return send(res, { success: false, message: 'مبلغ غير صحيح' });

    db.prepare("UPDATE users SET credits = credits + ? WHERE username = ?").run(amount, username);
    db.prepare("INSERT INTO transactions (user_id, amount, type, description) VALUES (?, ?, 'add', 'admin_add')").run(target.id, amount);

    return send(res, {
      success: true,
      message: `تم إضافة ${amount} كريدت لـ ${username}`,
      credits: target.credits + amount
    });
  }

  // ═══ سجل المعاملات ═══
  if (action === 'transactions') {
    const user = getAuthUser(input.token, input.device_id);
    if (!user) return send(res, { success: false, message: 'غير مصرح' });
    const rows = db.prepare("SELECT * FROM transactions WHERE user_id = ? ORDER BY id DESC LIMIT 20").all(user.uid);
    return send(res, { success: true, transactions: rows, credits: user.credits });
  }

  // ═══ إنشاء مستخدم (admin) ═══
  if (action === 'create_user') {
    const { admin_token, username, password, days = 30, credits = 0 } = input;
    const tokenRow = db.prepare(`
      SELECT u.username FROM tokens t JOIN users u ON t.user_id = u.id WHERE t.token = ?
    `).get(admin_token);
    if (!tokenRow || tokenRow.username !== 'admin')
      return send(res, { success: false, message: 'غير مصرح' });
    if (!username || !password) return send(res, { success: false, message: 'بيانات ناقصة' });

    try {
      const hash   = bcrypt.hashSync(password, 10);
      const expire = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString().split('T')[0];
      db.prepare("INSERT INTO users (username, password, expire_date, credits) VALUES (?, ?, ?, ?)").run(username, hash, expire, credits);
      return send(res, { success: true, message: `تم إنشاء ${username} بصلاحية ${days} يوم ورصيد ${credits} كريدت` });
    } catch {
      return send(res, { success: false, message: 'اسم المستخدم موجود مسبقاً' });
    }
  }

  // ═══ تسجيل الخروج ═══
  if (action === 'logout') {
    db.prepare("DELETE FROM tokens WHERE token = ?").run(input.token || '');
    return send(res, { success: true, message: 'تم تسجيل الخروج' });
  }

  // الصفحة الرئيسية
  return send(res, { success: true, message: 'IMEI Server is running', version: '2.0' });
});

server.listen(PORT, () => console.log(`Server running on port ${PORT}`));
