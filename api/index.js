const http = require('http');
const url = require('url');
const crypto = require('crypto');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const initSqlJs = require('sql.js');

const PORT = process.env.PORT || 3000;
const DB_PATH = '/tmp/imei_server.bin';

const SERVICE_PRICES = { check_fard: 1, check_kg: 2, check_imei: 1 };

let db;

async function initDB() {
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    db = new SQL.Database(fs.readFileSync(DB_PATH));
  } else {
    db = new SQL.Database();
  }
  db.run(`
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
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS transactions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      amount INTEGER NOT NULL,
      type TEXT NOT NULL,
      description TEXT,
      created_at TEXT DEFAULT CURRENT_TIMESTAMP
    );
  `);
  const adminRes = db.exec("SELECT id FROM users WHERE username='admin'");
  if (!adminRes.length || !adminRes[0].values.length) {
    const hash = bcrypt.hashSync('admin123', 10);
    const expire = new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0];
    db.run("INSERT INTO users (username,password,expire_date,credits) VALUES (?,?,?,?)", ['admin',hash,expire,100]);
    saveDB();
  }
}

function saveDB() {
  try { fs.writeFileSync(DB_PATH, Buffer.from(db.export())); } catch(e) {}
}

function escape(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return v;
  return `'${String(v).replace(/'/g,"''")}'`;
}

function buildSQL(sql, params) {
  let i = 0;
  return sql.replace(/\?/g, () => escape(params[i++]));
}

function dbGet(sql, params=[]) {
  const res = db.exec(buildSQL(sql, params));
  if (!res.length || !res[0].values.length) return null;
  const obj = {};
  res[0].columns.forEach((c,i) => obj[c] = res[0].values[0][i]);
  return obj;
}

function dbAll(sql, params=[]) {
  const res = db.exec(buildSQL(sql, params));
  if (!res.length) return [];
  return res[0].values.map(vals => {
    const obj = {};
    res[0].columns.forEach((c,i) => obj[c] = vals[i]);
    return obj;
  });
}

function dbRun(sql, params=[]) {
  db.run(buildSQL(sql, params));
  saveDB();
}

function getAuthUser(token, device_id) {
  if (!token || !device_id) return null;
  const row = dbGet(
    "SELECT t.*,u.id as uid,u.username,u.expire_date,u.credits FROM tokens t JOIN users u ON t.user_id=u.id WHERE t.token=? AND t.device_id=?",
    [token, device_id]
  );
  if (!row || new Date(row.expire_date) < new Date()) return null;
  return row;
}

function send(res, data) {
  res.writeHead(200, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
  });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise(resolve => {
    let body = '';
    req.on('data', c => body += c);
    req.on('end', () => { try { resolve(JSON.parse(body)); } catch { resolve({}); } });
  });
}

async function startServer() {
  await initDB();
  http.createServer(async (req, res) => {
    if (req.method === 'OPTIONS') { send(res, {}); return; }
    const parsed = url.parse(req.url, true);
    const action = parsed.query.action || '';
    const input  = req.method === 'POST' ? await readBody(req) : parsed.query;

    if (action === 'login') {
      const { username, password, device_id } = input;
      if (!username || !password || !device_id) return send(res, {success:false, message:'بيانات ناقصة'});
      const user = dbGet("SELECT * FROM users WHERE username=?", [username]);
      if (!user || !bcrypt.compareSync(password, user.password)) return send(res, {success:false, message:'اسم المستخدم أو كلمة المرور خاطئة'});
      if (new Date(user.expire_date) < new Date()) return send(res, {success:false, message:'انتهت صلاحية الحساب'});
      const existing = dbGet("SELECT device_id FROM tokens WHERE user_id=? ORDER BY id DESC LIMIT 1", [user.id]);
      if (existing && existing.device_id !== device_id) return send(res, {success:false, message:'هذا الحساب مسجّل على جهاز آخر'});
      dbRun("DELETE FROM tokens WHERE user_id=?", [user.id]);
      const token = crypto.randomBytes(32).toString('hex');
      dbRun("INSERT INTO tokens (user_id,token,device_id) VALUES (?,?,?)", [user.id, token, device_id]);
      return send(res, {success:true, token, username:user.username, expire_date:user.expire_date, credits:user.credits, message:'تم تسجيل الدخول بنجاح'});
    }

    if (action === 'verify') {
      const user = getAuthUser(input.token, input.device_id);
      if (!user) return send(res, {success:false, message:'توكن غير صالح أو جهاز مختلف'});
      return send(res, {success:true, username:user.username, expire_date:user.expire_date, credits:user.credits, message:'التوكن صالح'});
    }

    if (action === 'get_balance') {
      const user = getAuthUser(input.token, input.device_id);
      if (!user) return send(res, {success:false, message:'غير مصرح'});
      return send(res, {success:true, credits:user.credits, username:user.username});
    }

    if (action === 'deduct_credit') {
      const user = getAuthUser(input.token, input.device_id);
      const service = input.service || '';
      if (!user) return send(res, {success:false, message:'غير مصرح'});
      if (!SERVICE_PRICES[service]) return send(res, {success:false, message:'خدمة غير معروفة'});
      const price = SERVICE_PRICES[service];
      if (user.credits < price) return send(res, {success:false, message:'رصيدك غير كافٍ', credits:user.credits, required:price});
      dbRun("UPDATE users SET credits=credits-? WHERE id=?", [price, user.uid]);
      dbRun("INSERT INTO transactions (user_id,amount,type,description) VALUES (?,?,'deduct',?)", [user.uid, -price, service]);
      return send(res, {success:true, credits:user.credits-price, deducted:price, message:`تم خصم ${price} كريدت`});
    }

    if (action === 'add_credits') {
      const { admin_token, username, amount } = input;
      const tokenRow = dbGet("SELECT u.username FROM tokens t JOIN users u ON t.user_id=u.id WHERE t.token=?", [admin_token]);
      if (!tokenRow || tokenRow.username !== 'admin') return send(res, {success:false, message:'غير مصرح'});
      const target = dbGet("SELECT id,credits FROM users WHERE username=?", [username]);
      if (!target) return send(res, {success:false, message:'المستخدم غير موجود'});
      const amt = parseInt(amount);
      if (!amt || amt <= 0) return send(res, {success:false, message:'مبلغ غير صحيح'});
      dbRun("UPDATE users SET credits=credits+? WHERE username=?", [amt, username]);
      dbRun("INSERT INTO transactions (user_id,amount,type,description) VALUES (?,?,'add','admin_add')", [target.id, amt]);
      return send(res, {success:true, message:`تم إضافة ${amt} كريدت لـ ${username}`, credits:target.credits+amt});
    }

    if (action === 'create_user') {
      const { admin_token, username, password } = input;
      const days = parseInt(input.days)||30;
      const credits = parseInt(input.credits)||0;
      const tokenRow = dbGet("SELECT u.username FROM tokens t JOIN users u ON t.user_id=u.id WHERE t.token=?", [admin_token]);
      if (!tokenRow || tokenRow.username !== 'admin') return send(res, {success:false, message:'غير مصرح'});
      if (!username || !password) return send(res, {success:false, message:'بيانات ناقصة'});
      if (dbGet("SELECT id FROM users WHERE username=?", [username])) return send(res, {success:false, message:'اسم المستخدم موجود مسبقاً'});
      const hash = bcrypt.hashSync(password, 10);
      const expire = new Date(Date.now()+days*24*60*60*1000).toISOString().split('T')[0];
      dbRun("INSERT INTO users (username,password,expire_date,credits) VALUES (?,?,?,?)", [username,hash,expire,credits]);
      return send(res, {success:true, message:`تم إنشاء ${username} بصلاحية ${days} يوم ورصيد ${credits} كريدت`});
    }

    if (action === 'logout') {
      dbRun("DELETE FROM tokens WHERE token=?", [input.token||'']);
      return send(res, {success:true, message:'تم تسجيل الخروج'});
    }

    if (action === 'transactions') {
      const user = getAuthUser(input.token, input.device_id);
      if (!user) return send(res, {success:false, message:'غير مصرح'});
      const rows = dbAll("SELECT * FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 20", [user.uid]);
      return send(res, {success:true, transactions:rows, credits:user.credits});
    }

    return send(res, {success:true, message:'IMEI Server is running', version:'2.0'});

  }).listen(PORT, () => console.log(`Server on port ${PORT}`));
}

startServer();
