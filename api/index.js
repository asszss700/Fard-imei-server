const crypto = require('crypto');
const bcrypt = require('bcryptjs');

// قاعدة بيانات في الذاكرة (مؤقتة لكل instance)
// سنستخدم Vercel KV لاحقاً — الآن نبدأ بالتجربة
let memDB = {
  users: [
    {
      id: 1,
      username: 'admin',
      password: bcrypt.hashSync('admin123', 10),
      expire_date: new Date(Date.now() + 30*24*60*60*1000).toISOString().split('T')[0],
      credits: 100
    }
  ],
  tokens: [],
  transactions: [],
  nextUserId: 2,
  nextTokenId: 1,
  nextTxId: 1,
};

const SERVICE_PRICES = { check_fard: 1, check_kg: 2, check_imei: 1 };

function findUser(username) {
  return memDB.users.find(u => u.username === username) || null;
}
function findUserById(id) {
  return memDB.users.find(u => u.id === id) || null;
}
function findToken(token, device_id) {
  return memDB.tokens.find(t => t.token === token && t.device_id === device_id) || null;
}
function getAuthUser(token, device_id) {
  if (!token || !device_id) return null;
  const t = findToken(token, device_id);
  if (!t) return null;
  const u = findUserById(t.user_id);
  if (!u) return null;
  if (new Date(u.expire_date) < new Date()) return null;
  return { ...u, uid: u.id };
}

module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') { res.status(200).end('{}'); return; }

  const action = (req.query && req.query.action) || '';
  const input  = req.method === 'POST' ? req.body : req.query;

  const send = (data) => res.status(200).json(data);

  // ═══ تسجيل الدخول ═══
  if (action === 'login') {
    const { username, password, device_id } = input || {};
    if (!username || !password || !device_id) return send({success:false, message:'بيانات ناقصة'});
    const user = findUser(username);
    if (!user || !bcrypt.compareSync(password, user.password)) return send({success:false, message:'اسم المستخدم أو كلمة المرور خاطئة'});
    if (new Date(user.expire_date) < new Date()) return send({success:false, message:'انتهت صلاحية الحساب'});
    const existingTok = memDB.tokens.find(t => t.user_id === user.id);
    if (existingTok && existingTok.device_id !== device_id) return send({success:false, message:'هذا الحساب مسجّل على جهاز آخر'});
    memDB.tokens = memDB.tokens.filter(t => t.user_id !== user.id);
    const token = crypto.randomBytes(32).toString('hex');
    memDB.tokens.push({ id: memDB.nextTokenId++, user_id: user.id, token, device_id });
    return send({success:true, token, username:user.username, expire_date:user.expire_date, credits:user.credits, message:'تم تسجيل الدخول بنجاح'});
  }

  // ═══ التحقق من التوكن ═══
  if (action === 'verify') {
    const user = getAuthUser(input?.token, input?.device_id);
    if (!user) return send({success:false, message:'توكن غير صالح أو جهاز مختلف'});
    return send({success:true, username:user.username, expire_date:user.expire_date, credits:user.credits, message:'التوكن صالح'});
  }

  // ═══ جلب الرصيد ═══
  if (action === 'get_balance') {
    const user = getAuthUser(input?.token, input?.device_id);
    if (!user) return send({success:false, message:'غير مصرح'});
    return send({success:true, credits:user.credits, username:user.username});
  }

  // ═══ خصم الكريدت ═══
  if (action === 'deduct_credit') {
    const user = getAuthUser(input?.token, input?.device_id);
    const service = input?.service || '';
    if (!user) return send({success:false, message:'غير مصرح'});
    if (!SERVICE_PRICES[service]) return send({success:false, message:'خدمة غير معروفة'});
    const price = SERVICE_PRICES[service];
    if (user.credits < price) return send({success:false, message:'رصيدك غير كافٍ', credits:user.credits, required:price});
    const u = findUserById(user.id);
    u.credits -= price;
    memDB.transactions.push({id:memDB.nextTxId++, user_id:user.id, amount:-price, type:'deduct', description:service});
    return send({success:true, credits:u.credits, deducted:price, message:`تم خصم ${price} كريدت`});
  }

  // ═══ إضافة رصيد (admin) ═══
  if (action === 'add_credits') {
    const { admin_token, username, amount } = input || {};
    const tok = memDB.tokens.find(t => t.token === admin_token);
    if (!tok) return send({success:false, message:'غير مصرح'});
    const adminUser = findUserById(tok.user_id);
    if (!adminUser || adminUser.username !== 'admin') return send({success:false, message:'غير مصرح'});
    const target = findUser(username);
    if (!target) return send({success:false, message:'المستخدم غير موجود'});
    const amt = parseInt(amount);
    if (!amt || amt <= 0) return send({success:false, message:'مبلغ غير صحيح'});
    target.credits += amt;
    memDB.transactions.push({id:memDB.nextTxId++, user_id:target.id, amount:amt, type:'add', description:'admin_add'});
    return send({success:true, message:`تم إضافة ${amt} كريدت لـ ${username}`, credits:target.credits});
  }

  // ═══ إنشاء مستخدم (admin) ═══
  if (action === 'create_user') {
    const { admin_token, username, password } = input || {};
    const days = parseInt(input?.days) || 30;
    const credits = parseInt(input?.credits) || 0;
    const tok = memDB.tokens.find(t => t.token === admin_token);
    if (!tok) return send({success:false, message:'غير مصرح'});
    const adminUser = findUserById(tok.user_id);
    if (!adminUser || adminUser.username !== 'admin') return send({success:false, message:'غير مصرح'});
    if (!username || !password) return send({success:false, message:'بيانات ناقصة'});
    if (findUser(username)) return send({success:false, message:'اسم المستخدم موجود مسبقاً'});
    const hash = bcrypt.hashSync(password, 10);
    const expire = new Date(Date.now()+days*24*60*60*1000).toISOString().split('T')[0];
    memDB.users.push({id:memDB.nextUserId++, username, password:hash, expire_date:expire, credits});
    return send({success:true, message:`تم إنشاء ${username} بصلاحية ${days} يوم ورصيد ${credits} كريدت`});
  }

  // ═══ تسجيل الخروج ═══
  if (action === 'logout') {
    memDB.tokens = memDB.tokens.filter(t => t.token !== (input?.token || ''));
    return send({success:true, message:'تم تسجيل الخروج'});
  }

  // ═══ سجل المعاملات ═══
  if (action === 'transactions') {
    const user = getAuthUser(input?.token, input?.device_id);
    if (!user) return send({success:false, message:'غير مصرح'});
    const rows = memDB.transactions.filter(t => t.user_id === user.id).slice(-20).reverse();
    return send({success:true, transactions:rows, credits:user.credits});
  }

  return send({success:true, message:'IMEI Server is running', version:'2.0'});
};
