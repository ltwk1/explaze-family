const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('trust proxy', 1);
const PORT = Number(process.env.PORT || 3000);
const DATA_DIR = path.join(__dirname, 'data');
fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(path.join(DATA_DIR, 'explaze.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'member',
  balance INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  event_type TEXT NOT NULL,
  organization TEXT NOT NULL,
  details TEXT NOT NULL DEFAULT '',
  evidence TEXT NOT NULL DEFAULT '',
  reward INTEGER NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  admin_note TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  reviewed_at TEXT
);
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  amount INTEGER NOT NULL,
  kind TEXT NOT NULL,
  description TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS purchases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES users(id),
  item_id TEXT NOT NULL,
  item_name TEXT NOT NULL,
  price INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const EVENT_TYPES = {
  supply_success: { label: 'Успешная поставка', reward: 500 },
  supply_intercepted: { label: 'Перехваченная поставка', reward: 700 },
  tc_defended: { label: 'Отбитие ТЦ', reward: 600 },
  tc_captured: { label: 'Успешный захват ТЦ', reward: 800 },
  governor_kidnapped: { label: 'Успешное похищение губернатора', reward: 1000 },
  governor_rescued: { label: 'Отбитие губернатора', reward: 900 }
};
const CATALOG = [
  {id:'vest', name:'Бронежилет', category:'Экипировка', description:'Защитная экипировка для RP-ситуаций.', price:500, icon:'▰'},
  {id:'helmet', name:'Тактический шлем', category:'Экипировка', description:'Элемент игрового комплекта экипировки.', price:300, icon:'⬡'},
  {id:'backpack', name:'Тактический рюкзак', category:'Экипировка', description:'Дополнительный аксессуар персонажа.', price:250, icon:'▣'},
  {id:'weapon_basic', name:'Стандартное оружие', category:'Вооружение', description:'Игровой предмет для RP-сценариев.', price:1000, icon:'✦'},
  {id:'weapon_advanced', name:'Улучшенное оружие', category:'Вооружение', description:'Игровой предмет повышенного класса.', price:1500, icon:'✧'},
  {id:'weapon_special', name:'Специальное оружие', category:'Вооружение', description:'Редкий игровой предмет.', price:2500, icon:'✹'},
  {id:'medkit', name:'Аптечка', category:'Предметы', description:'Расходный игровой предмет.', price:150, icon:'✚'},
  {id:'radio', name:'Рация', category:'Предметы', description:'Средство связи персонажа.', price:200, icon:'⌁'},
  {id:'mask', name:'Маска', category:'Предметы', description:'Аксессуар для образа персонажа.', price:250, icon:'◉'},
  {id:'uniform', name:'Специальная форма', category:'Одежда', description:'Комплект одежды для RP.', price:500, icon:'◇'},
  {id:'exclusive_uniform', name:'Эксклюзивная форма', category:'Одежда', description:'Особый комплект одежды.', price:1000, icon:'◆'},
  {id:'accessory', name:'Эксклюзивный аксессуар', category:'Особые товары', description:'Редкий аксессуар персонажа.', price:2000, icon:'✺'},
  {id:'skin', name:'Уникальный скин', category:'Особые товары', description:'Уникальное оформление игрового предмета.', price:2500, icon:'✷'},
  {id:'title', name:'Особый титул', category:'Особые товары', description:'Отображаемый титул участника.', price:3000, icon:'♛'},
  {id:'bundle', name:'Эксклюзивный комплект', category:'Особые товары', description:'Набор эксклюзивных игровых предметов.', price:5000, icon:'✪'}
];

const adminName = process.env.ADMIN_USERNAME;
const adminPassword = process.env.ADMIN_PASSWORD;
if (adminName && adminPassword) {
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(adminName);
  if (!existing) {
    const hash = bcrypt.hashSync(adminPassword, 12);
    db.prepare('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)').run(adminName, hash, 'admin');
    console.log(`Admin account created: ${adminName}`);
  }
}

const extraAdmins = (process.env.ADMIN_USERNAMES || '').split(',').map(s => s.trim().toLowerCase()).filter(Boolean);
const isAdminName = name => {
  const n = String(name).toLowerCase();
  return extraAdmins.includes(n) || n === String(adminName || '').toLowerCase();
};

app.use(helmet({ contentSecurityPolicy: false }));
app.use(express.json({ limit: '30kb' }));
app.use(session({
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: DATA_DIR }),
  secret: process.env.SESSION_SECRET || 'development-only-change-this-session-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 1000*60*60*8 }
}));
app.use(express.static(path.join(__dirname, 'public')));
const authLimiter = rateLimit({windowMs: 15*60*1000, limit: 12, standardHeaders: true, legacyHeaders: false});
const requireAuth = (req,res,next) => req.session.user ? next() : res.status(401).json({error:'Необходимо войти в аккаунт.'});
const requireAdmin = (req,res,next) => req.session.user?.role === 'admin' ? next() : res.status(403).json({error:'Недостаточно прав.'});
const clean = (v,max=160) => String(v ?? '').trim().slice(0,max);

app.get('/api/me', (req,res) => {
  if (!req.session.user) return res.json({user:null});
  const user = db.prepare('SELECT id,username,role,balance,created_at FROM users WHERE id=?').get(req.session.user.id);
  res.json({user});
});
app.post('/api/register', authLimiter, (req,res) => {
  const username = clean(req.body.username,24);
  const password = String(req.body.password || '');
  if (!/^[a-zA-Z0-9_]{3,24}$/.test(username)) return res.status(400).json({error:'Ник: 3–24 символа, только латиница, цифры и _.'});
  if (password.length < 10 || password.length > 72) return res.status(400).json({error:'Пароль должен содержать от 10 до 72 символов.'});
  try {
    const hash = bcrypt.hashSync(password,12);
    const role = isAdminName(username) ? 'admin' : 'member';
    const info = db.prepare('INSERT INTO users (username,password_hash,role) VALUES (?,?,?)').run(username,hash,role);
    req.session.user = {id:Number(info.lastInsertRowid),role};
    res.json({ok:true});
  } catch { res.status(409).json({error:'Такой никнейм уже занят.'}); }
});
app.post('/api/login', authLimiter, (req,res) => {
  const username = clean(req.body.username,24);
  const row = db.prepare('SELECT * FROM users WHERE username=?').get(username);
  if (!row || !bcrypt.compareSync(String(req.body.password || ''),row.password_hash)) return res.status(401).json({error:'Неверный никнейм или пароль.'});
  if (isAdminName(row.username) && row.role !== 'admin') {
    db.prepare('UPDATE users SET role=? WHERE id=?').run('admin', row.id);
    row.role = 'admin';
  }
  req.session.regenerate(err => {
    if (err) return res.status(500).json({error:'Не удалось создать сессию.'});
    req.session.user = {id:row.id,role:row.role};
    res.json({ok:true});
  });
});
app.post('/api/logout', (req,res) => req.session.destroy(()=>res.json({ok:true})));
app.get('/api/catalog', (req,res) => res.json({items:CATALOG}));
app.get('/api/dashboard', requireAuth, (req,res) => {
  const userId=req.session.user.id;
  const user=db.prepare('SELECT id,username,role,balance,created_at FROM users WHERE id=?').get(userId);
  const events=db.prepare('SELECT id,event_type,organization,reward,status,admin_note,created_at FROM events WHERE user_id=? ORDER BY id DESC LIMIT 8').all(userId);
  const purchases=db.prepare('SELECT id,item_name,price,created_at FROM purchases WHERE user_id=? ORDER BY id DESC LIMIT 8').all(userId);
  const transactions=db.prepare('SELECT id,amount,kind,description,created_at FROM transactions WHERE user_id=? ORDER BY id DESC LIMIT 12').all(userId);
  res.json({user,events,purchases,transactions});
});
app.post('/api/events', requireAuth, (req,res) => {
  const type=clean(req.body.eventType,50), organization=clean(req.body.organization,80);
  const details=clean(req.body.details,500), evidence=clean(req.body.evidence,400);
  if (!EVENT_TYPES[type]) return res.status(400).json({error:'Выберите мероприятие из списка.'});
  if (organization.length<2) return res.status(400).json({error:'Укажите организацию.'});
  if (evidence && !/^https?:\/\/\S+$/i.test(evidence)) return res.status(400).json({error:'Ссылка на доказательства должна начинаться с http:// или https://.'});
  const event=EVENT_TYPES[type];
  db.prepare('INSERT INTO events (user_id,event_type,organization,details,evidence,reward) VALUES (?,?,?,?,?,?)')
    .run(req.session.user.id,type,organization,details,evidence,event.reward);
  res.json({ok:true,message:'Заявка отправлена на проверку.'});
});
app.post('/api/purchase', requireAuth, (req,res) => {
  const item=CATALOG.find(x=>x.id===clean(req.body.itemId,50));
  if (!item) return res.status(404).json({error:'Товар не найден.'});
  const buy=db.transaction(()=>{
    const user=db.prepare('SELECT balance FROM users WHERE id=?').get(req.session.user.id);
    if (user.balance<item.price) throw new Error('Недостаточно материалов для покупки.');
    db.prepare('UPDATE users SET balance=balance-? WHERE id=?').run(item.price,req.session.user.id);
    db.prepare('INSERT INTO purchases (user_id,item_id,item_name,price) VALUES (?,?,?,?)').run(req.session.user.id,item.id,item.name,item.price);
    db.prepare('INSERT INTO transactions (user_id,amount,kind,description) VALUES (?,?,?,?)').run(req.session.user.id,-item.price,'purchase',`Покупка: ${item.name}`);
  });
  try { buy(); res.json({ok:true,message:`Покупка «${item.name}» оформлена.`}); }
  catch(e) { res.status(400).json({error:e.message}); }
});
app.get('/api/admin/overview', requireAuth, requireAdmin, (req,res) => {
  const users=db.prepare('SELECT id,username,role,balance,created_at FROM users ORDER BY id DESC').all();
  const events=db.prepare(`SELECT e.*,u.username FROM events e JOIN users u ON u.id=e.user_id ORDER BY CASE e.status WHEN 'pending' THEN 0 ELSE 1 END,e.id DESC LIMIT 100`).all();
  const totals=db.prepare(`SELECT COUNT(*) AS users,(SELECT COUNT(*) FROM events WHERE status='pending') AS pending,(SELECT COALESCE(SUM(balance),0) FROM users) AS materials FROM users`).get();
  res.json({users,events,totals});
});
app.post('/api/admin/events/:id/review', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id), action=clean(req.body.action,20), note=clean(req.body.note,300);
  if (!Number.isInteger(id) || !['approve','reject'].includes(action)) return res.status(400).json({error:'Некорректный запрос.'});
  const event=db.prepare('SELECT * FROM events WHERE id=?').get(id);
  if (!event || event.status!=='pending') return res.status(404).json({error:'Заявка не найдена или уже рассмотрена.'});
  const review=db.transaction(()=>{
    if (action==='approve') {
      db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(event.reward,event.user_id);
      db.prepare('INSERT INTO transactions (user_id,amount,kind,description) VALUES (?,?,?,?)').run(event.user_id,event.reward,'event',`Награда: ${EVENT_TYPES[event.event_type].label}`);
    }
    db.prepare('UPDATE events SET status=?,admin_note=?,reviewed_at=CURRENT_TIMESTAMP WHERE id=?').run(action==='approve'?'approved':'rejected',note,id);
  });
  review(); res.json({ok:true});
});
app.post('/api/admin/users/:id/balance', requireAuth, requireAdmin, (req,res) => {
  const id=Number(req.params.id), amount=Number(req.body.amount), note=clean(req.body.note,160);
  if (!Number.isInteger(id) || !Number.isInteger(amount) || amount===0 || Math.abs(amount)>1000000 || note.length<2) return res.status(400).json({error:'Укажите корректную сумму и причину.'});
  const user=db.prepare('SELECT id FROM users WHERE id=?').get(id);
  if (!user) return res.status(404).json({error:'Пользователь не найден.'});
  const update=db.transaction(()=>{
    const balance=db.prepare('SELECT balance FROM users WHERE id=?').get(id).balance;
    if (balance+amount<0) throw new Error('Нельзя списать больше, чем есть на балансе.');
    db.prepare('UPDATE users SET balance=balance+? WHERE id=?').run(amount,id);
    db.prepare('INSERT INTO transactions (user_id,amount,kind,description) VALUES (?,?,?,?)').run(id,amount,'admin',note);
  });
  try {update();res.json({ok:true});}catch(e){res.status(400).json({error:e.message});}
});
app.get('/api/admin/catalog', requireAuth, requireAdmin, (req,res)=>res.json({items:CATALOG}));
app.use('/api', (req,res)=>res.status(404).json({error:'API-маршрут не найден.'}));
app.listen(PORT,()=>console.log(`Explaze Family запущен: http://localhost:${PORT}`));
