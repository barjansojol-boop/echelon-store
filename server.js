require('dotenv').config();
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { z } = require('zod');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const production = process.env.NODE_ENV === 'production';
const dataDir = path.join(__dirname, 'data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new Database(path.join(dataDir, 'echelon.sqlite'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
 password_hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'customer' CHECK(role IN ('owner','customer')),
 pin_hash TEXT, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS wallets (
 user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
 balance INTEGER NOT NULL DEFAULT 0 CHECK(balance >= 0), updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS cards (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
 brand TEXT NOT NULL CHECK(brand IN ('Echelon','Atlas')),
 tier TEXT NOT NULL CHECK(tier IN ('Normal','Premium','Gold Premium')),
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, UNIQUE(user_id, brand)
);
CREATE TABLE IF NOT EXISTS products (
 id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT NOT NULL DEFAULT '',
 price INTEGER NOT NULL CHECK(price >= 0), category TEXT NOT NULL DEFAULT 'Digital',
 image_url TEXT NOT NULL DEFAULT '', external_url TEXT NOT NULL DEFAULT '', active INTEGER NOT NULL DEFAULT 1,
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS orders (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
 total INTEGER NOT NULL CHECK(total >= 0), status TEXT NOT NULL DEFAULT 'paid',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS order_items (
 id INTEGER PRIMARY KEY AUTOINCREMENT, order_id INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
 product_id INTEGER REFERENCES products(id) ON DELETE SET NULL, product_name TEXT NOT NULL,
 unit_price INTEGER NOT NULL, quantity INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS ledger (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
 delta INTEGER NOT NULL, balance_after INTEGER NOT NULL, reason TEXT NOT NULL,
 actor_id INTEGER REFERENCES users(id), created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS requests (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL REFERENCES users(id),
 subject TEXT NOT NULL, details TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
 created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
`);

const countOwner = db.prepare("SELECT COUNT(*) n FROM users WHERE role='owner'").get().n;
if (!countOwner && process.env.OWNER_EMAIL && process.env.OWNER_PASSWORD && process.env.OWNER_SETUP_KEY && !process.env.OWNER_SETUP_KEY.startsWith('replace-')) {
  const hash = bcrypt.hashSync(process.env.OWNER_PASSWORD, 12);
  const result = db.prepare("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,'owner')")
    .run(process.env.OWNER_NAME || 'Store Owner', process.env.OWNER_EMAIL.toLowerCase(), hash);
  db.prepare('INSERT INTO wallets(user_id,balance) VALUES(?,0)').run(result.lastInsertRowid);
  console.log('Initial owner account created from environment configuration.');
} else if (!countOwner) {
  console.warn('OWNER account not initialized. Configure OWNER_EMAIL, OWNER_PASSWORD, OWNER_SETUP_KEY in .env before first launch.');
}

const initialProducts = [
 ['MovieBox','Digital service link. Verify legality, availability and safety before use.',10,'Digital','','https://movie-box.co/'],
 ['Minecraft download','External download link. Check source authenticity and device safety before use.',50,'Games','','https://minecraft-12631.apktodo.io/'],
 ['TikTok followers service','Third-party service; results are not guaranteed. Never share passwords or verification codes.',20,'Social','','https://superviral.io/free-tiktok-followers/'],
 ['Instagram followers','Add a verified provider URL in owner settings before activating this product.',20,'Social','',''],
 ['Discord request center','Free request center for stickers, photos, banners, gaming graphics and other digital designs.',0,'Requests','','https://discord.gg/a4ygcmsRV']
];
if (db.prepare('SELECT COUNT(*) n FROM products').get().n === 0) {
 const ins = db.prepare('INSERT INTO products(name,description,price,category,image_url,external_url) VALUES(?,?,?,?,?,?)');
 for (const p of initialProducts) ins.run(...p);
}

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: { directives: {
 defaultSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], scriptSrc: ["'self'"], imgSrc: ["'self'", 'https:', 'data:'],
 connectSrc: ["'self'"], objectSrc: ["'none'"], upgradeInsecureRequests: production ? [] : null
}}}));
if (production) app.set('trust proxy', 1);
app.use(express.urlencoded({ extended: false, limit: '30kb' }));
app.use(express.json({ limit: '30kb' }));
app.use(session({
 name: 'echelon.sid', secret: process.env.SESSION_SECRET || 'development-only-change-this-secret',
 resave: false, saveUninitialized: false, store: new SQLiteStore({ db: 'sessions.sqlite', dir: dataDir }),
 cookie: { httpOnly: true, sameSite: 'lax', secure: production, maxAge: 1000*60*60*8 }
}));
app.use(express.static(path.join(__dirname, 'public')));
const authLimiter = rateLimit({ windowMs: 15*60*1000, limit: 12, standardHeaders: true, legacyHeaders: false, message: 'Too many attempts. Try again later.' });
const safeText = (v, max=200) => String(v || '').trim().slice(0,max);
const currentUser = req => req.session.userId ? db.prepare('SELECT id,name,email,role,disabled,created_at FROM users WHERE id=?').get(req.session.userId) : null;
function requireAuth(req,res,next){ const u=currentUser(req); if(!u || u.disabled){ req.session.destroy(()=>{}); return res.status(401).json({error:'Please sign in first.'}); } req.user=u; next(); }
function requireOwner(req,res,next){ if(req.user.role!=='owner') return res.status(403).json({error:'Owner permission required.'}); next(); }
function csrf(req,res,next){ if(['POST','PUT','PATCH','DELETE'].includes(req.method)) { const token=req.get('x-csrf-token') || req.body.csrf; if(!req.session.csrf || token!==req.session.csrf) return res.status(403).json({error:'Security token expired. Refresh and try again.'}); } next(); }
app.use((req,res,next)=>{ if(!req.session.csrf) req.session.csrf=require('crypto').randomBytes(24).toString('hex'); res.setHeader('X-Content-Type-Options','nosniff'); next(); });
app.get('/api/bootstrap',(req,res)=>{const u=currentUser(req);res.json({csrf:req.session.csrf,user:u?{id:u.id,name:u.name,email:u.email,role:u.role}:null});});
app.get('/api/products',(req,res)=>res.json(db.prepare('SELECT id,name,description,price,category,image_url,external_url FROM products WHERE active=1 ORDER BY id DESC').all()));
app.get('/api/me',requireAuth,(req,res)=>{
 const wallet=db.prepare('SELECT balance FROM wallets WHERE user_id=?').get(req.user.id);
 const cards=db.prepare('SELECT id,brand,tier,created_at FROM cards WHERE user_id=? ORDER BY id').all(req.user.id);
 const orders=db.prepare('SELECT id,total,status,created_at FROM orders WHERE user_id=? ORDER BY id DESC LIMIT 20').all(req.user.id);
 const ledger=db.prepare('SELECT id,delta,balance_after,reason,created_at FROM ledger WHERE user_id=? ORDER BY id DESC LIMIT 30').all(req.user.id);
 res.json({user:req.user,wallet:wallet||{balance:0},cards,orders,ledger});
});
app.post('/api/register',authLimiter,csrf,(req,res)=>{
 const schema=z.object({name:z.string().trim().min(2).max(60),email:z.string().trim().email().max(254),password:z.string().min(10).max(100),pin:z.string().regex(/^\d{4,8}$/)});
 const parsed=schema.safeParse(req.body); if(!parsed.success) return res.status(400).json({error:'Use a name, valid email, password of at least 10 characters, and a 4–8 digit PIN.'});
 const {name,email,password,pin}=parsed.data; const e=email.toLowerCase();
 try { const hash=bcrypt.hashSync(password,12), ph=bcrypt.hashSync(pin,12); const r=db.prepare('INSERT INTO users(name,email,password_hash,pin_hash) VALUES(?,?,?,?)').run(name,e,hash,ph); db.prepare('INSERT INTO wallets(user_id,balance) VALUES(?,0)').run(r.lastInsertRowid); req.session.userId=Number(r.lastInsertRowid); res.status(201).json({ok:true}); }
 catch(err){ if(String(err).includes('UNIQUE')) return res.status(409).json({error:'An account with that email already exists.'}); res.status(500).json({error:'Could not create account.'}); }
});
app.post('/api/login',authLimiter,csrf,(req,res)=>{
 const email=safeText(req.body.email,254).toLowerCase(), password=String(req.body.password||''); const u=db.prepare('SELECT * FROM users WHERE email=?').get(email);
 if(!u || u.disabled || !bcrypt.compareSync(password,u.password_hash)) return res.status(401).json({error:'Email or password is incorrect.'});
 req.session.regenerate(err=>{if(err)return res.status(500).json({error:'Sign-in failed.'});req.session.userId=u.id;req.session.csrf=require('crypto').randomBytes(24).toString('hex');res.json({ok:true});});
});
app.post('/api/logout',csrf,(req,res)=>req.session.destroy(()=>{res.clearCookie('echelon.sid');res.json({ok:true});}));
app.post('/api/cards',requireAuth,csrf,(req,res)=>{
 const brand=req.body.brand, tier=req.body.tier;
 if(!['Echelon','Atlas'].includes(brand))return res.status(400).json({error:'Choose Echelon or Atlas.'});
 const allowed=brand==='Echelon'?['Normal','Premium']:['Normal','Gold Premium']; if(!allowed.includes(tier))return res.status(400).json({error:'That card tier is not available for this brand.'});
 try { db.prepare('INSERT INTO cards(user_id,brand,tier) VALUES(?,?,?)').run(req.user.id,brand,tier); res.status(201).json({ok:true}); }
 catch(e){ if(String(e).includes('UNIQUE'))return res.status(409).json({error:`You can have only one ${brand} card. You may have one Echelon and one Atlas card, maximum two total.`}); throw e; }
});
app.post('/api/orders',requireAuth,csrf,(req,res)=>{
 const ids=Array.isArray(req.body.productIds)?req.body.productIds.slice(0,20).map(Number):[];
 if(!ids.length || ids.some(x=>!Number.isSafeInteger(x)||x<=0))return res.status(400).json({error:'Choose products first.'});
 const counts=new Map(); ids.forEach(id=>counts.set(id,(counts.get(id)||0)+1));
 const tx=db.transaction(()=>{
  const items=[];let total=0;
  for(const [id,qty] of counts){const p=db.prepare('SELECT id,name,price,active FROM products WHERE id=?').get(id);if(!p||!p.active)throw new Error('A product is no longer available.');items.push({p,qty});total+=p.price*qty;}
  const w=db.prepare('SELECT balance FROM wallets WHERE user_id=?').get(req.user.id);if(!w||w.balance<total)throw new Error('Not enough Ω in your wallet.');
  const o=db.prepare("INSERT INTO orders(user_id,total,status) VALUES(?,?,'paid')").run(req.user.id,total);
  const itemIns=db.prepare('INSERT INTO order_items(order_id,product_id,product_name,unit_price,quantity) VALUES(?,?,?,?,?)');for(const it of items)itemIns.run(o.lastInsertRowid,it.p.id,it.p.name,it.p.price,it.qty);
  const balance=w.balance-total;db.prepare('UPDATE wallets SET balance=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(balance,req.user.id);
  db.prepare('INSERT INTO ledger(user_id,delta,balance_after,reason,actor_id) VALUES(?,?,?,?,?)').run(req.user.id,-total,balance,`Order #${o.lastInsertRowid}`,req.user.id);
  return {orderId:Number(o.lastInsertRowid),total,balance};
 });
 try{res.status(201).json(tx());}catch(e){res.status(400).json({error:e.message||'Purchase failed.'});}
});
app.post('/api/requests',requireAuth,csrf,(req,res)=>{const subject=safeText(req.body.subject,100),details=safeText(req.body.details,1500);if(subject.length<3||details.length<5)return res.status(400).json({error:'Add a subject and details.'});const r=db.prepare('INSERT INTO requests(user_id,subject,details) VALUES(?,?,?)').run(req.user.id,subject,details);res.status(201).json({ok:true,id:Number(r.lastInsertRowid)});});

// Owner-only management endpoints. Every mutation is checked on the server.
app.get('/api/admin/summary',requireAuth,requireOwner,(req,res)=>{
 const users=db.prepare("SELECT id,name,email,role,disabled,created_at FROM users ORDER BY id DESC LIMIT 200").all();
 const products=db.prepare('SELECT * FROM products ORDER BY id DESC').all();
 const wallets=db.prepare('SELECT w.user_id,w.balance,u.name,u.email FROM wallets w JOIN users u ON u.id=w.user_id ORDER BY u.id').all();
 const orders=db.prepare('SELECT o.*,u.name,u.email FROM orders o JOIN users u ON u.id=o.user_id ORDER BY o.id DESC LIMIT 100').all();
 const requests=db.prepare('SELECT r.*,u.name,u.email FROM requests r JOIN users u ON u.id=r.user_id ORDER BY r.id DESC LIMIT 100').all();
 const ledger=db.prepare('SELECT l.*,u.name,u.email FROM ledger l JOIN users u ON u.id=l.user_id ORDER BY l.id DESC LIMIT 100').all();
 res.json({users,products,wallets,orders,requests,ledger});
});
app.post('/api/admin/wallet',requireAuth,requireOwner,csrf,(req,res)=>{
 const userId=Number(req.body.userId), amount=Number(req.body.amount), reason=safeText(req.body.reason,160);
 if(!Number.isSafeInteger(userId)||!Number.isSafeInteger(amount)||amount===0||Math.abs(amount)>100000000||reason.length<3)return res.status(400).json({error:'Enter a valid account, non-zero whole-number Ω amount, and reason.'});
 const tx=db.transaction(()=>{const w=db.prepare('SELECT balance FROM wallets WHERE user_id=?').get(userId);if(!w)throw new Error('Wallet not found.');const balance=w.balance+amount;if(balance<0)throw new Error('That adjustment would make the balance negative.');db.prepare('UPDATE wallets SET balance=?,updated_at=CURRENT_TIMESTAMP WHERE user_id=?').run(balance,userId);db.prepare('INSERT INTO ledger(user_id,delta,balance_after,reason,actor_id) VALUES(?,?,?,?,?)').run(userId,amount, balance,reason,req.user.id);return balance;});
 try{res.json({ok:true,balance:tx()});}catch(e){res.status(400).json({error:e.message});}
});
app.post('/api/admin/products',requireAuth,requireOwner,csrf,(req,res)=>{
 const id=req.body.id?Number(req.body.id):null,name=safeText(req.body.name,100),description=safeText(req.body.description,1000),category=safeText(req.body.category,50)||'Digital',price=Number(req.body.price),image_url=safeText(req.body.image_url,500),external_url=safeText(req.body.external_url,1000),active=req.body.active==='false'||req.body.active===false?0:1;
 if(name.length<2||!Number.isSafeInteger(price)||price<0||price>100000000)return res.status(400).json({error:'Enter a product name and a non-negative whole-number Ω price.'});
 if(external_url&&!/^https:\/\//i.test(external_url))return res.status(400).json({error:'External links must use HTTPS.'});
 if(id){const r=db.prepare('UPDATE products SET name=?,description=?,price=?,category=?,image_url=?,external_url=?,active=? WHERE id=?').run(name,description,price,category,image_url,external_url,active,id);if(!r.changes)return res.status(404).json({error:'Product not found.'});res.json({ok:true,id});}
 else{const r=db.prepare('INSERT INTO products(name,description,price,category,image_url,external_url,active) VALUES(?,?,?,?,?,?,?)').run(name,description,price,category,image_url,external_url,active);res.status(201).json({ok:true,id:Number(r.lastInsertRowid)});}
});
app.post('/api/admin/users/:id/status',requireAuth,requireOwner,csrf,(req,res)=>{const id=Number(req.params.id);if(id===req.user.id)return res.status(400).json({error:'You cannot disable your own owner account here.'});const disabled=req.body.disabled?1:0;const u=db.prepare('SELECT role FROM users WHERE id=?').get(id);if(!u)return res.status(404).json({error:'Account not found.'});if(u.role==='owner')return res.status(400).json({error:'Owner accounts cannot be disabled using customer controls.'});db.prepare('UPDATE users SET disabled=? WHERE id=?').run(disabled,id);res.json({ok:true});});
app.post('/api/admin/requests/:id/status',requireAuth,requireOwner,csrf,(req,res)=>{const status=safeText(req.body.status,20);if(!['open','in_progress','completed','rejected'].includes(status))return res.status(400).json({error:'Invalid request status.'});db.prepare('UPDATE requests SET status=? WHERE id=?').run(status,Number(req.params.id));res.json({ok:true});});
app.get('/api/admin/export',requireAuth,requireOwner,(req,res)=>{const data={users:db.prepare('SELECT id,name,email,role,disabled,created_at FROM users').all(),wallets:db.prepare('SELECT * FROM wallets').all(),products:db.prepare('SELECT * FROM products').all(),cards:db.prepare('SELECT * FROM cards').all(),orders:db.prepare('SELECT * FROM orders').all(),orderItems:db.prepare('SELECT * FROM order_items').all(),ledger:db.prepare('SELECT * FROM ledger').all(),requests:db.prepare('SELECT * FROM requests').all()};res.setHeader('Content-Disposition','attachment; filename="echelon-store-export.json"');res.json(data);});
app.get('/api/health',(req,res)=>res.json({ok:true}));
app.get('*',(req,res)=>res.sendFile(path.join(__dirname,'public','index.html')));
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'An unexpected server error occurred.'});});
app.listen(PORT,()=>console.log(`Echelon Store running on http://localhost:${PORT}`));
