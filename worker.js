const DAY = 864e5;
const USER_RE = /^[a-z0-9_]{3,20}$/;
const IMG_RE = /^data:image\/(jpeg|webp|png);base64,/;
const DID_RE = /^[0-9a-f]{32}$/;
const PID = /^[0-9a-f]{12}$/;
const te = new TextEncoder();
const td = new TextDecoder();

class E extends Error {
  constructor(code, status) {
    super(code);
    this.code = code;
    this.status = status || 400;
  }
}

const SCHEMA = [
  "CREATE TABLE IF NOT EXISTS users(uid TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, display TEXT NOT NULL, account_id TEXT NOT NULL UNIQUE, pass TEXT NOT NULL, avatar TEXT NOT NULL DEFAULT '', banned INTEGER NOT NULL DEFAULT 0, sv INTEGER NOT NULL DEFAULT 0, un_at INTEGER NOT NULL DEFAULT 0, nm_at INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0, last_seen INTEGER NOT NULL DEFAULT 0, email TEXT NOT NULL DEFAULT '')",
  "CREATE INDEX IF NOT EXISTS ix_users_seen ON users(last_seen DESC)",
  "CREATE TABLE IF NOT EXISTS posts(id TEXT PRIMARY KEY, title TEXT NOT NULL, descr TEXT NOT NULL DEFAULT '', link TEXT NOT NULL DEFAULT '', btn TEXT NOT NULL DEFAULT '', links TEXT NOT NULL DEFAULT '[]', ldesc TEXT NOT NULL DEFAULT '', video TEXT NOT NULL DEFAULT '', vid TEXT NOT NULL DEFAULT '', thumb TEXT NOT NULL DEFAULT '', likes INTEGER NOT NULL DEFAULT 0, views INTEGER NOT NULL DEFAULT 0, created INTEGER NOT NULL DEFAULT 0, pinned INTEGER NOT NULL DEFAULT 0, pinned_at INTEGER NOT NULL DEFAULT 0, hidden INTEGER NOT NULL DEFAULT 0)",
  "CREATE INDEX IF NOT EXISTS ix_posts_new ON posts(hidden, pinned, created DESC)",
  "CREATE INDEX IF NOT EXISTS ix_posts_views ON posts(hidden, pinned, views DESC)",
  "CREATE INDEX IF NOT EXISTS ix_posts_vid ON posts(vid)",
  "CREATE TABLE IF NOT EXISTS covers(id TEXT PRIMARY KEY, data TEXT NOT NULL)",
  "CREATE TABLE IF NOT EXISTS likes(post_id TEXT NOT NULL, uid TEXT NOT NULL, PRIMARY KEY(post_id, uid))",
  "CREATE INDEX IF NOT EXISTS ix_likes_uid ON likes(uid)",
  "CREATE TABLE IF NOT EXISTS dv(did TEXT PRIMARY KEY, t INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS vw(k TEXT PRIMARY KEY, t INTEGER NOT NULL)",
  "CREATE TABLE IF NOT EXISTS rl(k TEXT PRIMARY KEY, n INTEGER NOT NULL, exp INTEGER NOT NULL)"
];
let ready = false;
async function init(db) {
  if (ready) return;
  await db.batch(SCHEMA.map(s => db.prepare(s)));
  try {
    await db.prepare("ALTER TABLE users ADD COLUMN email TEXT NOT NULL DEFAULT ''").run();
  } catch (e) {}
  ready = true;
}

const hex = u8 => [...u8].map(b => b.toString(16).padStart(2, "0")).join("");
const unhex = h => new Uint8Array((h.match(/../g) || []).map(x => parseInt(x, 16)));
const b64u = u8 => btoa(String.fromCharCode(...u8)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64u = s => {
  s = s.replace(/-/g, "+").replace(/_/g, "/");
  while (s.length % 4) s += "=";
  return Uint8Array.from(atob(s), c => c.charCodeAt(0));
};
const same = (a, b) => {
  if (a.length !== b.length) return false;
  let d = 0;
  for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i];
  return d === 0;
};
const sameStr = (a, b) => same(te.encode(a), te.encode(b));
const rnd = n => crypto.getRandomValues(new Uint8Array(n));
const rndHex = n => hex(rnd(n));
const sha = async s => new Uint8Array(await crypto.subtle.digest("SHA-256", te.encode(s)));

async function pbkdf2(pw, salt, iter) {
  const k = await crypto.subtle.importKey("raw", te.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(await crypto.subtle.deriveBits({name: "PBKDF2", hash: "SHA-256", salt, iterations: iter}, k, 256));
}
async function hashPw(env, p) {
  const iter = Math.min(100000, Math.max(1000, parseInt(env.PBKDF2_ITER, 10) || 100000));
  const salt = rnd(16);
  return "p1$" + iter + "$" + hex(salt) + "$" + hex(await pbkdf2(p, salt, iter));
}
async function checkPw(p, stored) {
  const m = /^p1\$(\d+)\$([0-9a-f]+)\$([0-9a-f]+)$/.exec(stored || "");
  if (!m) return false;
  return same(await pbkdf2(p, unhex(m[2]), +m[1]), unhex(m[3]));
}

async function hmac(env, s) {
  const k = await crypto.subtle.importKey("raw", te.encode(env.SESSION_SECRET), {name: "HMAC", hash: "SHA-256"}, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", k, te.encode(s))));
}
async function makeToken(env, uid, sv) {
  const pl = uid + "." + (Date.now() + 30 * DAY) + "." + sv;
  return pl + "." + (await hmac(env, pl));
}
async function readToken(env, t) {
  if (typeof t !== "string") return null;
  const p = t.split(".");
  if (p.length !== 4) return null;
  const pl = p[0] + "." + p[1] + "." + p[2];
  if (!sameStr(await hmac(env, pl), p[3])) return null;
  if (+p[1] < Date.now()) return null;
  return {uid: p[0], sv: p[2]};
}

const adminEmails = env => (env.ADMIN_EMAIL || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
const UCOLS = "uid, username, display, account_id, pass, banned, sv, un_at, nm_at, email";
const mapUser = (r, env) => ({
  uid: r.uid, username: r.username, displayName: r.display, accountId: r.account_id, pass: r.pass,
  banned: r.banned === 1, sv: String(r.sv), unAt: r.un_at, nmAt: r.nm_at,
  google: !!r.email, admin: !!r.email && adminEmails(env).includes(r.email)
});
async function loadUser(env, uid) {
  if (!/^[0-9a-f]{24}$/.test(uid)) return null;
  const r = await env.DB.prepare("SELECT " + UCOLS + " FROM users WHERE uid=?").bind(uid).first();
  return r ? mapUser(r, env) : null;
}

const ipHash = async (env, ip) => hex(await sha(env.SESSION_SECRET + ":" + ip)).slice(0, 32);

async function limit(env, key, max, sec) {
  const now = Date.now(), exp = now + sec * 1000;
  const rs = await env.DB.batch([
    env.DB.prepare("INSERT INTO rl(k, n, exp) VALUES(?, 1, ?) ON CONFLICT(k) DO UPDATE SET n = CASE WHEN rl.exp < ? THEN 1 ELSE rl.n + 1 END, exp = CASE WHEN rl.exp < ? THEN ? ELSE rl.exp END").bind(key, exp, now, now, exp),
    env.DB.prepare("SELECT n FROM rl WHERE k=?").bind(key)
  ]);
  if (rs[1].results[0].n > max) throw new E("rate", 429);
}

const str = (v, max) => typeof v === "string" ? v.trim().slice(0, max) : "";
function strongEnough(p) {
  if (typeof p !== "string" || p.length < 7 || p.length > 128) return false;
  return [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(p)).length >= 2;
}
const isHttp = u => /^https?:\/\/[^\s]+$/i.test(u);
const ytId = u => {
  const m = (u || "").trim().match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?(?:.*&)?v=|embed\/|shorts\/|live\/))([A-Za-z0-9_-]{11})/);
  return m ? m[1] : "";
};
const newAccountId = () => String(10000000 + Math.floor(crypto.getRandomValues(new Uint32Array(1))[0] / 4294967296 * 90000000));

let jwks = {keys: [], at: 0};
async function googleKey(kid) {
  const age = Date.now() - jwks.at;
  let k = jwks.keys.find(x => x.kid === kid);
  if ((!k && age > 60000) || age > 3600000) {
    const r = await fetch("https://www.googleapis.com/oauth2/v3/certs");
    if (!r.ok) throw new E("google", 502);
    jwks = {keys: (await r.json()).keys || [], at: Date.now()};
    k = jwks.keys.find(x => x.kid === kid);
  }
  if (!k) throw new E("badtoken", 401);
  return crypto.subtle.importKey("jwk", {kty: k.kty, n: k.n, e: k.e, alg: "RS256", ext: true}, {name: "RSASSA-PKCS1-v1_5", hash: "SHA-256"}, false, ["verify"]);
}
async function verifyGoogle(env, cred) {
  if (typeof cred !== "string" || cred.length > 4096) throw new E("badtoken", 401);
  const p = cred.split(".");
  if (p.length !== 3) throw new E("badtoken", 401);
  let head, body;
  try {
    head = JSON.parse(td.decode(unb64u(p[0])));
    body = JSON.parse(td.decode(unb64u(p[1])));
  } catch (e) {
    throw new E("badtoken", 401);
  }
  if (head.alg !== "RS256" || typeof head.kid !== "string") throw new E("badtoken", 401);
  const key = await googleKey(head.kid);
  let ok = false;
  try {
    ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, unb64u(p[2]), te.encode(p[0] + "." + p[1]));
  } catch (e) {}
  if (!ok) throw new E("badtoken", 401);
  const now = Date.now();
  if (body.aud !== env.GOOGLE_CLIENT_ID) throw new E("badtoken", 401);
  if (body.iss !== "https://accounts.google.com" && body.iss !== "accounts.google.com") throw new E("badtoken", 401);
  if (!(+body.exp * 1000 > now) || +body.iat * 1000 > now + 120000) throw new E("badtoken", 401);
  if (body.email_verified !== true && body.email_verified !== "true") throw new E("unverified", 403);
  if (typeof body.sub !== "string" || !body.sub || typeof body.email !== "string" || !body.email) throw new E("badtoken", 401);
  return body;
}

function outUser(u, extra) {
  return {uid: u.uid, username: u.google ? "" : u.username, displayName: u.displayName, accountId: u.accountId, admin: u.admin, google: u.google, unAt: +u.unAt || 0, nmAt: +u.nmAt || 0, ...extra};
}

const PCOLS = "id, title, descr, link, btn, links, ldesc, video, thumb, likes, views, created, pinned, pinned_at, hidden";
function outPost(r, admin) {
  let links = [];
  try { links = r.links ? JSON.parse(r.links) : []; } catch (e) {}
  const o = {
    id: r.id, title: r.title, desc: r.descr, link: r.link, btn: r.btn, ldesc: r.ldesc, video: r.video, thumb: r.thumb,
    likes: Math.max(0, r.likes), views: Math.max(0, r.views), createdAt: r.created, pinned: r.pinned === 1, pinnedAt: r.pinned_at, links
  };
  if (admin) o.hidden = r.hidden === 1;
  return o;
}

function cleanPost(b) {
  const title = str(b.title, 120);
  if (!title) throw new E("title");
  const out = {title, desc: str(b.desc, 5000), btn: str(b.btn, 40), ldesc: str(b.ldesc, 1000), video: str(b.video, 300)};
  let links = [];
  if (Array.isArray(b.links)) {
    links = b.links.slice(0, 30).map(l => ({u: str(l && l.u, 1000), n: str(l && l.n, 40)})).filter(l => l.u);
    if (links.some(l => !isHttp(l.u))) throw new E("badlink");
  }
  out.link = str(b.link, 1000);
  if (out.link && !isHttp(out.link)) throw new E("badlink");
  out.links = links.length > 1 ? links : [];
  if (links.length > 1) out.link = "";
  if (out.video && !ytId(out.video)) throw new E("badvideo");
  out.vid = out.video ? ytId(out.video) : "";
  out.pinned = !!b.pinned;
  if (typeof b.thumb === "string" && b.thumb !== "") {
    if (!IMG_RE.test(b.thumb) || b.thumb.length > 300000) throw new E("badimg");
    out.thumb = b.thumb;
  } else if (b.thumb === "") out.thumb = "";
  if (b.cover) {
    if (typeof b.cover !== "string" || !IMG_RE.test(b.cover) || b.cover.length > 2000000) throw new E("badimg");
    out.cover = b.cover;
  }
  return out;
}

const needAdmin = user => {
  if (!user || !user.admin) throw new E("forbidden", 403);
};

async function purgeUser(env, uid) {
  await env.DB.batch([
    env.DB.prepare("DELETE FROM likes WHERE uid=?").bind(uid),
    env.DB.prepare("UPDATE posts SET likes=(SELECT COUNT(*) FROM likes WHERE post_id=posts.id)"),
    env.DB.prepare("DELETE FROM users WHERE uid=?").bind(uid)
  ]);
}

const H = {};

H.cfg = async ({env}) => ({gid: env.GOOGLE_CLIENT_ID || ""});

H.list = async ({env, q}) => {
  const sort = ["new", "old", "pop"].includes(q.sort) ? q.sort : "new";
  const cur = Math.max(0, parseInt(q.cursor, 10) || 0);
  const lim = Math.min(20, Math.max(1, parseInt(q.limit, 10) || 12));
  const order = sort === "pop" ? "views DESC, created DESC" : sort === "old" ? "created ASC" : "created DESC";
  const cmds = [env.DB.prepare("SELECT " + PCOLS + " FROM posts WHERE hidden=0 AND pinned=0 ORDER BY " + order + " LIMIT ? OFFSET ?").bind(lim, cur)];
  if (cur === 0) cmds.push(env.DB.prepare("SELECT " + PCOLS + " FROM posts WHERE hidden=0 AND pinned=1 ORDER BY pinned_at DESC"));
  cmds.push(env.DB.prepare("SELECT COUNT(*) AS n FROM dv"));
  const rs = await env.DB.batch(cmds);
  const rows = rs[0].results;
  const pins = cur === 0 ? rs[1].results : [];
  return {
    posts: [...pins, ...rows].map(r => outPost(r, false)),
    next: rows.length === lim ? cur + lim : null,
    members: rs[rs.length - 1].results[0].n
  };
};

H.post = async ({env, q}) => {
  const id = str(q.id, 40);
  if (!PID.test(id)) throw new E("notfound", 404);
  const r = await env.DB.prepare("SELECT " + PCOLS + " FROM posts WHERE id=? AND hidden=0").bind(id).first();
  if (!r) throw new E("notfound", 404);
  return {post: outPost(r, false)};
};

H.cover = async ({env, q}) => {
  const id = str(q.id, 40);
  if (!PID.test(id)) throw new E("notfound", 404);
  const r = await env.DB.prepare("SELECT c.data AS data FROM covers c JOIN posts p ON p.id=c.id WHERE c.id=? AND p.hidden=0").bind(id).first();
  return {data: r ? r.data : ""};
};

H.vid = async ({env, q}) => {
  const v = str(q.v, 20);
  if (!/^[\w-]{11}$/.test(v)) throw new E("notfound", 404);
  const r = await env.DB.prepare("SELECT " + PCOLS + " FROM posts WHERE vid=? AND hidden=0 ORDER BY created DESC LIMIT 1").bind(v).first();
  if (!r) throw new E("notfound", 404);
  return {post: outPost(r, false)};
};

H.check = async ({env, q}) => {
  const u = str(q.u, 40).toLowerCase();
  if (!USER_RE.test(u)) throw new E("invalid");
  return {free: !(await env.DB.prepare("SELECT 1 AS x FROM users WHERE username=?").bind(u).first())};
};

H.view = async ({env, q, user, ip}) => {
  const id = str(q.id, 40);
  if (!PID.test(id)) throw new E("notfound", 404);
  const p = await env.DB.prepare("SELECT hidden FROM posts WHERE id=?").bind(id).first();
  if (!p || (p.hidden === 1 && !(user && user.admin))) throw new E("notfound", 404);
  const now = Date.now(), k = id + ":" + (await ipHash(env, ip));
  const cmds = [env.DB.prepare("INSERT INTO vw(k, t) VALUES(?, ?) ON CONFLICT(k) DO UPDATE SET t=excluded.t WHERE vw.t <= excluded.t - 2000").bind(k, now)];
  if (typeof q.d === "string" && DID_RE.test(q.d)) cmds.push(env.DB.prepare("INSERT OR IGNORE INTO dv(did, t) VALUES(?, ?)").bind(q.d, now));
  const rs = await env.DB.batch(cmds);
  const counted = rs[0].meta.changes > 0;
  if (counted) await env.DB.prepare("UPDATE posts SET views=views+1 WHERE id=?").bind(id).run();
  const v = await env.DB.prepare("SELECT views FROM posts WHERE id=?").bind(id).first();
  if (Math.random() < 0.02) {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM vw WHERE t < ?").bind(now - 60000),
      env.DB.prepare("DELETE FROM rl WHERE exp < ?").bind(now)
    ]);
  }
  return {counted, views: v.views};
};

H.like = async ({env, q, user, ip}) => {
  const d = typeof q.d === "string" ? q.d : "";
  if (!DID_RE.test(d)) throw new E("device");
  const id = str(q.id, 40);
  if (!PID.test(id)) throw new E("notfound", 404);
  await limit(env, "lk:" + (await ipHash(env, ip)), 60, 600);
  const p = await env.DB.prepare("SELECT hidden FROM posts WHERE id=?").bind(id).first();
  if (!p || (p.hidden === 1 && !(user && user.admin))) throw new E("notfound", 404);
  const on = !!q.on, uid = "d" + d;
  const rs = await env.DB.batch([
    on ? env.DB.prepare("INSERT OR IGNORE INTO likes(post_id, uid) VALUES(?, ?)").bind(id, uid)
       : env.DB.prepare("DELETE FROM likes WHERE post_id=? AND uid=?").bind(id, uid),
    env.DB.prepare("INSERT OR IGNORE INTO dv(did, t) VALUES(?, ?)").bind(d, Date.now()),
    env.DB.prepare("UPDATE posts SET likes=(SELECT COUNT(*) FROM likes WHERE post_id=?) WHERE id=?").bind(id, id),
    env.DB.prepare("SELECT likes FROM posts WHERE id=?").bind(id)
  ]);
  return {likes: rs[3].results[0].likes, liked: on};
};

H.register = async ({env, q, ip}) => {
  await limit(env, "reg:" + (await ipHash(env, ip)), 20, 3600);
  const u = str(q.u, 40).toLowerCase(), name = str(q.name, 30);
  if (!USER_RE.test(u)) throw new E("invalid");
  if (!name) throw new E("name");
  if (!strongEnough(q.p)) throw new E("weak");
  if (await env.DB.prepare("SELECT 1 AS x FROM users WHERE username=?").bind(u).first()) throw new E("taken", 409);
  const pass = await hashPw(env, q.p), uid = rndHex(12), now = Date.now();
  for (let i = 0; i < 6; i++) {
    try {
      await env.DB.prepare("INSERT INTO users(uid, username, display, account_id, pass, created, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?)").bind(uid, u, name, newAccountId(), pass, now, now).run();
      return {ok: true};
    } catch (e) {
      if (await env.DB.prepare("SELECT 1 AS x FROM users WHERE username=?").bind(u).first()) throw new E("taken", 409);
    }
  }
  throw new E("idfail", 500);
};

H.login = async ({env, q, ip}) => {
  const u = str(q.u, 40).toLowerCase(), p = typeof q.p === "string" ? q.p : "";
  await limit(env, "lg:" + (await ipHash(env, ip)), 30, 60);
  if (!USER_RE.test(u) || !p || p.length > 128) throw new E("invalid", 401);
  await limit(env, "lu:" + u, 10, 300);
  const r = await env.DB.prepare("SELECT " + UCOLS + ", avatar FROM users WHERE username=?").bind(u).first();
  const user = r && mapUser(r, env);
  if (!user || !(await checkPw(p, user.pass))) throw new E("invalid", 401);
  if (user.banned) throw new E("banned", 403);
  await env.DB.prepare("UPDATE users SET last_seen=? WHERE uid=?").bind(Date.now(), user.uid).run();
  return {user: outUser(user, {avatar: r.avatar}), token: await makeToken(env, user.uid, user.sv)};
};

H.glogin = async ({env, q, ip}) => {
  await limit(env, "gl:" + (await ipHash(env, ip)), 20, 600);
  if (!env.GOOGLE_CLIENT_ID) throw new E("gcfg", 500);
  const g = await verifyGoogle(env, q.cred);
  const email = g.email.trim().toLowerCase();
  const uid = hex(await sha("g:" + g.sub)).slice(0, 24);
  const now = Date.now();
  const sel = "SELECT " + UCOLS + ", avatar FROM users WHERE uid=?";
  let r = await env.DB.prepare(sel).bind(uid).first();
  if (r) {
    if (r.email !== email) await env.DB.prepare("UPDATE users SET email=? WHERE uid=?").bind(email, uid).run();
  } else {
    const name = str(g.name, 30) || email.split("@")[0].slice(0, 30);
    const pic = typeof g.picture === "string" && /^https:\/\/[^\s]{1,400}$/.test(g.picture) ? g.picture : "";
    for (let i = 0; i < 6 && !r; i++) {
      try {
        await env.DB.prepare("INSERT INTO users(uid, username, display, account_id, pass, avatar, created, last_seen, email) VALUES(?, ?, ?, ?, '', ?, ?, ?, ?)").bind(uid, "g" + uid, name, newAccountId(), pic, now, now, email).run();
      } catch (e) {}
      r = await env.DB.prepare(sel).bind(uid).first();
    }
    if (!r) throw new E("idfail", 500);
  }
  r = await env.DB.prepare(sel).bind(uid).first();
  const user = mapUser(r, env);
  if (user.banned) throw new E("banned", 403);
  await env.DB.prepare("UPDATE users SET last_seen=? WHERE uid=?").bind(now, uid).run();
  return {user: outUser(user, {avatar: r.avatar}), token: await makeToken(env, uid, user.sv)};
};

H.logout = async ({env, user}) => {
  if (user) await env.DB.prepare("UPDATE users SET last_seen=0 WHERE uid=?").bind(user.uid).run();
  return {ok: true};
};

H.me = async ({env, q, user, tok}) => {
  if (!user) {
    const u = tok && (await loadUser(env, tok.uid));
    if (u && u.banned) return {user: null, banned: true};
    return {user: null};
  }
  if (user.banned) return {user: null, banned: true};
  const rs = await env.DB.batch([
    env.DB.prepare("UPDATE users SET last_seen=? WHERE uid=?").bind(Date.now(), user.uid),
    env.DB.prepare("SELECT COUNT(*) AS n FROM dv"),
    env.DB.prepare("SELECT avatar FROM users WHERE uid=?").bind(user.uid)
  ]);
  return {user: outUser(user, q.full ? {avatar: rs[2].results[0].avatar} : {}), members: rs[1].results[0].n};
};

H.verify = async ({env, q, user}) => {
  if (!user) throw new E("login", 401);
  await limit(env, "vf:" + user.uid, 10, 300);
  if (!(await checkPw(typeof q.p === "string" ? q.p : "", user.pass))) throw new E("wrong", 403);
  return {ok: true};
};

H.psave = async ({env, q, user}) => {
  if (!user) throw new E("login", 401);
  const now = Date.now();
  const nu = user.google || q.username === undefined ? user.username : str(q.username, 40).toLowerCase();
  const nn = q.displayName === undefined ? user.displayName : str(q.displayName, 30);
  if (!nn) throw new E("name");
  if (nu !== user.username) {
    if (!USER_RE.test(nu)) throw new E("invalid");
    if (!user.admin && +user.unAt && now < +user.unAt + 14 * DAY) throw new E("locked", 403);
  }
  if (nn !== user.displayName && !user.admin && +user.nmAt && now < +user.nmAt + 7 * DAY) throw new E("locked", 403);
  let newPw = "";
  if (q.password) {
    if (user.google) throw new E("google");
    if (!strongEnough(q.password)) throw new E("weak");
    if (!(await checkPw(typeof q.cur === "string" ? q.cur : "", user.pass))) throw new E("wrong", 403);
    if (q.password === q.cur) throw new E("same");
    newPw = q.password;
  }
  if (q.avatar && (typeof q.avatar !== "string" || !IMG_RE.test(q.avatar) || q.avatar.length > 120000)) throw new E("badimg");
  const sets = [], vals = [];
  if (nu !== user.username) {
    sets.push("username=?", "un_at=?");
    vals.push(nu, now);
  }
  if (nn !== user.displayName) {
    sets.push("display=?");
    vals.push(nn);
    if (!user.admin) { sets.push("nm_at=?"); vals.push(now); }
  }
  let sv = user.sv;
  if (newPw) {
    sv = String((+user.sv || 0) + 1);
    sets.push("pass=?", "sv=?");
    vals.push(await hashPw(env, newPw), +sv);
  }
  if (q.avatar) { sets.push("avatar=?"); vals.push(q.avatar); }
  if (sets.length) {
    try {
      await env.DB.prepare("UPDATE users SET " + sets.join(", ") + " WHERE uid=?").bind(...vals, user.uid).run();
    } catch (e) {
      throw new E("taken", 409);
    }
  }
  const r = await env.DB.prepare("SELECT " + UCOLS + ", avatar FROM users WHERE uid=?").bind(user.uid).first();
  return {user: outUser(mapUser(r, env), {avatar: r.avatar}), token: newPw ? await makeToken(env, user.uid, sv) : undefined};
};

H.pdel = async ({env, q, user}) => {
  if (!user) throw new E("login", 401);
  if (user.admin) throw new E("admin", 403);
  await limit(env, "vf:" + user.uid, 10, 300);
  if (!user.google && !(await checkPw(typeof q.p === "string" ? q.p : "", user.pass))) throw new E("wrong", 403);
  await purgeUser(env, user.uid);
  return {ok: true};
};

H.plist = async ({env, q, user}) => {
  needAdmin(user);
  const cur = Math.max(0, parseInt(q.cursor, 10) || 0), lim = 20;
  const r = await env.DB.prepare("SELECT " + PCOLS + " FROM posts ORDER BY created DESC LIMIT ? OFFSET ?").bind(lim, cur).all();
  return {posts: r.results.map(x => outPost(x, true)), next: r.results.length === lim ? cur + lim : null};
};

H.psavepost = async ({env, q, user}) => {
  needAdmin(user);
  const d = cleanPost(q), now = Date.now();
  const editing = q.id ? str(q.id, 40) : "";
  if (editing) {
    if (!PID.test(editing)) throw new E("notfound", 404);
    const old = await env.DB.prepare("SELECT pinned, pinned_at FROM posts WHERE id=?").bind(editing).first();
    if (!old) throw new E("notfound", 404);
    const pinnedAt = d.pinned ? (old.pinned === 1 && old.pinned_at ? old.pinned_at : now) : 0;
    const sets = ["title=?", "descr=?", "link=?", "btn=?", "links=?", "ldesc=?", "video=?", "vid=?", "pinned=?", "pinned_at=?"];
    const vals = [d.title, d.desc, d.link, d.btn, JSON.stringify(d.links), d.ldesc, d.video, d.vid, d.pinned ? 1 : 0, pinnedAt];
    if (d.thumb !== undefined) { sets.push("thumb=?"); vals.push(d.thumb); }
    const cmds = [env.DB.prepare("UPDATE posts SET " + sets.join(", ") + " WHERE id=?").bind(...vals, editing)];
    if (d.cover) cmds.push(env.DB.prepare("INSERT OR REPLACE INTO covers(id, data) VALUES(?, ?)").bind(editing, d.cover));
    await env.DB.batch(cmds);
    return {id: editing};
  }
  const id = rndHex(6);
  const cmds = [env.DB.prepare("INSERT INTO posts(id, title, descr, link, btn, links, ldesc, video, vid, thumb, created, pinned, pinned_at) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
    .bind(id, d.title, d.desc, d.link, d.btn, JSON.stringify(d.links), d.ldesc, d.video, d.vid, d.thumb || "", now, d.pinned ? 1 : 0, d.pinned ? now : 0)];
  if (d.cover) cmds.push(env.DB.prepare("INSERT OR REPLACE INTO covers(id, data) VALUES(?, ?)").bind(id, d.cover));
  await env.DB.batch(cmds);
  return {id};
};

H.phide = async ({env, q, user}) => {
  needAdmin(user);
  const id = str(q.id, 40);
  if (!PID.test(id)) throw new E("notfound", 404);
  const r = await env.DB.prepare("UPDATE posts SET hidden=? WHERE id=?").bind(q.hidden ? 1 : 0, id).run();
  if (!r.meta.changes) throw new E("notfound", 404);
  return {ok: true};
};

H.pdelpost = async ({env, q, user}) => {
  needAdmin(user);
  const id = str(q.id, 40);
  if (!PID.test(id)) throw new E("notfound", 404);
  await env.DB.batch([
    env.DB.prepare("DELETE FROM posts WHERE id=?").bind(id),
    env.DB.prepare("DELETE FROM covers WHERE id=?").bind(id),
    env.DB.prepare("DELETE FROM likes WHERE post_id=?").bind(id)
  ]);
  return {ok: true};
};

H.ulist = async ({env, q, user}) => {
  needAdmin(user);
  const cur = Math.max(0, parseInt(q.cursor, 10) || 0), lim = 30;
  const r = await env.DB.prepare("SELECT uid, username, display, account_id, banned, last_seen, email FROM users ORDER BY last_seen DESC, created DESC LIMIT ? OFFSET ?").bind(lim, cur).all();
  return {
    users: r.results.map(x => ({id: x.uid, username: x.email ? "" : x.username, google: !!x.email, displayName: x.display, accountId: x.account_id, banned: x.banned === 1, lastSeen: x.last_seen})),
    next: r.results.length === lim ? cur + lim : null
  };
};

H.uban = async ({env, q, user}) => {
  needAdmin(user);
  const t = await loadUser(env, str(q.id, 40));
  if (!t) throw new E("notfound", 404);
  if (t.admin) throw new E("admin", 403);
  await env.DB.prepare("UPDATE users SET banned=?, sv=sv+1 WHERE uid=?").bind(q.banned ? 1 : 0, t.uid).run();
  return {ok: true};
};

H.udel = async ({env, q, user}) => {
  needAdmin(user);
  const t = await loadUser(env, str(q.id, 40));
  if (!t) throw new E("notfound", 404);
  if (t.admin) throw new E("admin", 403);
  await purgeUser(env, t.uid);
  return {ok: true};
};

H.uedit = async ({env, q, user}) => {
  needAdmin(user);
  const t = await loadUser(env, str(q.id, 40));
  if (!t) throw new E("notfound", 404);
  const nn = str(q.displayName, 30);
  if (!nn) throw new E("name");
  const sets = ["display=?"], vals = [nn];
  if (!t.google) {
    const nu = q.username === undefined ? t.username : str(q.username, 40).toLowerCase();
    if (nu !== t.username && !USER_RE.test(nu)) throw new E("invalid");
    if (q.password && !strongEnough(q.password)) throw new E("weak");
    sets.push("username=?");
    vals.push(nu);
    if (q.password) {
      sets.push("pass=?", "sv=?");
      vals.push(await hashPw(env, q.password), (+t.sv || 0) + 1);
    }
  }
  try {
    await env.DB.prepare("UPDATE users SET " + sets.join(", ") + " WHERE uid=?").bind(...vals, t.uid).run();
  } catch (e) {
    throw new E("taken", 409);
  }
  return {ok: true};
};

const GET_OK = new Set(["list", "post", "cover", "vid", "check", "cfg"]);

export default {
  async fetch(req, env) {
    const origin = req.headers.get("Origin") || "";
    const allowed = (env.ALLOWED_ORIGIN || "").split(",").map(s => s.trim().replace(/\/+$/, "")).filter(Boolean);
    const cors = {
      "Access-Control-Allow-Origin": !allowed.length ? "*" : allowed.includes(origin) ? origin : allowed[0],
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Access-Control-Max-Age": "86400",
      "Vary": "Origin",
      "Cache-Control": "no-store"
    };
    const send = (code, body) => new Response(code === 204 ? null : JSON.stringify(body), {status: code, headers: {...cors, "Content-Type": "application/json"}});
    try {
      if (req.method === "OPTIONS") return send(204);
      const isGet = req.method === "GET";
      if (!isGet && req.method !== "POST") throw new E("method", 405);
      if (allowed.length && origin && !allowed.includes(origin)) throw new E("origin", 403);
      if (!env.DB || !env.SESSION_SECRET || env.SESSION_SECRET.length < 16) throw new E("config", 500);
      await init(env.DB);
      let q;
      if (isGet) q = Object.fromEntries(new URL(req.url).searchParams);
      else {
        try { q = await req.json(); } catch (e) { q = {}; }
        if (!q || typeof q !== "object") q = {};
      }
      const a = typeof q.a === "string" ? q.a : "";
      const fn = Object.prototype.hasOwnProperty.call(H, a) ? H[a] : null;
      if (!fn) throw new E("unknown", 404);
      if (isGet !== GET_OK.has(a)) throw new E("method", 405);
      let tok = null, user = null;
      if (!isGet) {
        tok = await readToken(env, q.t);
        user = tok ? await loadUser(env, tok.uid) : null;
        if (user && user.sv !== tok.sv) user = null;
        if (user && user.banned && a !== "me" && a !== "logout") throw new E("banned", 403);
      }
      const ip = req.headers.get("CF-Connecting-IP") || req.headers.get("x-forwarded-for") || "0";
      return send(200, await fn({env, q, user, tok, ip}));
    } catch (e) {
      if (e instanceof E) return send(e.status, {error: e.code});
      return send(500, {error: "server"});
    }
  }
};
