const crypto = require("crypto");

const REST_URL = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const REST_TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const SECRET = process.env.SESSION_SECRET || "";
const ADMIN = (process.env.ADMIN_USERNAME || "").trim().toLowerCase();
const DAY = 864e5;
const USER_RE = /^[a-z0-9_]{3,20}$/;
const IMG_RE = /^data:image\/(jpeg|webp|png);base64,/;

class E extends Error {
  constructor(code, status) {
    super(code);
    this.code = code;
    this.status = status || 400;
  }
}

async function pipe(cmds) {
  if (!REST_URL || !REST_TOKEN || SECRET.length < 16) throw new E("config", 500);
  const r = await fetch(REST_URL + "/pipeline", {
    method: "POST",
    headers: {Authorization: "Bearer " + REST_TOKEN, "Content-Type": "application/json"},
    body: JSON.stringify(cmds)
  });
  if (!r.ok) throw new E("db", 502);
  const j = await r.json();
  return j.map(x => {
    if (x && x.error) throw new E("db", 502);
    return x.result;
  });
}
const cmd = async (...c) => (await pipe([c]))[0];

const toObj = a => {
  if (!a) return null;
  if (!Array.isArray(a)) return Object.keys(a).length ? a : null;
  if (!a.length) return null;
  const o = {};
  for (let i = 0; i < a.length; i += 2) o[a[i]] = a[i + 1];
  return o;
};

const scrypt = (p, s) => new Promise((res, rej) => crypto.scrypt(p, s, 64, {N: 16384, r: 8, p: 1}, (e, k) => e ? rej(e) : res(k)));
async function hashPw(p) {
  const salt = crypto.randomBytes(16);
  return "s1$" + salt.toString("hex") + "$" + (await scrypt(p, salt)).toString("hex");
}
async function checkPw(p, stored) {
  const m = /^s1\$([0-9a-f]+)\$([0-9a-f]+)$/.exec(stored || "");
  if (!m) return false;
  const k = await scrypt(p, Buffer.from(m[1], "hex")), s = Buffer.from(m[2], "hex");
  return k.length === s.length && crypto.timingSafeEqual(k, s);
}

const hmac = s => crypto.createHmac("sha256", SECRET).update(s).digest("base64url");
function makeCookie(uid, sv) {
  const exp = Date.now() + 30 * DAY, pl = uid + "." + exp + "." + sv;
  return "sid=" + pl + "." + hmac(pl) + "; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=" + 30 * 86400;
}
const clearCookie = () => "sid=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0";

function readCookie(req) {
  const m = /(?:^|;\s*)sid=([^;]+)/.exec(req.headers.cookie || "");
  if (!m) return null;
  const p = m[1].split(".");
  if (p.length !== 4) return null;
  const pl = p[0] + "." + p[1] + "." + p[2], a = Buffer.from(hmac(pl)), b = Buffer.from(p[3]);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  if (+p[1] < Date.now()) return null;
  return {uid: p[0], sv: p[2]};
}

const UF = ["username", "displayName", "accountId", "banned", "sv", "unAt", "nmAt", "pass"];
async function loadUser(uid) {
  if (!/^[0-9a-f]{24}$/.test(uid)) return null;
  const v = await cmd("HMGET", "u:" + uid, ...UF);
  if (!v || !v[0]) return null;
  const u = {uid};
  UF.forEach((k, i) => { u[k] = v[i]; });
  u.admin = !!ADMIN && u.username === ADMIN;
  u.banned = u.banned === "1";
  u.sv = u.sv || "0";
  return u;
}
async function authUser(req) {
  const c = readCookie(req);
  if (!c) return null;
  const u = await loadUser(c.uid);
  if (!u || u.sv !== c.sv) return null;
  return u;
}

function clientIp(req) {
  const h = req.headers;
  const ip = String(h["x-vercel-forwarded-for"] || h["x-forwarded-for"] || h["x-real-ip"] || (req.socket && req.socket.remoteAddress) || "").split(",")[0].trim();
  return ip || "0";
}
const ipHash = ip => crypto.createHash("sha256").update(SECRET + ":" + ip).digest("hex").slice(0, 32);

async function limit(key, max, sec) {
  const n = await cmd("INCR", key);
  if (n === 1) await cmd("EXPIRE", key, sec);
  if (n > max) throw new E("rate", 429);
}

const str = (v, max) => typeof v === "string" ? v.trim().slice(0, max) : "";
function strongEnough(p) {
  if (typeof p !== "string" || p.length < 7 || p.length > 128) return false;
  return [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter(r => r.test(p)).length >= 2;
}
const isHttp = u => /^https?:\/\/[^\s]+$/i.test(u);

function outUser(u, extra) {
  return {
    uid: u.uid, username: u.username, displayName: u.displayName, accountId: u.accountId,
    admin: u.admin, unAt: +u.unAt || 0, nmAt: +u.nmAt || 0, ...extra
  };
}

function outPost(h, admin) {
  if (!h) return null;
  const o = {
    id: h.id, title: h.title || "", desc: h.desc || "", link: h.link || "", btn: h.btn || "",
    ldesc: h.ldesc || "", video: h.video || "", thumb: h.thumb || "",
    likes: Math.max(0, +h.likes || 0), views: Math.max(0, +h.views || 0),
    createdAt: +h.createdAt || 0, pinned: h.pinned === "1", pinnedAt: +h.pinnedAt || 0
  };
  try { o.links = h.links ? JSON.parse(h.links) : []; } catch (e) { o.links = []; }
  if (admin) o.hidden = h.hidden === "1";
  return o;
}

const ytId = u => {
  const m = (u || "").trim().match(/(?:youtu\.be\/|youtube\.com\/(?:watch\?(?:.*&)?v=|embed\/|shorts\/|live\/))([A-Za-z0-9_-]{11})/);
  return m ? m[1] : "";
};

async function getPosts(ids, admin) {
  if (!ids.length) return [];
  const rs = await pipe(ids.map(id => ["HGETALL", "p:" + id]));
  return rs.map((r, i) => {
    const h = toObj(r);
    if (!h) return null;
    h.id = ids[i];
    return outPost(h, admin);
  }).filter(Boolean);
}

async function renameUser(uid, from, to) {
  if (to === from) return;
  const ok = await cmd("SET", "un:" + to, uid, "NX");
  if (!ok) throw new E("taken", 409);
  if (from) await cmd("DEL", "un:" + from);
  await cmd("HSET", "u:" + uid, "username", to);
}

async function purgeUser(uid, u) {
  const c = [["DEL", "u:" + uid], ["DEL", "av:" + uid], ["ZREM", "users", uid]];
  if (u.username) c.push(["DEL", "un:" + u.username]);
  if (u.accountId) c.push(["DEL", "aid:" + u.accountId]);
  await pipe(c);
}

function cleanPost(b, needImgs) {
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
  if (b.thumb !== undefined && b.thumb !== null && b.thumb !== "") {
    if (typeof b.thumb !== "string" || !IMG_RE.test(b.thumb) || b.thumb.length > 300000) throw new E("badimg");
    out.thumb = b.thumb;
  } else if (b.thumb === "") out.thumb = "";
  if (b.cover) {
    if (typeof b.cover !== "string" || !IMG_RE.test(b.cover) || b.cover.length > 2000000) throw new E("badimg");
    out.cover = b.cover;
  }
  return out;
}

const H = {};

H.list = async ({q}) => {
  const sort = ["new", "old", "pop"].includes(q.sort) ? q.sort : "new";
  const cur = Math.max(0, parseInt(q.cursor, 10) || 0);
  const lim = Math.min(20, Math.max(1, parseInt(q.limit, 10) || 12));
  const key = sort === "pop" ? "z:pop" : "z:new";
  const rev = sort !== "old";
  const [ids, pins, members] = await pipe([
    [rev ? "ZREVRANGE" : "ZRANGE", key, cur, cur + lim - 1],
    ["ZREVRANGE", "z:pin", 0, -1],
    ["ZCARD", "users"]
  ]);
  const regular = ids.filter(id => !pins.includes(id));
  const want = cur === 0 ? [...pins, ...regular] : regular;
  return {posts: await getPosts(want, false), next: ids.length === lim ? cur + lim : null, members: members || 0};
};

H.post = async ({q, user}) => {
  const id = str(q.id, 40);
  if (!/^[0-9a-f]{12}$/.test(id)) throw new E("notfound", 404);
  const [p] = await getPosts([id], true);
  const adm = !!(user && user.admin);
  if (!p || (p.hidden && !adm)) throw new E("notfound", 404);
  if (!adm) delete p.hidden;
  return {post: p};
};

H.cover = async ({q}) => {
  const id = str(q.id, 40);
  if (!/^[0-9a-f]{12}$/.test(id)) throw new E("notfound", 404);
  const [d, hid] = await pipe([["GET", "cover:" + id], ["HGET", "p:" + id, "hidden"]]);
  if (!d || hid === "1") return {data: ""};
  return {data: d};
};

H.vid = async ({q, user}) => {
  const v = str(q.v, 20);
  if (!/^[\w-]{11}$/.test(v)) throw new E("notfound", 404);
  const id = await cmd("HGET", "h:vid", v);
  if (!id) throw new E("notfound", 404);
  const [p] = await getPosts([id], true);
  const adm = !!(user && user.admin);
  if (!p || (p.hidden && !adm)) throw new E("notfound", 404);
  if (!adm) delete p.hidden;
  return {post: p};
};

H.check = async ({q}) => {
  const u = str(q.u, 40).toLowerCase();
  if (!USER_RE.test(u)) throw new E("invalid");
  return {free: !(await cmd("EXISTS", "un:" + u))};
};

H.view = async ({q, user, ip}) => {
  const id = str(q.id, 40);
  if (!/^[0-9a-f]{12}$/.test(id)) throw new E("notfound", 404);
  const [hid, title, ok] = await pipe([
    ["HGET", "p:" + id, "hidden"], ["HGET", "p:" + id, "title"],
    ["SET", "vw:" + id + ":" + ipHash(ip), "1", "NX", "PX", "2000"]
  ]);
  if (title === null || (hid === "1" && !(user && user.admin))) throw new E("notfound", 404);
  if (!ok) {
    const v = await cmd("HGET", "p:" + id, "views");
    return {counted: false, views: +v || 0};
  }
  const rs = await pipe([["HINCRBY", "p:" + id, "views", 1], ["ZADD", "z:pop", "XX", "INCR", 1, id]]);
  return {counted: true, views: rs[0]};
};

H.liked = async ({q, user}) => {
  if (!user) return {liked: false};
  return {liked: (await cmd("SISMEMBER", "lk:" + str(q.id, 40), user.uid)) === 1};
};

H.like = async ({q, user}) => {
  if (!user) throw new E("login", 401);
  const id = str(q.id, 40);
  if (!/^[0-9a-f]{12}$/.test(id)) throw new E("notfound", 404);
  const [hid, title] = await pipe([["HGET", "p:" + id, "hidden"], ["HGET", "p:" + id, "title"]]);
  if (title === null || (hid === "1" && !user.admin)) throw new E("notfound", 404);
  const on = !!q.on;
  const ch = await cmd(on ? "SADD" : "SREM", "lk:" + id, user.uid);
  let likes;
  if (ch === 1) likes = await cmd("HINCRBY", "p:" + id, "likes", on ? 1 : -1);
  else likes = +(await cmd("HGET", "p:" + id, "likes")) || 0;
  if (likes < 0) { await cmd("HSET", "p:" + id, "likes", 0); likes = 0; }
  return {likes, liked: on};
};

H.register = async ({q, ip}) => {
  await limit("rl:r:" + ipHash(ip), 20, 3600);
  const u = str(q.u, 40).toLowerCase(), name = str(q.name, 30);
  if (!USER_RE.test(u)) throw new E("invalid");
  if (!name) throw new E("name");
  if (!strongEnough(q.p)) throw new E("weak");
  const uid = crypto.randomBytes(12).toString("hex");
  const ok = await cmd("SET", "un:" + u, uid, "NX");
  if (!ok) throw new E("taken", 409);
  let aid = "";
  for (let i = 0; i < 10 && !aid; i++) {
    const n = String(10000000 + crypto.randomInt(0, 90000000));
    if (await cmd("SET", "aid:" + n, uid, "NX")) aid = n;
  }
  if (!aid) {
    await cmd("DEL", "un:" + u);
    throw new E("idfail", 500);
  }
  const now = Date.now();
  await pipe([
    ["HSET", "u:" + uid, "username", u, "displayName", name, "accountId", aid, "pass", await hashPw(q.p), "createdAt", now, "sv", "0"],
    ["ZADD", "users", now, uid]
  ]);
  return {ok: true};
};

H.login = async ({q, ip}) => {
  const u = str(q.u, 40).toLowerCase(), p = typeof q.p === "string" ? q.p : "";
  await limit("rl:l:" + ipHash(ip), 30, 60);
  if (!USER_RE.test(u) || !p || p.length > 128) throw new E("invalid", 401);
  await limit("rl:lu:" + u, 10, 300);
  const uid = await cmd("GET", "un:" + u);
  const user = uid && (await loadUser(uid));
  if (!user || !(await checkPw(p, user.pass))) throw new E("invalid", 401);
  if (user.banned) throw new E("banned", 403);
  const rs = await pipe([["ZADD", "users", Date.now(), uid], ["GET", "av:" + uid]]);
  return {user: outUser(user, {avatar: rs[1] || ""}), cookie: makeCookie(uid, user.sv)};
};

H.logout = async ({user}) => {
  if (user) await cmd("ZADD", "users", 0, user.uid);
  return {ok: true, cookie: clearCookie()};
};

H.me = async ({q, user, req}) => {
  const c = readCookie(req);
  if (!user) {
    const u = c && (await loadUser(c.uid));
    if (u && u.banned) return {user: null, banned: true, cookie: clearCookie()};
    return {user: null, cookie: c ? clearCookie() : undefined};
  }
  if (user.banned) return {user: null, banned: true, cookie: clearCookie()};
  const rs = await pipe([["ZADD", "users", Date.now(), user.uid], ["ZCARD", "users"]].concat(q.full ? [["GET", "av:" + user.uid]] : []));
  return {user: outUser(user, q.full ? {avatar: rs[2] || ""} : {}), members: rs[1]};
};

H.verify = async ({q, user}) => {
  if (!user) throw new E("login", 401);
  await limit("rl:v:" + user.uid, 10, 300);
  if (!(await checkPw(typeof q.p === "string" ? q.p : "", user.pass))) throw new E("wrong", 403);
  return {ok: true};
};

H.psave = async ({q, user}) => {
  if (!user) throw new E("login", 401);
  const now = Date.now(), sets = [], cmds = [];
  const nu = q.username === undefined ? user.username : str(q.username, 40).toLowerCase();
  const nn = q.displayName === undefined ? user.displayName : str(q.displayName, 30);
  if (!nn) throw new E("name");
  if (nu !== user.username) {
    if (!USER_RE.test(nu)) throw new E("invalid");
    if (!user.admin && +user.unAt && now < +user.unAt + 14 * DAY) throw new E("locked", 403);
  }
  if (nn !== user.displayName && !user.admin && +user.nmAt && now < +user.nmAt + 7 * DAY) throw new E("locked", 403);
  let newPw = "";
  if (q.password) {
    if (!strongEnough(q.password)) throw new E("weak");
    if (!(await checkPw(typeof q.cur === "string" ? q.cur : "", user.pass))) throw new E("wrong", 403);
    if (q.password === q.cur) throw new E("same");
    newPw = q.password;
  }
  if (q.avatar && (typeof q.avatar !== "string" || !IMG_RE.test(q.avatar) || q.avatar.length > 120000)) throw new E("badimg");
  if (nu !== user.username) {
    await renameUser(user.uid, user.username, nu);
    sets.push("unAt", now);
  }
  if (nn !== user.displayName) {
    sets.push("displayName", nn);
    if (!user.admin) sets.push("nmAt", now);
  }
  let sv = user.sv;
  if (newPw) {
    sv = String((+user.sv || 0) + 1);
    sets.push("pass", await hashPw(newPw), "sv", sv);
  }
  if (sets.length) cmds.push(["HSET", "u:" + user.uid, ...sets]);
  if (q.avatar) cmds.push(["SET", "av:" + user.uid, q.avatar]);
  if (cmds.length) await pipe(cmds);
  const fresh = await loadUser(user.uid);
  const av = await cmd("GET", "av:" + user.uid);
  return {user: outUser(fresh, {avatar: av || ""}), cookie: newPw ? makeCookie(user.uid, sv) : undefined};
};

H.pdel = async ({q, user}) => {
  if (!user) throw new E("login", 401);
  if (user.admin) throw new E("admin", 403);
  await limit("rl:v:" + user.uid, 10, 300);
  if (!(await checkPw(typeof q.p === "string" ? q.p : "", user.pass))) throw new E("wrong", 403);
  await purgeUser(user.uid, user);
  return {ok: true, cookie: clearCookie()};
};

const needAdmin = user => {
  if (!user || !user.admin) throw new E("forbidden", 403);
};

H.plist = async ({q, user}) => {
  needAdmin(user);
  const cur = Math.max(0, parseInt(q.cursor, 10) || 0), lim = 20;
  const ids = await cmd("ZREVRANGE", "z:all", cur, cur + lim - 1);
  return {posts: await getPosts(ids, true), next: ids.length === lim ? cur + lim : null};
};

H.psavepost = async ({q, user}) => {
  needAdmin(user);
  const d = cleanPost(q);
  const editing = q.id ? str(q.id, 40) : "";
  const now = Date.now();
  if (editing) {
    if (!/^[0-9a-f]{12}$/.test(editing)) throw new E("notfound", 404);
    const old = toObj(await cmd("HGETALL", "p:" + editing));
    if (!old) throw new E("notfound", 404);
    const wasPinned = old.pinned === "1";
    const pinnedAt = d.pinned ? (wasPinned && +old.pinnedAt ? +old.pinnedAt : now) : 0;
    const set = ["title", d.title, "desc", d.desc, "link", d.link, "btn", d.btn, "links", JSON.stringify(d.links), "ldesc", d.ldesc, "video", d.video, "vid", d.vid];
    if (d.thumb !== undefined) set.push("thumb", d.thumb);
    const c = [["HSET", "p:" + editing, ...set]];
    if (d.pinned) c.push(["HSET", "p:" + editing, "pinned", "1", "pinnedAt", pinnedAt]);
    else c.push(["HDEL", "p:" + editing, "pinned", "pinnedAt"]);
    if (old.hidden !== "1") c.push(d.pinned ? ["ZADD", "z:pin", pinnedAt, editing] : ["ZREM", "z:pin", editing]);
    if (old.vid && old.vid !== d.vid) c.push(["HDEL", "h:vid", old.vid]);
    if (d.vid) c.push(["HSET", "h:vid", d.vid, editing]);
    if (d.cover) c.push(["SET", "cover:" + editing, d.cover]);
    await pipe(c);
    return {id: editing};
  }
  const id = crypto.randomBytes(6).toString("hex");
  const set = ["title", d.title, "desc", d.desc, "link", d.link, "btn", d.btn, "links", JSON.stringify(d.links), "ldesc", d.ldesc, "video", d.video, "vid", d.vid, "thumb", d.thumb || "", "likes", 0, "views", 0, "createdAt", now];
  if (d.pinned) set.push("pinned", "1", "pinnedAt", now);
  const c = [["HSET", "p:" + id, ...set], ["ZADD", "z:all", now, id], ["ZADD", "z:new", now, id], ["ZADD", "z:pop", 0, id]];
  if (d.pinned) c.push(["ZADD", "z:pin", now, id]);
  if (d.vid) c.push(["HSET", "h:vid", d.vid, id]);
  if (d.cover) c.push(["SET", "cover:" + id, d.cover]);
  await pipe(c);
  return {id};
};

H.phide = async ({q, user}) => {
  needAdmin(user);
  const id = str(q.id, 40);
  const h = /^[0-9a-f]{12}$/.test(id) ? toObj(await cmd("HGETALL", "p:" + id)) : null;
  if (!h) throw new E("notfound", 404);
  const hide = !!q.hidden;
  if (hide) {
    await pipe([["HSET", "p:" + id, "hidden", "1"], ["ZREM", "z:new", id], ["ZREM", "z:pop", id], ["ZREM", "z:pin", id]]);
  } else {
    const c = [["HDEL", "p:" + id, "hidden"], ["ZADD", "z:new", +h.createdAt || Date.now(), id], ["ZADD", "z:pop", +h.views || 0, id]];
    if (h.pinned === "1") c.push(["ZADD", "z:pin", +h.pinnedAt || Date.now(), id]);
    await pipe(c);
  }
  return {ok: true};
};

H.pdelpost = async ({q, user}) => {
  needAdmin(user);
  const id = str(q.id, 40);
  if (!/^[0-9a-f]{12}$/.test(id)) throw new E("notfound", 404);
  const vid = await cmd("HGET", "p:" + id, "vid");
  const c = [["DEL", "p:" + id], ["DEL", "cover:" + id], ["DEL", "lk:" + id], ["ZREM", "z:all", id], ["ZREM", "z:new", id], ["ZREM", "z:pop", id], ["ZREM", "z:pin", id]];
  if (vid) c.push(["HDEL", "h:vid", vid]);
  await pipe(c);
  return {ok: true};
};

H.ulist = async ({q, user}) => {
  needAdmin(user);
  const cur = Math.max(0, parseInt(q.cursor, 10) || 0), lim = 30;
  const flat = await cmd("ZREVRANGE", "users", cur, cur + lim - 1, "WITHSCORES");
  const ids = [], seen = [];
  for (let i = 0; i < flat.length; i += 2) { ids.push(flat[i]); seen.push(+flat[i + 1]); }
  const rs = await pipe(ids.map(id => ["HMGET", "u:" + id, "username", "displayName", "accountId", "banned"]));
  const users = ids.map((id, i) => ({
    id, username: rs[i][0] || "", displayName: rs[i][1] || "", accountId: rs[i][2] || "",
    banned: rs[i][3] === "1", lastSeen: seen[i]
  })).filter((u, i) => rs[i][0]);
  return {users, next: ids.length === lim ? cur + lim : null};
};

H.uban = async ({q, user}) => {
  needAdmin(user);
  const t = await loadUser(str(q.id, 40));
  if (!t) throw new E("notfound", 404);
  if (t.admin) throw new E("admin", 403);
  const ban = !!q.banned;
  await cmd("HSET", "u:" + t.uid, "banned", ban ? "1" : "0", "sv", String((+t.sv || 0) + 1));
  return {ok: true};
};

H.udel = async ({q, user}) => {
  needAdmin(user);
  const t = await loadUser(str(q.id, 40));
  if (!t) throw new E("notfound", 404);
  if (t.admin) throw new E("admin", 403);
  await purgeUser(t.uid, t);
  return {ok: true};
};

H.uedit = async ({q, user}) => {
  needAdmin(user);
  const t = await loadUser(str(q.id, 40));
  if (!t) throw new E("notfound", 404);
  const nu = q.username === undefined ? t.username : str(q.username, 40).toLowerCase();
  const nn = str(q.displayName, 30);
  if (!nn) throw new E("name");
  if (nu !== t.username && !USER_RE.test(nu)) throw new E("invalid");
  if (q.password && !strongEnough(q.password)) throw new E("weak");
  await renameUser(t.uid, t.username, nu);
  const sets = ["displayName", nn];
  if (q.password) sets.push("pass", await hashPw(q.password), "sv", String((+t.sv || 0) + 1));
  await cmd("HSET", "u:" + t.uid, ...sets);
  return {ok: true};
};

const GET_OK = new Set(["list", "post", "cover", "vid", "check"]);

module.exports = async (req, res) => {
  res.setHeader("Cache-Control", "no-store");
  const send = (code, body) => {
    const {cookie, ...rest} = body;
    if (cookie) res.setHeader("Set-Cookie", cookie);
    res.status(code).json(rest);
  };
  try {
    const isGet = req.method === "GET";
    if (!isGet && req.method !== "POST") throw new E("method", 405);
    if (!isGet) {
      const o = req.headers.origin;
      if (o) {
        let host = "";
        try { host = new URL(o).host; } catch (e) {}
        if (host !== req.headers.host) throw new E("origin", 403);
      }
    }
    const q = (isGet ? req.query : req.body) || {};
    const a = typeof q.a === "string" ? q.a : "";
    const fn = Object.prototype.hasOwnProperty.call(H, a) ? H[a] : null;
    if (!fn) throw new E("unknown", 404);
    if (isGet && !GET_OK.has(a)) throw new E("method", 405);
    if (!isGet && GET_OK.has(a)) throw new E("method", 405);
    const user = await authUser(req);
    if (user && user.banned && a !== "me" && a !== "logout") throw new E("banned", 403);
    send(200, await fn({q, user, req, ip: clientIp(req)}));
  } catch (e) {
    if (e instanceof E) return send(e.status, {error: e.code});
    send(500, {error: "server"});
  }
};
