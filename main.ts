// Deno Deploy — بوابة متابعة جاهزية المدارس
// نقطة دخول واحدة: توجيه /api/* + خدمة الواجهة، والتخزين عبر Deno KV المدمج
import { MOE_LOGO, plans, secrets, sectors } from "./data.js";

// حساب "المؤشرات غير المصنّفة": وجهة افتراضية يوجّه إليها المدير المؤشرات التي لا تخصّ أي جهة.
// تُستبعد من احتساب النسبة الكلية، والمدير وحده يوزّعها لاحقاً.
const UNCLASSIFIED_ID = "__UNCLASSIFIED__";
if (!plans[UNCLASSIFIED_ID]) {
  plans[UNCLASSIFIED_ID] = { name: "مؤشرات غير مصنّفة", items: [], unclassifiedBucket: true };
}

// فتح KV بمرونة: لا يُسقط التطبيق لو لم تُربَط قاعدة بعد
let kvPromise = null;
async function getKv() {
  if (!kvPromise) kvPromise = Deno.openKv();
  return await kvPromise;
}
const enc = new TextEncoder();

// ===== helpers =====
async function sha256(str) {
  const buf = await crypto.subtle.digest("SHA-256", enc.encode(str));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
async function sign(payload) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secrets.session_secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["sign"],
  );
  const data = btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  const sigHex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return data + "." + sigHex;
}
async function verifyToken(token) {
  if (!token || !token.includes(".")) return null;
  const [data, sigHex] = token.split(".");
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secrets.session_secret),
    { name: "HMAC", hash: "SHA-256" }, false, ["verify"],
  );
  const sigBytes = new Uint8Array(sigHex.match(/.{2}/g).map((b) => parseInt(b, 16)));
  const ok = await crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(data));
  if (!ok) return null;
  let payload;
  try { payload = JSON.parse(decodeURIComponent(escape(atob(data)))); } catch { return null; }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload;
}
function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status, headers: { "Content-Type": "application/json; charset=utf-8" },
  });
}
function bearer(request) {
  const a = request.headers.get("authorization") || "";
  return a.startsWith("Bearer ") ? a.slice(7) : "";
}
// ===== سجلّ الحركات (Audit Log) =====
// يسجّل كل إجراء مؤثّر: من قام به، ونوعه، وتفاصيله، ووقته
async function logAction(kv, actor, action, detail) {
  try {
    const now = new Date().toISOString();
    const id = now + "_" + Math.random().toString(36).slice(2, 8);
    await kv.set(["audit", id], { at: now, actor, action, detail: detail || "" });
  } catch (_e) { /* لا نُفشل العملية الأصلية بسبب فشل التسجيل */ }
}
// من هو الفاعل (للسجلّ)
function actorOf(p) {
  if (!p) return "غير معروف";
  if (p.role === "sysadmin") return "أدمن النظام";
  if (p.role === "admin") return "مدير عام شؤون المدارس";
  if (p.sid) return "منسّق قطاع:" + p.sid;
  if (p.eid) return "إدارة:" + p.eid;
  return "غير معروف";
}
// ===== طبقة الأكواد الديناميكية (يديرها أدمن النظام في KV) =====
// مفتاح: ["userCode", hash] -> { role, sid?, eid?, disabled, label, createdAt }
async function lookupDynamicCode(kv, hash) {
  try {
    const rec = (await kv.get(["userCode", hash])).value;
    if (rec && !rec.disabled) return rec;
  } catch (_e) {}
  return null;
}
// ===== السنوات الدراسية (أرشيف حقيقي) =====
// السنة الدراسية تبدأ في سبتمبر. الصيغة "2025-2026".
function currentSchoolYear() {
  const now = new Date();
  const y = now.getMonth() >= 8 ? now.getFullYear() : now.getFullYear() - 1;
  const base = 2025;
  const start = Math.max(base, y); // لا تسبق 2025
  return start + "-" + (start + 1);
}
// حساب مدى التأخّر: يحوّل حقل "إلى" (اسم شهر عربي) لتاريخ استحقاق ضمن السنة الدراسية، ويقارنه باليوم
// يُرجع {days, weeks, remDays, label, computable, targetText}
const AR_MONTHS = { "سبتمبر": 9, "أكتوبر": 10, "اكتوبر": 10, "نوفمبر": 11, "ديسمبر": 12, "يناير": 1, "فبراير": 2, "مارس": 3, "أبريل": 4, "ابريل": 4, "مايو": 5, "يونيو": 6, "يوليو": 7, "أغسطس": 8, "اغسطس": 8 };
// السنة المستثناة من احتساب التأخير (فُعّلت المنصة بعد انتهائها)
const NO_DELAY_YEAR = "2025-2026";
function delayInfo(toText, year, refNow) {
  const t = (toText || "").trim();
  const yr = year || currentSchoolYear();
  // استثناء: السنة الأكاديمية الماضية لا يُحسب عليها تأخير (المنصة فُعّلت بعد انتهائها)
  if (yr === NO_DELAY_YEAR) return { computable: false, label: "—", targetText: t, exempt: true };
  const startYear = +yr.split("-")[0];
  const mo = AR_MONTHS[t];
  if (!mo) return { computable: false, label: t || "—", targetText: t || "—" };
  const calYear = mo >= 9 ? startYear : startYear + 1;
  const due = new Date(calYear, mo, 0);
  const now = refNow || new Date(); // دائماً بتاريخ اليوم الفعلي
  const diffMs = now - due;
  if (diffMs <= 0) return { computable: true, days: 0, weeks: 0, remDays: 0, label: "ضمن الموعد", targetText: t, due: due.toISOString().slice(0, 10) };
  const days = Math.floor(diffMs / 86400000);
  const weeks = Math.floor(days / 7);
  const remDays = days % 7;
  let label = "";
  if (weeks > 0) label += weeks + " أسبوع";
  if (remDays > 0) label += (label ? " و" : "") + remDays + " يوم";
  if (!label) label = "أقل من يوم";
  return { computable: true, days, weeks, remDays, label, targetText: t, due: due.toISOString().slice(0, 10) };
}
function schoolYears() {
  const cur = +currentSchoolYear().split("-")[0];
  const base = 2025;
  const shift = Math.max(0, Math.floor((cur - base) / 2) * 2);
  const first = base + shift;
  const ys = [];
  for (let k = 0; k < 5; k++) ys.push((first + k) + "-" + (first + k + 1));
  return ys;
}
// استخرج السنة المطلوبة من الطلب (query أو body)؛ الافتراضي = السنة الحالية
function reqYear(request, body) {
  let y = null;
  try { y = new URL(request.url).searchParams.get("year"); } catch (_) {}
  if (!y && body && body.year) y = body.year;
  if (!y || !/^\d{4}-\d{4}$/.test(y)) return currentSchoolYear();
  return y;
}
// هل هذه السنة قابلة للتعديل؟ (السنة الحالية فقط)
// قابلة للتعديل: السنة الحالية، أو السنة التالية لها مباشرة (تحضير مسبق لسنة واحدة قادمة فقط)
function nextSchoolYear() {
  const cur = +currentSchoolYear().split("-")[0];
  return (cur + 1) + "-" + (cur + 2);
}
// السنة ضمن نافذة التعديل المسموح بها هيكلياً: السنة الحالية أو أي سنة مستقبلية ضمن النافذة (٥ سنوات)
// المدير يحضّر أي سنة مستقبلية ويفتحها يدوياً للجهات
function yearEditable(y) {
  const cur = currentSchoolYear();
  if (y === cur) return true;
  return y > cur && schoolYears().includes(y); // أي سنة مستقبلية ضمن النافذة
}
// هل فتح المدير هذه السنة القادمة للقطاعات والإدارات؟ (السنة الحالية مفتوحة دائماً)
async function yearOpened(kv, year) {
  if (year === currentSchoolYear()) return true;
  try { return !!(await kv.get(["yearOpen", year])).value; } catch { return false; }
}
// صلاحية التعديل الفعلية حسب الدور: المدير يعدّل السنة القادمة دائماً (تحضير مسبق)؛
// القطاعات والإدارات لا تعدّلها إلا بعد أن يفتحها المدير
async function effectiveEditable(kv, year, isAdmin) {
  if (!yearEditable(year)) return false;
  if (isAdmin) return true;
  return await yearOpened(kv, year);
}

function canAccess(p, eid) {
  if (p.role === "admin") return true;                 // المشرف يصل ويعدّل أي جهة
  if (p.eid) return p.eid === eid;
  if (p.sid) return (sectors[p.sid]?.entity_ids || []).includes(eid);
  return false;
}
// من يحق له كتابة تعليق على جهة: المشرف، أو منسق قطاعها
function canComment(p, eid) {
  if (p.role === "admin") return true;
  if (p.sid) return (sectors[p.sid]?.entity_ids || []).includes(eid);
  if (p.eid) return p.eid === eid; // الإدارة تعلّق على مؤشراتها (نقطة 6)
  return false;
}
function whoLabel(p) {
  if (p.role === "admin") return "مدير عام شؤون المدارس";
  if (p.sid) return "منسق " + (sectors[p.sid]?.name || "القطاع");
  if (p.eid) return plans[p.eid]?.name || "الجهة";
  return "الجهة";
}
function statusOf(it, u) {
  if (!u || u.v === "" || u.v === undefined || u.v === null) {
    // عدد-إنجاز: احسب من المرجعي والمنجز
    if (it.measure === "عدد-إنجاز" && u && u.ref) {
      const pct = Math.round((+u.done || 0) / (+u.ref || 1) * 100);
      return pct >= 100 ? "مكتمل" : pct >= 50 ? "قيد التنفيذ" : pct > 0 ? "متأخر" : "لم يبدأ";
    }
    return "لم يبدأ";
  }
  if (it.measure === "نسبة") { const p = +u.v; return p >= 100 ? "مكتمل" : p >= 50 ? "قيد التنفيذ" : p > 0 ? "متأخر" : "لم يبدأ"; }
  if (it.measure === "عدد") return +u.v > 0 ? "منجز" : "لم يبدأ";
  if (it.measure === "عدد-إنجاز") {
    const pct = Math.round((+u.done || 0) / (+u.ref || 1) * 100);
    return pct >= 100 ? "مكتمل" : pct >= 50 ? "قيد التنفيذ" : pct > 0 ? "متأخر" : "لم يبدأ";
  }
  return u.v;
}
// نسبة مؤشر عدد-إنجاز
function pctOf(it, u) {
  if (it.measure === "عدد-إنجاز" && u) return Math.min(100, Math.round((+u.done || 0) / (+u.ref || 1) * 100));
  if (it.measure === "نسبة" && u) return +u.v || 0;
  return null;
}

// ===== endpoint handlers =====
async function handleLogin(request) {
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const code = (body.code || "").trim().toUpperCase();
  if (!code) return json({ error: "الرمز مطلوب" }, 400);
  const h = await sha256(code);
  const exp = Date.now() + 8 * 3600 * 1000;
  // أدمن النظام (دور فنّي منفصل)
  if (secrets.sysadmin_hash && h === secrets.sysadmin_hash) {
    try { const kv = await getKv(); await logAction(kv, "أدمن النظام", "login", "دخول أدمن النظام"); } catch (_e) {}
    return json({ role: "sysadmin", token: await sign({ role: "sysadmin", exp }) });
  }
  if (h === secrets.admin_hash) return json({ role: "admin", token: await sign({ role: "admin", exp }) });
  let sid = secrets.sector_hash[h];
  let eid = secrets.code_hash[h];
  // طبقة الأكواد الديناميكية في KV (يديرها أدمن النظام) — تعمل بالتوازي مع المدمجة
  if (!sid && !eid && h !== secrets.admin_hash) {
    try {
      const kv = await getKv();
      const dyn = await lookupDynamicCode(kv, h);
      if (dyn) {
        if (dyn.role === "admin") return json({ role: "admin", token: await sign({ role: "admin", exp }) });
        if (dyn.role === "sector" && dyn.sid) sid = dyn.sid;
        else if (dyn.role === "entity" && dyn.eid) eid = dyn.eid;
      }
    } catch (_e) {}
  }
  if (sid) {
    const sec = sectors[sid];
    if (!sec) return json({ error: "قطاع غير معروف" }, 401);
    const list = sec.entity_ids.map((eid) => ({ id: eid, name: plans[eid].name, count: plans[eid].items.length }));
    return json({ role: "sector", token: await sign({ sid, exp }), sector: { id: sid, name: sec.name, entities: list } });
  }
  if (!eid) return json({ error: "رمز الدخول غير صحيح" }, 401);
  const plan = plans[eid];
  if (!plan) return json({ error: "إدارة غير معروفة" }, 401);
  return json({ role: "entity", token: await sign({ eid, exp }), entity: { id: eid, name: plan.name, items: plan.items } });
}

async function handleEntity(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  const eid = new URL(request.url).searchParams.get("eid");
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  if (!canAccess(p, eid)) return json({ error: "غير مصرح" }, 403);
  const year = reqYear(request);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة — اربطها من Databases ثم أعد النشر" }, 503); }
  const editableYear = await effectiveEditable(kv, year, p.role === "admin");
  const yearIsOpen = await yearOpened(kv, year);
  const res = await kv.get(["plan", year, eid]);
  const rec = res.value;
  const cres = await kv.get(["comments", year, eid]);
  const rawComments = cres.value || { general: [], items: {} };
  // أضف أعلاماً لكل ملاحظة: mine (لي)، canEdit (يمكن تعديلها)، edited (عُدّلت)
  const myLabel2 = whoLabel(p);
  const myRole2 = p.role === "admin" ? "admin" : p.sid ? "sector" : "entity";
  const isSys2 = p.role === "sysadmin";
  const annotate = (thread) => (thread || []).map((c) => {
    const mine = c.by === myLabel2 && c.role === myRole2;
    const replied = commentHasReply(thread, c);
    return { ...c, mine, hasReply: replied, canEdit: isSys2 || (mine && !replied && editableYear), edited: !!c.editedAt };
  });
  const comments = { general: annotate(rawComments.general), items: {} };
  for (const k of Object.keys(rawComments.items || {})) comments.items[k] = annotate(rawComments.items[k]);
  const ov = (await kv.get(["overrides", year, eid])).value || { edits: {}, added: [], deleted: [], delReq: [] };
  const docs = ((await kv.get(["docs", year, eid])).value || []).map((d) => ({ id: d.id, name: d.name, by: d.by, at: d.at, approved: d.approved, approvedBy: d.approvedBy, approvedAt: d.approvedAt }));
  const justify = (await kv.get(["justify", year, eid])).value || {};
  const locked = await sectorLocked(kv, eid, year);
  // السنوات المنتهية للقراءة فقط
  const canFullEdit = editableYear && canEditIndicators(p, eid) && (p.role === "admin" || !locked);
  // احسب علامة "خلف الجدول الزمني" لكل مؤشر: تجاوز تاريخ "إلى" ولم يكتمل (زمني، يحترم استثناء السنة)
  const updatesForFlag = rec ? (rec.updates || {}) : {};
  const nowRef = new Date();
  const pendingE = ov.pendingEdits || {};
  const itemsMerged = mergedItems(eid, ov).map((it) => {
    const st = statusOf(it, updatesForFlag[it._idx]);
    const completed = ["مكتمل", "منجز", "تم"].includes(st);
    let behindSchedule = false, delayLabel = "";
    if (!completed) {
      const di = delayInfo(it.to, year, nowRef);
      if (di.computable && di.days > 0) { behindSchedule = true; delayLabel = di.label; }
    }
    const pe = pendingE[String(it._idx)];
    return { ...it, behindSchedule, delayLabel, ...(pe ? { pendingEdit: { fields: pe.fields, by: pe.by, at: pe.at } } : {}) };
  });
  return json({
    year, currentYear: currentSchoolYear(), nextYear: nextSchoolYear(), years: schoolYears(), editableYear,
    yearIsOpen, canOpenYears: p.role === "admin", yearInWindow: yearEditable(year),
    entity: { id: eid, name: plans[eid].name, items: itemsMerged },
    updates: rec ? (rec.updates || {}) : {},
    times: rec ? (rec.times || {}) : {},
    savedAt: rec ? rec.savedAt : null,
    comments,
    docs,
    justify,
    delReq: ov.delReq || [],
    xferReq: ov.xferReq || [],
    locked,
    canComment: editableYear && canComment(p, eid),
    canEdit: editableYear,
    canEditText: canFullEdit,
    canEditMeasure: canFullEdit,
    canEditPeriod: canFullEdit,
    canAddIndicator: canFullEdit,
    canDelete: canFullEdit,
    canJustify: editableYear && canComment(p, eid),
    isAdmin: p.role === "admin",
    isSector: !!p.sid,
    isEntity: !!p.eid,
    canRequestTransfer: editableYear && !!(p.eid === eid || (p.sid && (sectors[p.sid]?.entity_ids || []).includes(eid))) && !locked,
    canRequestEdit: editableYear && !!p.eid && p.eid === eid && !locked,
    canUpload: editableYear && canUpload(p, eid),
    canApproveDocs: editableYear && p.role === "admin",
    allAxes: collectAllAxes(),
    entityCatalog: entityCatalog(),
    entityDone: (await kv.get(["entityDone", year])).value?.[eid] || null,
    pendingEdits: ov.pendingEdits || {},
  });
}
// قائمة كل الإدارات مجمّعة حسب القطاع (لمنتقي وجهة التحويل)
let _catCache = null;
function entityCatalog() {
  if (_catCache) return _catCache;
  const out = [];
  for (const sid of Object.keys(sectors)) {
    for (const eid of (sectors[sid].entity_ids || [])) {
      if (plans[eid]) out.push({ id: eid, name: plans[eid].name, sector: sectors[sid].name, sid });
    }
  }
  // حساب المؤشرات غير المصنّفة — يظهر كوجهة للمدير فقط
  out.push({ id: UNCLASSIFIED_ID, name: "مؤشرات غير مصنّفة", sector: "غير مصنّف", sid: null, adminOnly: true, bucket: true });
  _catCache = out;
  return _catCache;
}
// جمع كل أسماء المحاور المستخدمة عبر المنصّة (لقوائم اختيار المحور)
let _axesCache = null;
function collectAllAxes() {
  if (_axesCache) return _axesCache;
  const set = new Set();
  for (const eid of Object.keys(plans)) {
    for (const it of plans[eid].items) { const a = (it.axis || "").trim(); if (a) set.add(a); }
  }
  _axesCache = [...set].sort((a, b) => a.localeCompare(b, "ar"));
  return _axesCache;
}

// إضافة تعليق: عام (scope=general) أو على مؤشر (scope=item, index=i)
async function handleComment(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const eid = body.eid;
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  if (!canComment(p, eid)) return json({ error: "غير مصرح بالتعليق" }, 403);
  const year = reqYear(request, body);
  if (!yearEditable(year)) return json({ error: "السنة الدراسية " + year + " مؤرشفة للقراءة فقط" }, 423);
  const text = (body.text || "").toString().trim().slice(0, 1000);
  if (!text) return json({ error: "التعليق فارغ" }, 400);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة — اربطها من Databases ثم أعد النشر" }, 503); }
  if (!(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد من مدير عام شؤون المدارس" }, 423);
  const cres = await kv.get(["comments", year, eid]);
  const comments = cres.value || { general: [], items: {} };
  const myRole = p.role === "admin" ? "admin" : p.sid ? "sector" : "entity";
  // منع التعليق على مؤشر منقول لجهة أخرى
  if (body.scope === "item" && Number.isInteger(body.index)) {
    const ovC = (await kv.get(["overrides", year, eid])).value || {};
    if ((ovC.transferred || {})[String(body.index)]) return json({ error: "لا يمكن التعليق على مؤشر مُحوَّل إلى جهة أخرى" }, 423);
  }
  // معرّف فريد للتعليق + معرّف الأصل عند الرد (للتشعّب)
  const cid = crypto.randomUUID();
  const replyTo = body.replyTo || null;
  const entry = { id: cid, text, by: whoLabel(p), role: myRole, replyTo, at: new Date().toISOString() };
  let priorThread = [];
  if (body.scope === "item" && Number.isInteger(body.index)) {
    const k = String(body.index);
    priorThread = (comments.items[k] || []).slice();
    (comments.items[k] = comments.items[k] || []).push(entry);
  } else {
    priorThread = comments.general.slice();
    comments.general.push(entry);
  }
  await kv.set(["comments", year, eid], comments);
  await pushNotify(kv, eid, "comment", "ملاحظة جديدة: " + text.slice(0, 60), body.scope === "item" ? body.index : null, p, ["sector", "entity"], year);
  // إشعار "رد على ملاحظتك": إن كان رداً مباشراً، أشعِر صاحب الأصل؛ وإلا أشعِر كل من علّق سابقاً
  if (replyTo) {
    const parent = priorThread.find((c) => c.id === replyTo);
    if (parent && parent.role && parent.role !== myRole) {
      await pushNotify(kv, eid, "reply", "تم الرد على ملاحظتك: " + text.slice(0, 55), body.scope === "item" ? body.index : null, p, [parent.role], year);
    }
  } else {
    const priorRoles = new Set(priorThread.map((c) => c.role).filter(Boolean));
    priorRoles.delete(myRole);
    for (const r of priorRoles) {
      await pushNotify(kv, eid, "reply", "تم الرد على ملاحظتك: " + text.slice(0, 55), body.scope === "item" ? body.index : null, p, [r], year);
    }
  }
  // أرجِع الملاحظات مع أعلام التعديل (ليظهر زر التعديل فوراً لصاحبها)
  const myLabelC = whoLabel(p);
  const myRoleC = p.role === "admin" ? "admin" : p.sid ? "sector" : "entity";
  const isSysC = p.role === "sysadmin";
  const annC = (thread) => (thread || []).map((c) => {
    const mine = c.by === myLabelC && c.role === myRoleC;
    const replied = commentHasReply(thread, c);
    return { ...c, mine, hasReply: replied, canEdit: isSysC || (mine && !replied && yearEditable(year)), edited: !!c.editedAt };
  });
  const annotated = { general: annC(comments.general), items: {} };
  for (const k of Object.keys(comments.items || {})) annotated.items[k] = annC(comments.items[k]);
  return json({ ok: true, comments: annotated });
}
// القاعدة: مردود عليها إذا وُجد تعليق يشير إليها عبر replyTo، أو تعليق لاحق في نفس السلسلة
function commentHasReply(thread, c) {
  if (!c) return false;
  const cTime = new Date(c.at || 0).getTime();
  return thread.some((x) => x.id !== c.id && (x.replyTo === c.id || new Date(x.at || 0).getTime() > cTime));
}
// تعديل ملاحظة: صاحبها فقط وقبل الرد عليها؛ أدمن النظام يعدّل أي ملاحظة أي وقت
async function handleCommentEdit(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body; try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const eid = body.eid;
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  const year = reqYear(request, body);
  const cid = body.id;
  const newText = (body.text || "").toString().trim().slice(0, 1000);
  if (!cid) return json({ error: "معرّف الملاحظة مطلوب" }, 400);
  if (!newText) return json({ error: "النص فارغ" }, 400);
  let kv; try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  const isSys = p.role === "sysadmin";
  // أدمن النظام يتجاوز قفل السنة أيضاً
  if (!isSys && !(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " غير متاحة للتعديل" }, 423);
  const cres = await kv.get(["comments", year, eid]);
  const comments = cres.value || { general: [], items: {} };
  // ابحث عن الملاحظة في العام أو في سلاسل المؤشرات
  let thread = null, entry = null;
  const gi = comments.general.findIndex((c) => c.id === cid);
  if (gi >= 0) { thread = comments.general; entry = comments.general[gi]; }
  else {
    for (const k of Object.keys(comments.items || {})) {
      const idx = comments.items[k].findIndex((c) => c.id === cid);
      if (idx >= 0) { thread = comments.items[k]; entry = comments.items[k][idx]; break; }
    }
  }
  if (!entry) return json({ error: "الملاحظة غير موجودة" }, 404);
  const myLabel = whoLabel(p);
  const myRole = p.role === "admin" ? "admin" : p.sid ? "sector" : "entity";
  if (!isSys) {
    // يجب أن يكون صاحب الملاحظة
    if (!(entry.by === myLabel && entry.role === myRole)) return json({ error: "لا يمكنك تعديل ملاحظة غيرك" }, 403);
    // ممنوع بعد الرد عليها
    if (commentHasReply(thread, entry)) return json({ error: "لا يمكن التعديل بعد الرد على الملاحظة" }, 423);
  }
  entry.text = newText;
  entry.editedAt = new Date().toISOString();
  entry.editedBy = isSys ? "أدمن النظام" : myLabel;
  await kv.set(["comments", year, eid], comments);
  await logAction(kv, actorOf(p), "comment-edit", "تعديل ملاحظة في " + plans[eid].name + (isSys ? " (أدمن)" : ""));
  // أرجِع مع الأعلام
  const annE = (thread) => (thread || []).map((c) => {
    const mine = c.by === myLabel && c.role === myRole;
    const replied = commentHasReply(thread, c);
    return { ...c, mine, hasReply: replied, canEdit: isSys || (mine && !replied && yearEditable(year)), edited: !!c.editedAt };
  });
  const annotatedE = { general: annE(comments.general), items: {} };
  for (const k of Object.keys(comments.items || {})) annotatedE.items[k] = annE(comments.items[k]);
  return json({ ok: true, comments: annotatedE });
}

async function handleSave(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const eid = body.eid;
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  if (!canAccess(p, eid)) return json({ error: "غير مصرح" }, 403);
  const year = reqYear(request, body);
  if (!yearEditable(year)) return json({ error: "السنة الدراسية " + year + " مؤرشفة للقراءة فقط — لا يمكن الحفظ" }, 423);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة — اربطها من Databases ثم أعد النشر" }, 503); }
  if (!(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد من مدير عام شؤون المدارس" }, 423);
  if (p.role !== "admin" && await sectorLocked(kv, eid, year)) {
    return json({ error: "التقرير معتمد ومقفل — يلزم تصريح المدير للتعديل" }, 423);
  }
  // قفل إعلان انتهاء الإدارة: الإدارة نفسها لا تعدّل حتى يُعاد الفتح (المدير/المنسّق يعدّلان)
  if (!p.sid && p.role !== "admin" && await entityDoneLocked(kv, eid, year)) {
    return json({ error: "أعلنت الإدارة انتهاء استعدادها والتقرير مقفل — يلزم إعادة الفتح من المنسّق أو المدير للتعديل" }, 423);
  }
  const prev = (await kv.get(["plan", year, eid])).value || { updates: {}, times: {} };
  const prevUpdates = prev.updates || {};
  const times = prev.times || {};
  const now = new Date().toISOString();
  const newUpdates = body.updates || {};
  // منع تعديل قيمة أي مؤشر منقول لجهة أخرى (مقفول تماماً حتى يعود)
  const ovLock = (await kv.get(["overrides", year, eid])).value || {};
  const transferredIdx = ovLock.transferred || {};
  for (const k of Object.keys(newUpdates)) {
    if (transferredIdx[String(k)] && JSON.stringify(newUpdates[k]) !== JSON.stringify(prevUpdates[k])) {
      return json({ error: "لا يمكن تعديل مؤشر مُحوَّل إلى جهة أخرى" }, 423);
    }
  }
  const changed = [];
  Object.keys(newUpdates).forEach((k) => {
    if (JSON.stringify(newUpdates[k]) !== JSON.stringify(prevUpdates[k])) { times[k] = now; changed.push(k); }
  });
  const record = {
    eid, updates: newUpdates, times, savedAt: now,
    by: p.role === "admin" ? "admin" : p.sid ? ("sector:" + p.sid) : ("entity:" + eid),
  };
  await kv.set(["plan", year, eid], record);
  const ov = (await kv.get(["overrides", year, eid])).value || {};
  const items = mergedItems(eid, ov);
  for (const k of changed) {
    const it = items.find((x) => String(x._idx) === String(k));
    if (it && statusOf(it, newUpdates[k]) === "متأخر") {
      await pushNotify(kv, eid, "delay", "تأخّر في تنفيذ مؤشر: " + (it.proc || "").slice(0, 50), +k, p, ["sector", "entity"], year);
    }
  }
  await logAction(kv, actorOf(p), "save", "حفظ مؤشرات إدارة " + (plans[eid] ? plans[eid].name : eid) + " (سنة " + year + ")");
  return json({ ok: true, savedAt: record.savedAt, times });
}

// تعديل صياغة مؤشر / إضافة مؤشر جديد (المدير العام لأي إدارة، المنسق لإداراته)
function canEditIndicators(p, eid) {
  if (p.role === "admin") return true;
  if (p.sid) return (sectors[p.sid]?.entity_ids || []).includes(eid);
  return false;
}
// هل قطاع الجهة مقفل (معتمد ولم يُصرَّح بالتعديل)؟
async function sectorLocked(kv, eid, year) {
  const sid = sectorOfEntity(eid);
  if (!sid) return false;
  const subs = (await kv.get(["reportSubs", year || currentSchoolYear()])).value || {};
  const s = subs[sid];
  return !!(s && s.status === "approved" && !s.unlocked);
}
// هل الإدارة مقفلة بسبب إعلان انتهاء استعدادها (لم تُفتح بعد)؟
async function entityDoneLocked(kv, eid, year) {
  const store = (await kv.get(["entityDone", year || currentSchoolYear()])).value || {};
  const e = store[eid];
  return !!(e && e.status === "done" && e.locked);
}
function sectorOfEntity(eid) {
  for (const sid in sectors) if ((sectors[sid].entity_ids || []).includes(eid)) return sid;
  return null;
}

// ========== نظام التعاميم المُوجّهة ==========
// تخزين: ["announce", id] = {id,text,level,audience,sectors[],entities[],inclEntities,active,expiresAt,by,at}
// audience: "all" | "sectors" | "entities"
function annVisibleTo(ann, p) {
  if (!ann || ann.active === false) return false;
  if (ann.expiresAt && Date.now() > new Date(ann.expiresAt).getTime()) return false;
  const aud = ann.audience || "all";
  if (aud === "all") return true;
  // المدير وأدمن النظام يريان كل التعاميم النشطة (للمتابعة)
  if (p.role === "admin" || p.role === "sysadmin") return true;
  if (aud === "sectors") {
    const list = ann.sectors || [];
    if (p.sid) return list.includes(p.sid);
    if (p.eid) { // إدارة: تُشمَل فقط إذا كان القطاع مستهدفاً وخيار «شامل الإدارات» مفعّل
      const sid = sectorOfEntity(p.eid);
      return ann.inclEntities && list.includes(sid);
    }
    return false;
  }
  if (aud === "entities") {
    const list = ann.entities || [];
    if (p.eid) return list.includes(p.eid);
    // المنسّق يرى تعميم إدارة إن كانت ضمن قطاعه (ليتابع ما يخصّ إداراته)
    if (p.sid) { const sec = sectors[p.sid]; return sec && (sec.entity_ids || []).some((e) => list.includes(e)); }
    return false;
  }
  return false;
}
async function listActiveAnnouncements(kv) {
  const out = [];
  for await (const e of kv.list({ prefix: ["announce"] })) {
    if (e.value) out.push(e.value);
  }
  // الأحدث أولاً
  out.sort((a, b) => new Date(b.at || 0) - new Date(a.at || 0));
  return out;
}
// جلب التعاميم الظاهرة لمستخدم (تُستدعى من نقاط الدخول للشاشات)
async function announcementsFor(kv, p) {
  const all = await listActiveAnnouncements(kv);
  return all.filter((a) => annVisibleTo(a, p)).map((a) => ({ id: a.id, text: a.text, level: a.level || "info", at: a.at, expiresAt: a.expiresAt || null }));
}
// جلب التعاميم الظاهرة للمستخدم الحالي (لأي دور)
async function handleMyAnnouncements(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ ok: true, rows: [] });
  let kv; try { kv = await getKv(); } catch { return json({ ok: true, rows: [] }); }
  const rows = await announcementsFor(kv, p);
  return json({ ok: true, rows });
}
// إدارة التعاميم (الأدمن + المدير العام)
async function handleAnnounce(request) {
  const p = await verifyToken(bearer(request));
  if (!p || !(p.role === "admin" || p.role === "sysadmin")) return json({ error: "إدارة التعاميم للمدير العام وأدمن النظام فقط" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  const action = body.action || "list";
  let kv; try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }

  if (action === "list") {
    const all = await listActiveAnnouncements(kv);
    const secList = Object.keys(sectors).map((sid) => ({ id: sid, name: sectors[sid].name }));
    const entList = Object.keys(plans).map((eid) => ({ id: eid, name: plans[eid].name }));
    return json({ ok: true, rows: all, sectors: secList, entities: entList });
  }
  if (action === "save") {
    // إنشاء أو تعديل
    const id = body.id || crypto.randomUUID();
    const text = (body.text || "").toString().trim().slice(0, 500);
    if (!text) return json({ error: "نص التعميم مطلوب" }, 400);
    const level = ["info", "important", "urgent"].includes(body.level) ? body.level : "info";
    const audience = ["all", "sectors", "entities"].includes(body.audience) ? body.audience : "all";
    const existing = (await kv.get(["announce", id])).value || {};
    const ann = {
      id, text, level, audience,
      sectors: Array.isArray(body.sectors) ? body.sectors.filter((s) => sectors[s]) : [],
      entities: Array.isArray(body.entities) ? body.entities.filter((e) => plans[e]) : [],
      inclEntities: !!body.inclEntities,
      active: body.active === undefined ? true : !!body.active,
      expiresAt: body.expiresAt || null,
      by: existing.by || actorOf(p),
      at: existing.at || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    await kv.set(["announce", id], ann);
    await logAction(kv, actorOf(p), "announce-save", "تعميم: " + text.slice(0, 40) + " (" + audience + ")");
    return json({ ok: true, id, announcement: ann });
  }
  if (action === "toggle") {
    const id = body.id; if (!id) return json({ error: "id مطلوب" }, 400);
    const ann = (await kv.get(["announce", id])).value;
    if (!ann) return json({ error: "التعميم غير موجود" }, 404);
    ann.active = !ann.active; ann.updatedAt = new Date().toISOString();
    await kv.set(["announce", id], ann);
    await logAction(kv, actorOf(p), "announce-toggle", (ann.active ? "تفعيل" : "إيقاف") + " تعميم");
    return json({ ok: true, active: ann.active });
  }
  if (action === "delete") {
    const id = body.id; if (!id) return json({ error: "id مطلوب" }, 400);
    await kv.delete(["announce", id]);
    await logAction(kv, actorOf(p), "announce-delete", "حذف تعميم");
    return json({ ok: true });
  }
  return json({ error: "إجراء غير معروف" }, 400);
}

async function handleIndicator(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const eid = body.eid;
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  const actEarly = body.action;
  // طلب/تأكيد التحويل: صلاحيات خاصة (الإدارة تطلب على مؤشراتها، المنسّق يؤكّد لقطاعه)
  const isXferAct = actEarly === "xfer-request" || actEarly === "xfer-confirm" || actEarly === "xfer-cancel";
  // تعديلات الهيكل: الإدارة تُرسلها كطلب معلّق؛ المنسّق يعتمد/يرفض
  const structuralActsE = ["editText", "editMeasure", "editPeriod", "editAxis"];
  const isEntityStructEdit = !!p.eid && p.role !== "admin" && !p.sid && structuralActsE.includes(actEarly);
  const isEditReviewAct = actEarly === "edit-approve" || actEarly === "edit-reject";
  if (isXferAct) {
    const ownEntity = p.eid === eid;
    const ownSector = p.sid && (sectors[p.sid]?.entity_ids || []).includes(eid);
    const isAdminX = p.role === "admin";
    if (actEarly === "xfer-request" && !(ownEntity || ownSector || isAdminX)) return json({ error: "غير مصرح" }, 403);
    if ((actEarly === "xfer-confirm") && !(ownSector || isAdminX)) return json({ error: "التأكيد لمنسّق القطاع أو المدير" }, 403);
    if (actEarly === "xfer-cancel" && !(ownEntity || ownSector || isAdminX)) return json({ error: "غير مصرح" }, 403);
  } else if (isEntityStructEdit) {
    if (p.eid !== eid) return json({ error: "غير مصرح" }, 403);
  } else if (isEditReviewAct) {
    const ownSector = p.sid && (sectors[p.sid]?.entity_ids || []).includes(eid);
    if (p.role !== "admin" && !ownSector) return json({ error: "الاعتماد لمنسّق القطاع أو المدير" }, 403);
  } else if (!canEditIndicators(p, eid)) return json({ error: "غير مصرح بتعديل المؤشرات" }, 403);
  const year = reqYear(request, body);
  if (!yearEditable(year)) return json({ error: "السنة الدراسية " + year + " مؤرشفة للقراءة فقط — لا يمكن التعديل" }, 423);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  if (!(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد من مدير عام شؤون المدارس" }, 423);
  if (!isXferAct && !isEditReviewAct && p.role !== "admin" && await sectorLocked(kv, eid, year)) {
    return json({ error: "التقرير معتمد ومقفل — يلزم تصريح من مدير عام شؤون المدارس للتعديل" }, 423);
  }
  const ov = (await kv.get(["overrides", year, eid])).value || { edits: {}, added: [], deleted: [] };
  if (!ov.deleted) ov.deleted = [];
  const act = body.action;
  // منع أي تعديل هيكلي على مؤشر منقول (الصياغة/المحور/القياس/الفترة/الحذف) — عدا إجراءات التحويل نفسها
  if (!isXferAct && body.index !== undefined && (ov.transferred || {})[String(body.index)]) {
    return json({ error: "لا يمكن تعديل مؤشر مُحوَّل إلى جهة أخرى" }, 423);
  }
  // ===== تعديلات الهيكل من الإدارة: تُخزَّن كـ"تعديل معلّق" بانتظار اعتماد المنسّق =====
  // (القيم/الحالة تُحفظ عبر /api/save فوراً — لا تمرّ من هنا)
  const structuralActs = ["editText", "editMeasure", "editPeriod", "editAxis"];
  const isEntityActor = !!p.eid && p.role !== "admin" && !p.sid;
  if (isEntityActor && structuralActs.includes(act)) {
    ov.pendingEdits = ov.pendingEdits || {};
    const idx = String(body.index);
    const pend = ov.pendingEdits[idx] || { by: whoLabel(p), at: null, fields: {} };
    if (act === "editText") pend.fields.proc = (body.proc || "").slice(0, 500);
    else if (act === "editMeasure") { const m = ["نسبة", "عدد", "عدد-إنجاز", "وصفي", "زمني"].includes(body.measure) ? body.measure : "وصفي"; pend.fields.measure = m; if ((m === "عدد" || m === "عدد-إنجاز") && body.ref) pend.fields.ref = +body.ref; }
    else if (act === "editPeriod") { pend.fields.from = (body.from || "").slice(0, 40); pend.fields.to = (body.to || "").slice(0, 40); }
    else if (act === "editAxis") pend.fields.axis = (body.axis || "").slice(0, 200);
    pend.at = new Date().toISOString(); pend.by = whoLabel(p); pend.status = "pending";
    ov.pendingEdits[idx] = pend;
    await kv.set(["overrides", year, eid], ov);
    await pushNotify(kv, eid, "editReq", "طلب تعديل هيكل مؤشر بانتظار الاعتماد", +body.index, p, ["sector"], year);
    await logAction(kv, actorOf(p), "edit-request", "طلب تعديل هيكل مؤشر في " + plans[eid].name);
    return json({ ok: true, pending: true, overrides: ov });
  }
  if (act === "editText") {
    ov.edits[String(body.index)] = { ...(ov.edits[String(body.index)] || {}), proc: (body.proc || "").slice(0, 500) };
  } else if (act === "editMeasure") {
    const m = ["نسبة", "عدد", "عدد-إنجاز", "وصفي", "زمني"].includes(body.measure) ? body.measure : "وصفي";
    ov.edits[String(body.index)] = { ...(ov.edits[String(body.index)] || {}), measure: m };
    if ((m === "عدد" || m === "عدد-إنجاز") && body.ref) ov.edits[String(body.index)].ref = +body.ref;
  } else if (act === "editPeriod") {
    ov.edits[String(body.index)] = { ...(ov.edits[String(body.index)] || {}), from: (body.from || "").slice(0, 40), to: (body.to || "").slice(0, 40) };
  } else if (act === "editAxis") {
    ov.edits[String(body.index)] = { ...(ov.edits[String(body.index)] || {}), axis: (body.axis || "").slice(0, 200) };
  } else if (act === "add") {
    const it = {
      axis: (body.axis || "").slice(0, 200), proc: (body.proc || "").slice(0, 500),
      from: (body.from || "").slice(0, 40), to: (body.to || "").slice(0, 40),
      measure: ["نسبة", "عدد", "عدد-إنجاز", "وصفي", "زمني"].includes(body.measure) ? body.measure : "وصفي",
      note: (body.note || "").slice(0, 300), added: true,
    };
    if ((it.measure === "عدد-إنجاز" || it.measure === "عدد") && body.ref) it.ref = +body.ref;
    ov.added.push(it);
    await pushNotify(kv, eid, "add", "أُضيف مؤشر جديد: " + it.proc.slice(0, 60), ov.added.length - 1 + plans[eid].items.length, p, ["sector", "entity"], year);
  } else if (act === "delete") {
    if (p.role === "admin") {
      const idx = +body.index;
      if (idx < plans[eid].items.length) { if (!ov.deleted.includes(idx)) ov.deleted.push(idx); }
      else { ov.added.splice(idx - plans[eid].items.length, 1); }
      ov.delReq = (ov.delReq || []).filter((x) => x !== +body.index);
    } else {
      ov.delReq = ov.delReq || [];
      if (!ov.delReq.includes(+body.index)) ov.delReq.push(+body.index);
      await pushNotify(kv, eid, "delReq", "طلب حذف مؤشر بانتظار موافقة المدير", +body.index, p, ["sector", "entity"], year);
    }
  } else if (act === "setRef") {
    ov.edits[String(body.index)] = { ...(ov.edits[String(body.index)] || {}), ref: +body.ref };
  } else if (act === "xfer-request") {
    // طلب تحويل من الإدارة/المنسّق مع تحديد الوجهة (إلزامي)
    const dstEid = body.dstEid;
    if (!dstEid || !plans[dstEid]) return json({ error: "حدّد الإدارة الهدف" }, 400);
    if (dstEid === eid) return json({ error: "لا يمكن التحويل لنفس الإدارة" }, 400);
    ov.xferReq = ov.xferReq || [];
    if (ov.xferReq.find((r) => r.index === +body.index)) return json({ error: "يوجد طلب تحويل قائم على هذا المؤشر" }, 400);
    ov.xferReq.push({ index: +body.index, dstEid, dstName: plans[dstEid].name, by: whoLabel(p), byRole: p.sid ? "sector" : "entity", at: new Date().toISOString(), status: "pending", confirmedBy: null });
    await pushNotify(kv, eid, "xferReq", "طلب تحويل مؤشر إلى: " + plans[dstEid].name, +body.index, p, ["sector"], year);
  } else if (act === "xfer-confirm") {
    // المنسّق يؤكّد الطلب
    if (!p.sid && p.role !== "admin") return json({ error: "التأكيد لمنسّق القطاع" }, 403);
    ov.xferReq = ov.xferReq || [];
    const r = ov.xferReq.find((x) => x.index === +body.index);
    if (!r) return json({ error: "لا يوجد طلب" }, 404);
    r.status = "confirmed"; r.confirmedBy = whoLabel(p); r.confirmedAt = new Date().toISOString();
    await pushNotify(kv, eid, "xferReq", "تم تأكيد طلب تحويل — بانتظار تنفيذ المدير", +body.index, p, ["entity", "admin"], year);
  } else if (act === "xfer-cancel") {
    ov.xferReq = (ov.xferReq || []).filter((x) => x.index !== +body.index);
  } else if (act === "edit-approve") {
    // المنسّق يعتمد التعديل المعلّق → يُنقل إلى edits (يصبح سارياً)
    const idx = String(body.index);
    const pend = (ov.pendingEdits || {})[idx];
    if (!pend) return json({ error: "لا يوجد تعديل معلّق" }, 404);
    ov.edits[idx] = { ...(ov.edits[idx] || {}), ...pend.fields };
    delete ov.pendingEdits[idx];
    _axesCache = null;
    await pushNotify(kv, eid, "editReq", "تم اعتماد تعديل هيكل المؤشر", +body.index, p, ["entity"], year);
    await logAction(kv, actorOf(p), "edit-approve", "اعتماد تعديل هيكل مؤشر في " + plans[eid].name);
  } else if (act === "edit-reject") {
    const idx = String(body.index);
    const pend = (ov.pendingEdits || {})[idx];
    if (!pend) return json({ error: "لا يوجد تعديل معلّق" }, 404);
    const reason = (body.reason || "").toString().slice(0, 500);
    delete ov.pendingEdits[idx];
    await pushNotify(kv, eid, "editReq", "رُفض تعديل هيكل المؤشر" + (reason ? ": " + reason : ""), +body.index, p, ["entity"], year);
    await logAction(kv, actorOf(p), "edit-reject", "رفض تعديل هيكل مؤشر في " + plans[eid].name + (reason ? " — " + reason : ""));
  } else return json({ error: "إجراء غير معروف" }, 400);
  await kv.set(["overrides", year, eid], ov);
  return json({ ok: true, overrides: ov });
}

// نقل مؤشر كامل من إدارة لأخرى — حصري لمدير عام شؤون المدارس
// المؤشر ينتقل ببياناته (القيمة، الملاحظات، المبررات، الأوقات)؛ يبقى في المصدر معلّماً "منقول"؛ يعمل في أي سنة (حتى المؤرشفة)
async function handleTransfer(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const srcEid = body.srcEid, dstEid = body.dstEid;
  const idx = body.index;
  if (!srcEid || !plans[srcEid]) return json({ error: "الإدارة المصدر غير معروفة" }, 400);
  if (!dstEid || !plans[dstEid]) return json({ error: "الإدارة الهدف غير معروفة" }, 400);
  if (srcEid === dstEid) return json({ error: "لا يمكن النقل إلى نفس الإدارة" }, 400);
  if (idx === undefined || idx === null) return json({ error: "المؤشر غير محدد" }, 400);
  // الصلاحيات:
  // - المدير وأدمن النظام: ينفّذان أي نقل مباشرةً (أي قطاع).
  // - المنسّق داخل قطاعه (المصدر والهدف كلاهما في قطاعه): نقل مباشر فوري بلا طلب — إشعار المدير فقط.
  // - النقل خارج القطاع: يتطلّب طلباً مؤكّداً + تنفيذ المدير/الأدمن.
  const isAdmin = p.role === "admin" || p.role === "sysadmin";
  const year = reqYear(request, body);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  // حساب المؤشرات غير المصنّفة: النقل من/إليه للمدير العام فقط
  if ((srcEid === UNCLASSIFIED_ID || dstEid === UNCLASSIFIED_ID) && !isAdmin) {
    return json({ error: "النقل من/إلى حساب المؤشرات غير المصنّفة متاح لمدير عام شؤون المدارس فقط" }, 403);
  }
  let coordInSector = false;
  if (!isAdmin) {
    if (!p.sid) return json({ error: "النقل لمنسّق القطاع أو المدير" }, 403);
    const inSec = sectors[p.sid]?.entity_ids || [];
    const srcIn = inSec.includes(srcEid), dstIn = inSec.includes(dstEid);
    if (srcIn && dstIn) {
      // نقل داخلي: مسموح مباشرةً بلا طلب
      coordInSector = true;
    } else {
      // النقل خارج القطاع غير مسموح للمنسّق — يتطلّب المدير
      return json({ error: "المنسّق ينقل داخل قطاعه فقط — النقل لقطاع آخر يتطلّب موافقة وتنفيذ المدير العام" }, 403);
    }
  }

  // 1) اجلب المؤشر من المصدر (بصيغته المدموجة)
  const srcOv = (await kv.get(["overrides", year, srcEid])).value || { edits: {}, added: [], deleted: [], delReq: [], transferred: {} };
  if (!srcOv.transferred) srcOv.transferred = {};
  const srcItems = mergedItems(srcEid, srcOv);
  const item = srcItems.find((x) => String(x._idx) === String(idx));
  if (!item) return json({ error: "المؤشر غير موجود في الإدارة المصدر" }, 404);

  // 2) اجلب بيانات المؤشر: القيمة والوقت
  const srcPlan = (await kv.get(["plan", year, srcEid])).value || { updates: {}, times: {} };
  const val = (srcPlan.updates || {})[String(idx)];
  const tim = (srcPlan.times || {})[String(idx)];
  // الملاحظات والمبررات لهذا المؤشر
  const srcComments = (await kv.get(["comments", year, srcEid])).value || { general: [], items: {} };
  const itemCmts = (srcComments.items || {})[String(idx)] || [];
  const srcJust = (await kv.get(["justify", year, srcEid])).value || {};
  const itemJust = srcJust[String(idx)];

  // 3) أضف نسخة كاملة للإدارة الهدف (كمؤشر مُضاف)
  const dstOv = (await kv.get(["overrides", year, dstEid])).value || { edits: {}, added: [], deleted: [], delReq: [], transferred: {} };
  if (!dstOv.added) dstOv.added = [];
  const newItem = {
    axis: item.axis || "", proc: item.proc || "", from: item.from || "", to: item.to || "",
    measure: item.measure || "وصفي", note: item.note || "", added: true,
    transferredFrom: plans[srcEid].name,
  };
  if (item.ref !== undefined && item.ref !== "") newItem.ref = item.ref;
  dstOv.added.push(newItem);
  const newIdx = plans[dstEid].items.length + dstOv.added.length - 1;
  await kv.set(["overrides", year, dstEid], dstOv);

  // 4) انقل القيمة والوقت للهدف
  if (val !== undefined || tim !== undefined) {
    const dstPlan = (await kv.get(["plan", year, dstEid])).value || { updates: {}, times: {} };
    if (!dstPlan.updates) dstPlan.updates = {}; if (!dstPlan.times) dstPlan.times = {};
    if (val !== undefined) dstPlan.updates[String(newIdx)] = val;
    dstPlan.times[String(newIdx)] = tim || new Date().toISOString();
    dstPlan.savedAt = new Date().toISOString();
    await kv.set(["plan", year, dstEid], dstPlan);
  }
  // 5) انقل الملاحظات والمبرر
  if (itemCmts.length) {
    const dstComments = (await kv.get(["comments", year, dstEid])).value || { general: [], items: {} };
    if (!dstComments.items) dstComments.items = {};
    dstComments.items[String(newIdx)] = (dstComments.items[String(newIdx)] || []).concat(itemCmts);
    await kv.set(["comments", year, dstEid], dstComments);
  }
  if (itemJust) {
    const dstJust = (await kv.get(["justify", year, dstEid])).value || {};
    dstJust[String(newIdx)] = itemJust;
    await kv.set(["justify", year, dstEid], dstJust);
  }

  // 6) علّم المصدر أن المؤشر "منقول" (أثر مرجعي، دون حذف)
  srcOv.transferred[String(idx)] = { to: dstEid, toName: plans[dstEid].name, at: new Date().toISOString(), by: whoLabel(p) };
  // أزل طلب التحويل بعد التنفيذ
  if (srcOv.xferReq) srcOv.xferReq = srcOv.xferReq.filter((r) => r.index !== +idx);
  await kv.set(["overrides", year, srcEid], srcOv);

  // 7) إشعارات للإدارتين وقطاعيهما
  await pushNotify(kv, srcEid, "transfer", "نُقل مؤشر إلى إدارة: " + plans[dstEid].name + " — " + (item.proc || "").slice(0, 40), +idx, p, ["sector", "entity"], year);
  await pushNotify(kv, dstEid, "transfer", "استُقبل مؤشر من إدارة: " + plans[srcEid].name + " — " + (item.proc || "").slice(0, 40), newIdx, p, ["sector", "entity"], year);
  // 8) نقل داخلي نفّذه المنسّق: إشعار المدير العام (اعتماد تلقائي) + تسجيل واضح
  if (coordInSector) {
    await pushNotify(kv, srcEid, "transfer", "نقل داخلي نفّذه منسّق القطاع: «" + (item.proc || "").slice(0, 40) + "» من " + plans[srcEid].name + " إلى " + plans[dstEid].name, +idx, p, ["admin"], year);
    await logAction(kv, actorOf(p), "transfer-internal", "نقل داخلي (منسّق) من " + plans[srcEid].name + " إلى " + plans[dstEid].name + " — " + (item.proc || "").slice(0, 50));
  } else {
    await logAction(kv, actorOf(p), "transfer", "نقل مؤشر من " + plans[srcEid].name + " إلى " + plans[dstEid].name + " — " + (item.proc || "").slice(0, 50));
  }

  return json({ ok: true, newIdx, dstName: plans[dstEid].name, internal: coordInSector });
}
// دمج الخطة الأصلية مع التعديلات والإضافات والمحذوفات
function mergedItems(eid, ov) {
  const del = (ov && ov.deleted) || [];
  const transferred = (ov && ov.transferred) || {};
  const base = plans[eid].items.map((it, i) => {
    if (del.includes(i)) return null;
    const e = ov && ov.edits && ov.edits[String(i)];
    if (e) return { ...it, ...(e.proc !== undefined ? { proc: e.proc } : {}), ...(e.ref !== undefined ? { ref: e.ref } : {}), ...(e.measure !== undefined ? { measure: e.measure } : {}), ...(e.from !== undefined ? { from: e.from } : {}), ...(e.to !== undefined ? { to: e.to } : {}), ...(e.axis !== undefined ? { axis: e.axis } : {}) };
    return it;
  });
  const out = [];
  base.forEach((it, i) => { if (it !== null) { const t = transferred[String(i)]; out.push({ ...it, _idx: i, ...(t ? { transferredTo: t.toName, transferredAt: t.at } : {}) }); } });
  if (ov && ov.added) ov.added.forEach((it, k) => { const gi = plans[eid].items.length + k; const t = transferred[String(gi)]; out.push({ ...it, _idx: gi, ...(t ? { transferredTo: t.toName, transferredAt: t.at } : {}), ...(it.transferredFrom ? { transferredFrom: it.transferredFrom } : {}) }); });
  return out;
}

// نظام الإشعارات: يُخزَّن لكل قطاع/إدارة/مدير حسب السنة، ويستهدف المنسق والإدارة والمدير
async function pushNotify(kv, eid, kind, text, index, actor, targets, year) {
  const y = year || currentSchoolYear();
  const sid = sectorOfEntity(eid);
  const note = { id: crypto.randomUUID(), eid, entName: plans[eid].name, kind, text, index, year: y, by: whoLabel(actor), at: new Date().toISOString(), read: false };
  const to = targets || ["sector", "entity"];
  if (to.includes("sector") && sid) {
    const nk = ["notify", "sector", y, sid];
    const arr = (await kv.get(nk)).value || [];
    arr.unshift(note); await kv.set(nk, arr.slice(0, 100));
  }
  if (to.includes("entity")) {
    const ek = ["notify", "entity", y, eid];
    const earr = (await kv.get(ek)).value || [];
    earr.unshift(note); await kv.set(ek, earr.slice(0, 100));
  }
  if (to.includes("admin")) {
    const ak = ["notify", "admin", y];
    const aarr = (await kv.get(ak)).value || [];
    aarr.unshift(note); await kv.set(ak, aarr.slice(0, 100));
  }
}

// رفع/جلب/اعتماد/حذف وثيقة PDF داعمة لجهة
// الرفع: منسق القطاع فقط. الاعتماد: المدير العام فقط. الحذف: المدير العام فقط.
function canUpload(p, eid) {
  return p.sid && (sectors[p.sid]?.entity_ids || []).includes(eid);
}
async function handleUpload(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  const eid = body.eid;
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  const year = reqYear(request, body);
  if (!yearEditable(year)) return json({ error: "السنة الدراسية " + year + " مؤرشفة للقراءة فقط" }, 423);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  if (!(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد من مدير عام شؤون المدارس" }, 423);
  const docs = (await kv.get(["docs", year, eid])).value || [];
  const action = body.action || "upload";
  if (action === "upload") {
    if (!canUpload(p, eid)) return json({ error: "الرفع متاح لمنسق القطاع فقط" }, 403);
    if (body.data && body.name) {
      if (body.data.length > 3_000_000) return json({ error: "الملف كبير جداً (الحد ~2MB)" }, 400);
      docs.push({ id: crypto.randomUUID(), name: body.name.slice(0, 120), data: body.data, by: whoLabel(p), at: new Date().toISOString(), approved: false, approvedBy: null, approvedAt: null });
      await kv.set(["docs", year, eid], docs);
    }
  } else if (action === "approve") {
    if (p.role !== "admin") return json({ error: "الاعتماد للمدير العام فقط" }, 403);
    const doc = docs.find((d) => d.id === body.id);
    if (doc) { doc.approved = true; doc.approvedBy = whoLabel(p); doc.approvedAt = new Date().toISOString(); await kv.set(["docs", year, eid], docs); }
  } else if (action === "delete") {
    if (p.role !== "admin") return json({ error: "الحذف للمدير العام فقط" }, 403);
    const idx = docs.findIndex((d) => d.id === body.id);
    if (idx >= 0) { docs.splice(idx, 1); await kv.set(["docs", year, eid], docs); }
  }
  return json({ ok: true, docs: docs.map((d) => ({ id: d.id, name: d.name, by: d.by, at: d.at, approved: d.approved, approvedBy: d.approvedBy, approvedAt: d.approvedAt })) });
}

// تجميع مشترك (للوحة المشرف والتقرير الرسمي)
// خط زمني: أحدث التحديثات (منجز/غير منجز) عبر عدة إدارات
async function recentUpdates(kv, eids, limit, year) {
  const y = year || currentSchoolYear();
  const all = [];
  for (const eid of eids) {
    const rec = (await kv.get(["plan", y, eid])).value;
    if (!rec || !rec.times) continue;
    const ov = (await kv.get(["overrides", y, eid])).value || {};
    const items = mergedItems(eid, ov);
    for (const k of Object.keys(rec.times)) {
      const it = items.find((x) => String(x._idx) === String(k));
      if (!it) continue;
      const st = statusOf(it, (rec.updates || {})[k]);
      all.push({ eid, entName: plans[eid].name, proc: it.proc, at: rec.times[k], st, index: +k });
    }
  }
  all.sort((a, b) => new Date(b.at) - new Date(a.at));
  return all.slice(0, limit || 10);
}

async function aggregate(kv, year) {
  const y = year || currentSchoolYear();
  const cache = {};
  async function statsFor(eid) {
    if (cache[eid]) return cache[eid];
    const rec = (await kv.get(["plan", y, eid])).value;
    const ov = (await kv.get(["overrides", y, eid])).value || {};
    // استبعاد المؤشرات المنقولة إلى جهة أخرى من حسابات هذه الجهة (المسؤولية انتقلت — منع الحساب المزدوج)
    const items = mergedItems(eid, ov).filter((it) => !it.transferredTo);
    const updates = rec ? (rec.updates || {}) : {};
    let done = 0, prog = 0, late = 0, no = 0, sum = 0;
    items.forEach((it) => {
      const u = updates[it._idx];
      const st = statusOf(it, u);
      if (["مكتمل", "منجز", "تم"].includes(st)) { done++; sum += 100; }
      else if (st === "قيد التنفيذ") { prog++; sum += (it.measure === "نسبة" && u) ? +u.v : 50; }
      else if (st === "متأخر") { late++; sum += (it.measure === "نسبة" && u) ? +u.v : 0; }
      else no++;
    });
    const r = { id: eid, name: plans[eid].name, total: items.length, done, prog, late, no,
      overall: items.length ? Math.round(sum / items.length) : 0, savedAt: rec ? rec.savedAt : null };
    cache[eid] = r; return r;
  }
  const out = [];
  for (const sid of Object.keys(sectors)) {
    const sec = sectors[sid];
    const rows = [];
    for (const eid of sec.entity_ids) rows.push(await statsFor(eid));
    // استبعاد الإدارات ذات الـ ٠ مؤشرات تماماً (قرار: لا تظهر ولا تُحتسب)
    const active = rows.filter((r) => r.total > 0);
    if (active.length === 0) continue; // قطاع بلا أي مؤشرات: يُستبعد كلياً
    const tot = active.reduce((a, r) => a + r.total, 0);
    // متوسط نسب الإدارات (وزن متساوٍ لكل إدارة)
    const avg = active.length ? Math.round(active.reduce((a, r) => a + r.overall, 0) / active.length) : 0;
    // النسبة المرجّحة بعدد المؤشرات (وزن متساوٍ لكل مؤشر)
    const wsum = active.reduce((a, r) => a + (r.overall * r.total), 0);
    const weighted = tot ? Math.round(wsum / tot) : 0;
    active.sort((a, b) => b.overall - a.overall);
    out.push({ id: sid, name: sec.name, total: tot, overall: avg, weighted, entities: active });
  }
  const inSector = new Set(Object.values(sectors).flatMap((s) => s.entity_ids));
  const extra = [];
  let bucket = null;
  for (const eid of Object.keys(plans)) {
    if (inSector.has(eid)) continue;
    if (eid === UNCLASSIFIED_ID) { const st = await statsFor(eid); if (st.total > 0) bucket = st; continue; }
    const st = await statsFor(eid); if (st.total > 0) extra.push(st);
  }
  return { sectors: out, unclassified: extra, bucket };
}

// تجميع الإنجاز حسب المحور (البُعد) عبر مجموعة من الإدارات — يمتد عبر القطاعات
// scopeEids: قائمة الإدارات المشمولة (للمنسق = إدارات قطاعه، للمدير = الكل)
async function aggregateByAxis(kv, year, scopeEids) {
  const eids = scopeEids || Object.keys(plans);
  const axes = {};
  const nowRef = new Date(); // احتساب التأخير دائماً بتاريخ اليوم الفعلي
  const isExempt = (year || currentSchoolYear()) === NO_DELAY_YEAR; // ٢٠٢٥-٢٠٢٦: لا تعثّر (أرشيف منتهٍ فُعّلت المنصة بعده)
  for (const eid of eids) {
    const rec = (await kv.get(["plan", year, eid])).value || { updates: {} };
    const ov = (await kv.get(["overrides", year, eid])).value || {};
    const items = mergedItems(eid, ov).filter((it) => !it.transferredTo);
    const updates = rec.updates || {};
    const sid = sectorOfEntity(eid);
    const secName = sid ? (sectors[sid]?.name || "") : "غير مصنّف";
    for (const it of items) {
      const axis = (it.axis || "بدون محور").trim();
      const a = axes[axis] || (axes[axis] = { axis, total: 0, done: 0, prog: 0, late: 0, no: 0, sum: 0, blockers: {}, entTotals: {}, notDone: [] });
      const u = updates[it._idx];
      const st = statusOf(it, u);
      a.total++;
      let pct = 0;
      if (["مكتمل", "منجز", "تم"].includes(st)) { a.done++; pct = 100; }
      else if (st === "قيد التنفيذ") { a.prog++; pct = (it.measure === "نسبة" && u) ? +u.v : 50; }
      else if (st === "متأخر") { a.late++; pct = (it.measure === "نسبة" && u) ? +u.v : 0; }
      else { a.no++; }
      a.sum += pct;
      // مصفوفة الجهات: تتبّع كل جهة في هذا المحور (الإجمالي والمتأخر ومدى التأخّر)
      const bAll = a.entTotals[eid] || (a.entTotals[eid] = { eid, name: plans[eid].name, sector: secName, total: 0, late: 0, no: 0, maxDelayDays: -1, delayLabel: "—", targetText: "" });
      bAll.total++;
      if (st === "متأخر" || st === "لم يبدأ" || st === "لم يتم") {
        if (st === "متأخر") bAll.late++; else bAll.no++;
        // احسب مدى التأخّر لهذا المؤشر
        const di = delayInfo(it.to, year, nowRef);
        let delayText;
        if (di.exempt) { delayText = "—"; if (bAll.delayLabel === "—") bAll.delayLabel = "غير محسوب"; }
        else if (di.computable) { delayText = di.label; if (di.days > bAll.maxDelayDays) { bAll.maxDelayDays = di.days; bAll.delayLabel = di.label; bAll.targetText = di.targetText; } }
        else { delayText = "الفترة: " + di.targetText; if (bAll.maxDelayDays < 0) { bAll.delayLabel = "الفترة: " + di.targetText; bAll.targetText = di.targetText; } }
        a.notDone.push({ eid, entName: plans[eid].name, sector: secName, proc: it.proc, status: st, measure: it.measure, delay: delayText });
      }
    }
  }
  // حوّل لمصفوفة مرتّبة: الأدنى إنجازاً أولاً (الأكثر تعثراً)
  const out = Object.values(axes).map((a) => {
    const overall = a.total ? Math.round(a.sum / a.total) : 0;
    // ٢٠٢٥-٢٠٢٦ مستثناة: لا تعثّر ولا "خلف الجدول الزمني" — الدونت يعكس الإنجاز الفعلي فقط
    const troubled = isExempt ? false : (a.late + a.no) > 0;
    const behind = isExempt ? [] : Object.values(a.entTotals)
      .filter((e) => (e.late + e.no) > 0)
      .map((e) => ({ eid: e.eid, name: e.name, sector: e.sector, delayed: e.late + e.no, total: e.total, delayLabel: e.delayLabel, maxDelayDays: e.maxDelayDays }))
      .sort((x, y) => (y.maxDelayDays - x.maxDelayDays) || (y.delayed - x.delayed));
    return {
      axis: a.axis, total: a.total, done: a.done, prog: a.prog, late: a.late, no: a.no,
      overall, troubled, behind, exempt: isExempt,
      notDone: isExempt ? [] : a.notDone,
    };
  });
  out.sort((x, y) => x.overall - y.overall);
  return out;
}


// تصفير كامل للمنصّة: يمسح كل بيانات KV (الحالات، التعليقات، المستندات، الاعتمادات،
// فتح السنوات، الإشعارات) ويعيد النظام لحالته الأولى النظيفة. للمدير فقط + عبارة تأكيد.
// المؤشرات والأكواد مضمّنة في الكود ولا تتأثر.
// ========== أدمن النظام (دور فنّي منفصل) ==========
// شاشة فنّية: سجلّ الحركات، النسخ الاحتياطي/الاستعادة، إدارة الأكواد، والتصحيح
async function handleSysadmin(request) {
  const p = await verifyToken(bearer(request));
  if (!p || p.role !== "sysadmin") return json({ error: "خاص بأدمن النظام فقط" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  const action = body.action || "";
  let kv; try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }

  // 1) سجلّ الحركات (أحدث أولاً، مع حدّ)
  if (action === "audit") {
    const limit = Math.min(+body.limit || 200, 1000);
    const rows = [];
    for await (const e of kv.list({ prefix: ["audit"] }, { reverse: true })) {
      rows.push(e.value);
      if (rows.length >= limit) break;
    }
    return json({ ok: true, rows, count: rows.length });
  }

  // 2) نسخة احتياطية كاملة (كل مفاتيح KV)
  if (action === "backup") {
    const yr = (body.year || "").toString().trim(); // فارغ = كل السنوات
    // يحدّد ما إذا كان المفتاح يخصّ السنة المطلوبة
    const keyMatchesYear = (key, year) => {
      const head = key[0];
      // مفاتيح السنة في الموضع 1
      if (["plan", "comments", "overrides", "docs", "justify", "submission", "reportPdf", "reportSubs", "yearOpen"].includes(head)) {
        return key[1] === year;
      }
      // الإشعارات: السنة في الموضع 2 — ["notify", role, year, ...]
      if (head === "notify") return key[2] === year;
      // audit و userCode عابرة للسنوات — تُضمّن دائماً في نسخة السنة (سياق فنّي مفيد)
      if (head === "audit" || head === "userCode") return true;
      return false;
    };
    const dump = [];
    for await (const e of kv.list({ prefix: [] })) {
      if (yr && !keyMatchesYear(e.key, yr)) continue;
      dump.push({ key: e.key, value: e.value });
    }
    const scope = yr || "كل السنوات";
    await logAction(kv, actorOf(p), "backup", "تنزيل نسخة احتياطية (" + scope + " — " + dump.length + " مفتاح)");
    return json({ ok: true, at: new Date().toISOString(), year: yr || null, count: dump.length, data: dump });
  }

  // 3) استعادة من نسخة احتياطية (استبدال كامل)
  if (action === "restore") {
    if (!Array.isArray(body.data)) return json({ error: "بيانات الاستعادة غير صالحة" }, 400);
    if ((body.confirm || "").toString().trim() !== "استعادة") return json({ error: "يلزم كتابة كلمة «استعادة» للتأكيد" }, 400);
    // امسح الحالي ثم اكتب المستعاد
    for await (const e of kv.list({ prefix: [] })) { await kv.delete(e.key); }
    let n = 0;
    for (const item of body.data) {
      if (item && Array.isArray(item.key)) { await kv.set(item.key, item.value); n++; }
    }
    await logAction(kv, actorOf(p), "restore", "استعادة نسخة احتياطية (" + n + " مفتاح)");
    return json({ ok: true, restored: n });
  }

  // 4) إدارة الأكواد الديناميكية: قائمة / توليد / تعطيل / تفعيل / حذف
  if (action === "codes-list") {
    const rows = [];
    for await (const e of kv.list({ prefix: ["userCode"] })) {
      const v = e.value || {};
      rows.push({ hash: e.key[1], role: v.role, sid: v.sid, eid: v.eid, disabled: !!v.disabled, label: v.label || "", code: v.code || "", createdAt: v.createdAt });
    }
    return json({ ok: true, rows });
  }
  if (action === "code-set") {
    // توليد أو تغيير كود لمستخدم: يعطي role + (sid أو eid) + code
    const role = body.role, target = body.target, newCode = (body.code || "").trim().toUpperCase();
    if (!["admin", "sector", "entity"].includes(role)) return json({ error: "الدور غير صالح" }, 400);
    if (!newCode || newCode.length < 6) return json({ error: "الكود قصير جداً (٦ أحرف على الأقل)" }, 400);
    if (role === "sector" && !sectors[target]) return json({ error: "قطاع غير معروف" }, 400);
    if (role === "entity" && !plans[target]) return json({ error: "إدارة غير معروفة" }, 400);
    const h = await sha256(newCode);
    const rec = { role, code: newCode, disabled: false, label: body.label || "", createdAt: new Date().toISOString() };
    if (role === "sector") rec.sid = target;
    if (role === "entity") rec.eid = target;
    await kv.set(["userCode", h], rec);
    await logAction(kv, actorOf(p), "code-set", "ضبط كود " + role + " للجهة " + (target || "-"));
    return json({ ok: true, hash: h });
  }
  if (action === "code-toggle") {
    const h = body.hash; if (!h) return json({ error: "hash مطلوب" }, 400);
    const rec = (await kv.get(["userCode", h])).value;
    if (!rec) return json({ error: "الكود غير موجود" }, 404);
    rec.disabled = !rec.disabled;
    await kv.set(["userCode", h], rec);
    await logAction(kv, actorOf(p), "code-toggle", (rec.disabled ? "تعطيل" : "تفعيل") + " كود " + (rec.label || h.slice(0, 8)));
    return json({ ok: true, disabled: rec.disabled });
  }
  if (action === "code-delete") {
    const h = body.hash; if (!h) return json({ error: "hash مطلوب" }, 400);
    await kv.delete(["userCode", h]);
    await logAction(kv, actorOf(p), "code-delete", "حذف كود " + h.slice(0, 8));
    return json({ ok: true });
  }

  // 5) تصحيح مباشر: قراءة/كتابة قيمة مفتاح KV (للصيانة الدقيقة)
  if (action === "kv-get") {
    if (!Array.isArray(body.key)) return json({ error: "مفتاح غير صالح" }, 400);
    const v = (await kv.get(body.key)).value;
    return json({ ok: true, key: body.key, value: v });
  }
  if (action === "kv-set") {
    if (!Array.isArray(body.key)) return json({ error: "مفتاح غير صالح" }, 400);
    await kv.set(body.key, body.value);
    await logAction(kv, actorOf(p), "kv-set", "تعديل مفتاح: " + JSON.stringify(body.key));
    return json({ ok: true });
  }
  if (action === "kv-list") {
    const prefix = Array.isArray(body.prefix) ? body.prefix : [];
    const keys = [];
    for await (const e of kv.list({ prefix })) { keys.push(e.key); if (keys.length >= 500) break; }
    return json({ ok: true, keys });
  }

  // ========== أداة التصحيح الفنّي: عرض وتصحيح مؤشرات أي إدارة/سنة (يتجاوز الأقفال) ==========
  if (action === "fix-list") {
    const eid = body.eid; const yr = (body.year || currentSchoolYear()).toString();
    if (!eid || !plans[eid]) return json({ error: "إدارة غير معروفة" }, 400);
    const ov = (await kv.get(["overrides", yr, eid])).value || {};
    const rec = (await kv.get(["plan", yr, eid])).value || { updates: {}, times: {} };
    const items = mergedItems(eid, ov).map((it) => {
      const u = rec.updates ? rec.updates[String(it._idx)] : null;
      return {
        idx: it._idx, proc: it.proc || "", axis: it.axis || "", measure: it.measure || "وصفي",
        from: it.from || "", to: it.to || "",
        value: u || null, status: statusOf(it, u), pct: pctOf(it, u),
        savedAt: rec.times ? rec.times[String(it._idx)] : null,
      };
    });
    return json({ ok: true, year: yr, eid, entName: plans[eid].name, sector: sectorOfEntity(eid), items, savedAt: rec.savedAt });
  }
  if (action === "fix-set") {
    const eid = body.eid; const yr = (body.year || currentSchoolYear()).toString();
    if (!eid || !plans[eid]) return json({ error: "إدارة غير معروفة" }, 400);
    if (!body.updates || typeof body.updates !== "object") return json({ error: "لا توجد تصحيحات" }, 400);
    const rec = (await kv.get(["plan", yr, eid])).value || { updates: {}, times: {} };
    rec.updates = rec.updates || {}; rec.times = rec.times || {};
    const now = new Date().toISOString();
    const changed = [];
    for (const k of Object.keys(body.updates)) {
      const val = body.updates[k];
      // قيمة فارغة/undefined = مسح المؤشر (إعادته "لم يبدأ")
      if (val === null || val === undefined) { delete rec.updates[k]; delete rec.times[k]; changed.push(k); continue; }
      if (JSON.stringify(val) !== JSON.stringify(rec.updates[k])) { rec.updates[k] = val; rec.times[k] = now; changed.push(k); }
    }
    rec.savedAt = now;
    await kv.set(["plan", yr, eid], rec);
    await logAction(kv, actorOf(p), "fix-set", "تصحيح فنّي لإدارة " + plans[eid].name + " (سنة " + yr + ") — " + changed.length + " مؤشر");
    return json({ ok: true, changed: changed.length, savedAt: now });
  }

  // ========== التحليلات الشاملة (نشاط + صحة المنصّة + عبر السنوات) ==========
  if (action === "analytics") {
    const yr = (body.year || currentSchoolYear()).toString();
    const now = Date.now();
    const DAY = 86400000;
    // 1) نشاط الإدارات في السنة المحددة
    const entityActivity = [];
    let totalKeys = 0, auditCount = 0, dynCodes = 0;
    const allEids = Object.keys(plans);
    for (const eid of allEids) {
      const ov = (await kv.get(["overrides", yr, eid])).value || {};
      const items = mergedItems(eid, ov);
      if (items.length === 0) continue; // تجاهل الإدارات الفارغة
      const rec = (await kv.get(["plan", yr, eid])).value;
      const updates = rec ? (rec.updates || {}) : {};
      const times = rec ? (rec.times || {}) : {};
      const filled = Object.keys(updates).length;
      // آخر نشاط: أحدث وقت في times أو savedAt
      let lastAt = rec && rec.savedAt ? new Date(rec.savedAt).getTime() : 0;
      for (const k of Object.keys(times)) { const t = new Date(times[k]).getTime(); if (t > lastAt) lastAt = t; }
      const sid = sectorOfEntity(eid);
      entityActivity.push({
        eid, name: plans[eid].name, sector: sid ? sectors[sid].name : "غير مصنّف",
        total: items.length, filled, fillRate: items.length ? Math.round(filled / items.length * 100) : 0,
        lastAt: lastAt || null, daysSince: lastAt ? Math.floor((now - lastAt) / DAY) : null,
        neverEntered: filled === 0,
      });
    }
    // 2) إحصاء المفاتيح الكلي + تصنيفها
    const keyTypes = {};
    for await (const e of kv.list({ prefix: [] })) {
      totalKeys++;
      const t = e.key[0];
      keyTypes[t] = (keyTypes[t] || 0) + 1;
      if (t === "audit") auditCount++;
      if (t === "userCode") dynCodes++;
    }
    // 3) إحصاءات عبر السنوات
    const yearStats = [];
    for (const y of schoolYears()) {
      const agg = await aggregate(kv, y);
      const allEnts = agg.sectors.flatMap((s) => s.entities);
      const totItems = allEnts.reduce((a, e) => a + e.total, 0);
      const wsum = allEnts.reduce((a, e) => a + e.overall * e.total, 0);
      const weighted = totItems ? Math.round(wsum / totItems) : 0;
      const activeEnts = allEnts.filter((e) => e.savedAt).length;
      yearStats.push({ year: y, sectors: agg.sectors.length, entities: allEnts.length, activeEntities: activeEnts, totalItems: totItems, weighted, isCurrent: y === currentSchoolYear() });
    }
    // 4) ملخّص سجلّ الحركات (آخر 30 يوماً حسب النوع)
    const auditByType = {}; let auditRecent = 0;
    for await (const e of kv.list({ prefix: ["audit"] }, { reverse: true })) {
      const a = e.value; if (!a) continue;
      auditByType[a.action] = (auditByType[a.action] || 0) + 1;
      if (a.at && (now - new Date(a.at).getTime()) < 30 * DAY) auditRecent++;
    }
    // 5) آخر نسخة احتياطية (من السجلّ)
    let lastBackup = null;
    for await (const e of kv.list({ prefix: ["audit"] }, { reverse: true })) {
      if (e.value && e.value.action === "backup") { lastBackup = e.value.at; break; }
    }
    // 6) تنبيهات صحّية
    const alerts = [];
    const inactive = entityActivity.filter((e) => e.neverEntered);
    if (inactive.length) alerts.push({ level: "warn", text: inactive.length + " إدارة لم تُدخل أي بيانات في سنة " + yr });
    const stale = entityActivity.filter((e) => e.daysSince !== null && e.daysSince > 30);
    if (stale.length) alerts.push({ level: "info", text: stale.length + " إدارة لم تُحدّث بياناتها منذ أكثر من 30 يوماً" });
    if (!lastBackup) alerts.push({ level: "warn", text: "لا توجد نسخة احتياطية مسجّلة بعد" });
    else if ((now - new Date(lastBackup).getTime()) > 7 * DAY) alerts.push({ level: "info", text: "آخر نسخة احتياطية منذ أكثر من أسبوع" });

    entityActivity.sort((a, b) => (b.lastAt || 0) - (a.lastAt || 0));
    return json({
      ok: true, year: yr,
      health: { totalKeys, auditCount, dynCodes, keyTypes, lastBackup, currentYear: currentSchoolYear() },
      entityActivity, yearStats,
      audit: { byType: auditByType, recent30d: auditRecent },
      alerts,
      summary: {
        totalEntities: entityActivity.length,
        neverEntered: inactive.length,
        fullyEntered: entityActivity.filter((e) => e.fillRate === 100).length,
        avgFillRate: entityActivity.length ? Math.round(entityActivity.reduce((a, e) => a + e.fillRate, 0) / entityActivity.length) : 0,
      },
    });
  }

  // نظرة عامة (إحصاء) + قوائم الجهات (لواجهة إدارة الأكواد)
  if (action === "overview" || !action) {
    let total = 0, audit = 0, codes = 0;
    for await (const e of kv.list({ prefix: [] })) {
      total++;
      if (e.key[0] === "audit") audit++;
      if (e.key[0] === "userCode") codes++;
    }
    const secList = Object.keys(sectors).map((sid) => ({ id: sid, name: sectors[sid].name }));
    const entList = Object.keys(plans).map((eid) => ({ id: eid, name: plans[eid].name }));
    return json({ ok: true, stats: { totalKeys: total, auditEntries: audit, dynamicCodes: codes, currentYear: currentSchoolYear() }, sectors: secList, entities: entList, years: schoolYears() });
  }

  return json({ error: "إجراء غير معروف" }, 400);
}

async function handleAdminReset(request) {
  const p = await verifyToken(bearer(request));
  if (!p || p.role !== "admin") return json({ error: "التصفير لمدير عام شؤون المدارس فقط" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  // عبارة تأكيد إلزامية لمنع التصفير بالخطأ
  if ((body.confirm || "").toString().trim() !== "تصفير") {
    return json({ error: "يلزم كتابة كلمة «تصفير» للتأكيد" }, 400);
  }
  let kv; try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  // امسح كل المفاتيح دفعةً دفعة
  let deleted = 0;
  for await (const entry of kv.list({ prefix: [] })) {
    await kv.delete(entry.key);
    deleted++;
  }
  await logAction(kv, actorOf(p), "reset-all", "تصفير كامل للمنصّة (" + deleted + " مفتاح)");
  return json({ ok: true, deleted });
}

// تصفير مُنطاقي: منسّق القطاع يصفّر بيانات إدارة واحدة أو قطاعه كاملاً (ضمن نطاقه فقط)
// المدير العام وأدمن النظام يستطيعان تصفير أي جهة
async function handleScopedReset(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة" }, 401);
  if (!(p.role === "admin" || p.role === "sysadmin" || p.sid)) return json({ error: "غير مصرّح" }, 403);
  let body; try { body = await request.json(); } catch { body = {}; }
  if ((body.confirm || "").toString().trim() !== "تصفير") return json({ error: "يلزم كتابة كلمة «تصفير» للتأكيد" }, 400);
  let kv; try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  const scope = body.scope; // "entity" أو "sector"
  const year = body.year || null; // null = كل السنوات

  // حدّد الإدارات المستهدفة ضمن صلاحية الفاعل
  let targetEids = [];
  if (scope === "entity") {
    const eid = body.eid;
    if (!eid || !plans[eid]) return json({ error: "إدارة غير معروفة" }, 400);
    // منسّق القطاع: يجب أن تكون الإدارة ضمن قطاعه
    if (p.sid) {
      const sec = sectors[p.sid];
      if (!sec || !sec.entity_ids.includes(eid)) return json({ error: "هذه الإدارة ليست ضمن قطاعك" }, 403);
    }
    targetEids = [eid];
  } else if (scope === "sector") {
    const sid = p.sid || body.sid;
    const sec = sectors[sid];
    if (!sec) return json({ error: "قطاع غير معروف" }, 400);
    if (p.sid && p.sid !== sid) return json({ error: "لا يمكنك تصفير قطاع آخر" }, 403);
    targetEids = sec.entity_ids.slice();
  } else {
    return json({ error: "نطاق غير صالح" }, 400);
  }

  // امسح مفاتيح البيانات التشغيلية لكل إدارة مستهدفة (كل السنوات أو سنة محددة)
  const dataPrefixes = ["plan", "comments", "overrides", "docs", "justify"];
  let deleted = 0;
  const years = year ? [year] : schoolYears();
  for (const eid of targetEids) {
    for (const pref of dataPrefixes) {
      for (const y of years) {
        const key = [pref, y, eid];
        if ((await kv.get(key)).value != null) { await kv.delete(key); deleted++; }
      }
    }
  }
  // تصفير حالة اعتماد القطاع أيضاً عند تصفير القطاع
  if (scope === "sector") {
    const sid = p.sid || body.sid;
    for (const y of years) {
      const k = ["submission", y, sid];
      if ((await kv.get(k)).value != null) { await kv.delete(k); deleted++; }
    }
  }
  await logAction(kv, actorOf(p), "reset-scoped", scope + ":" + (scope === "entity" ? body.eid : (p.sid || body.sid)) + " سنة:" + (year || "الكل") + " (" + deleted + " مفتاح)");
  return json({ ok: true, deleted, scope, entities: targetEids.length });
}

async function handleYearOpen(request) {
  const p = await verifyToken(bearer(request));
  if (!p || p.role !== "admin") return json({ error: "الفتح لمدير عام شؤون المدارس فقط" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  const year = (body.year || "").toString();
  if (!yearEditable(year) || year === currentSchoolYear()) return json({ error: "لا يمكن التحكّم في فتح هذه السنة" }, 400);
  let kv; try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  const open = !!body.open;
  await kv.set(["yearOpen", year], open);
  await logAction(kv, actorOf(p), "year-open", (open ? "فتح" : "إغلاق") + " السنة " + year + " للجهات");
  return json({ ok: true, year, open });
}

async function handleAdmin(request) {
  const p = await verifyToken(bearer(request));
  if (!p || p.role !== "admin") return json({ error: "غير مصرح" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  const year = reqYear(request, body);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة — اربطها من Databases ثم أعد النشر" }, 503); }
  const agg = await aggregate(kv, year);
  const allEids = Object.keys(plans);
  agg.timeline = await recentUpdates(kv, allEids, 10, year);
  agg.byAxis = await aggregateByAxis(kv, year, allEids);
  agg.year = year; agg.currentYear = currentSchoolYear(); agg.nextYear = nextSchoolYear(); agg.years = schoolYears();
  agg.editableYear = await effectiveEditable(kv, year, true);
  agg.yearIsOpen = await yearOpened(kv, year); agg.canOpenYears = true; agg.yearInWindow = yearEditable(year);
  // حالة فتح كل السنوات ضمن النافذة (للوحة تحكّم المدير)
  const openMap = {};
  for (const y of schoolYears()) { if (yearEditable(y)) openMap[y] = await yearOpened(kv, y); }
  agg.yearOpenMap = openMap;
  return json(agg);
}

// رفع تقرير القطاع للاعتماد من المدير العام
async function handleReportSubmit(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  const action = body.action || "submit";
  const year = reqYear(request, body);
  if (action === "submit") {
    if (!p.sid) return json({ error: "الرفع للاعتماد متاح لمنسق القطاع فقط" }, 403);
    if (!(await effectiveEditable(kv, year, false))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد من مدير عام شؤون المدارس" }, 423);
    if (!body.pdf || !body.pdfName) return json({ error: "يلزم إرفاق ملف PDF للتقرير قبل الرفع للاعتماد" }, 400);
    // الحد 2 ميجابايت للملف الفعلي (base64 يضخّمه ~1.37×)
    if (body.pdf.length > 2_800_000) return json({ error: "ملف PDF كبير جداً (الحد 2MB)" }, 400);
    const subs = (await kv.get(["reportSubs", year])).value || {};
    subs[p.sid] = { sid: p.sid, name: sectors[p.sid]?.name || "", by: whoLabel(p), at: new Date().toISOString(), status: "pending", approvedBy: null, approvedAt: null, unlocked: false, pdfName: body.pdfName.slice(0, 120) };
    await kv.set(["reportSubs", year], subs);
    await kv.set(["reportPdf", year, p.sid], { name: body.pdfName.slice(0, 120), data: body.pdf, at: new Date().toISOString() });
    return json({ ok: true });
  } else if (action === "list") {
    if (p.role !== "admin") return json({ error: "غير مصرح" }, 403);
    const subs = (await kv.get(["reportSubs", year])).value || {};
    return json({ ok: true, submissions: Object.values(subs) });
  } else if (action === "getPdf") {
    if (p.role !== "admin") return json({ error: "غير مصرح" }, 403);
    const pdf = (await kv.get(["reportPdf", year, body.sid])).value;
    return json({ ok: true, pdf: pdf || null });
  } else if (action === "approve") {
    if (p.role !== "admin") return json({ error: "الاعتماد للمدير العام فقط" }, 403);
    const subs = (await kv.get(["reportSubs", year])).value || {};
    if (subs[body.sid]) { subs[body.sid].status = "approved"; subs[body.sid].unlocked = false; subs[body.sid].approvedBy = whoLabel(p); subs[body.sid].approvedAt = new Date().toISOString(); await kv.set(["reportSubs", year], subs); }
    return json({ ok: true, submissions: Object.values(subs) });
  } else if (action === "unlock") {
    if (p.role !== "admin") return json({ error: "التصريح للمدير العام فقط" }, 403);
    const subs = (await kv.get(["reportSubs", year])).value || {};
    if (subs[body.sid]) { subs[body.sid].unlocked = true; await kv.set(["reportSubs", year], subs); }
    return json({ ok: true, submissions: Object.values(subs) });
  } else if (action === "return") {
    // المدير يُرجع التقرير للقطاع للتعديل/إعادة الرفع (قبل الاعتماد أو بعده) مع ملاحظات اختيارية
    if (p.role !== "admin") return json({ error: "الإرجاع للمدير العام فقط" }, 403);
    const subs = (await kv.get(["reportSubs", year])).value || {};
    const s = subs[body.sid];
    if (!s) return json({ error: "لا يوجد تقرير مرفوع لهذا القطاع" }, 404);
    const notes = (body.notes || "").toString().slice(0, 1000);
    s.status = "returned"; s.unlocked = false; s.returnedBy = whoLabel(p); s.returnedAt = new Date().toISOString(); s.returnNotes = notes;
    s.approvedBy = null; s.approvedAt = null;
    await kv.set(["reportSubs", year], subs);
    // إشعار كل إدارات القطاع (المنسّق يراها عبر إشعارات القطاع)
    const firstEid = (sectors[body.sid]?.entity_ids || [])[0];
    if (firstEid) await pushNotify(kv, firstEid, "reportReturn", "أُرجِع تقرير القطاع للتعديل وإعادة الرفع" + (notes ? " — " + notes.slice(0, 80) : ""), null, p, ["sector"], year);
    await logAction(kv, actorOf(p), "report-return", "إرجاع تقرير قطاع " + (sectors[body.sid]?.name || "") + " للتعديل" + (notes ? " — " + notes.slice(0, 60) : ""));
    return json({ ok: true, submissions: Object.values(subs) });
  } else if (action === "mine") {
    const subs = (await kv.get(["reportSubs", year])).value || {};
    return json({ ok: true, mine: p.sid ? (subs[p.sid] || null) : null });
  }
  return json({ error: "إجراء غير معروف" }, 400);
}

// إنهاء استعداد الإدارة: الإدارة تعلن الانتهاء (بمبرر مجمّع إن كانت أقل من 100%) → تُقفل → إشعار المنسّق والمدير → يفكّها المنسّق/المدير
async function handleEntityDone(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة، أعد الدخول" }, 401);
  let body;
  try { body = await request.json(); } catch { return json({ error: "bad request" }, 400); }
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  const action = body.action || "finish";
  const year = reqYear(request, body);
  const eid = body.eid;

  if (action === "finish") {
    if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
    if (!canAccess(p, eid)) return json({ error: "غير مصرح" }, 403);
    if (!(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد" }, 423);
    // احسب النسبة والمؤشرات الناقصة
    const rec = (await kv.get(["plan", year, eid])).value || { updates: {} };
    const ov = (await kv.get(["overrides", year, eid])).value || {};
    const items = mergedItems(eid, ov).filter((it) => !it.transferredTo);
    const updates = rec.updates || {};
    let done = 0, sum = 0; const incomplete = [];
    items.forEach((it) => {
      const st = statusOf(it, updates[it._idx]);
      if (["مكتمل", "منجز", "تم"].includes(st)) { done++; sum += 100; }
      else { sum += (st === "قيد التنفيذ") ? ((it.measure === "نسبة" && updates[it._idx]) ? +updates[it._idx].v : 50) : ((st === "متأخر" && it.measure === "نسبة" && updates[it._idx]) ? +updates[it._idx].v : 0); incomplete.push({ index: it._idx, proc: it.proc, axis: it.axis || "", status: st }); }
    });
    const overall = items.length ? Math.round(sum / items.length) : 0;
    const justification = (body.justification || "").toString().trim().slice(0, 2000);
    if (overall < 100 && !justification) return json({ error: "النسبة أقل من 100% — يلزم كتابة مبرر مجمّع قبل الإنهاء" }, 400);
    const store = (await kv.get(["entityDone", year])).value || {};
    store[eid] = {
      eid, name: plans[eid].name, by: whoLabel(p), at: new Date().toISOString(),
      overall, total: items.length, done, incomplete, justification,
      status: "done", locked: true, reopenedBy: null,
    };
    await kv.set(["entityDone", year], store);
    // إشعار المنسّق والمدير
    await pushNotify(kv, eid, "entityDone", "أعلنت الإدارة انتهاء استعدادها (" + overall + "%)" + (overall < 100 ? " مع مبرر للنقص" : " — مكتمل 100%"), null, p, ["sector", "admin"], year);
    await logAction(kv, actorOf(p), "entity-done", "إنهاء استعداد إدارة " + plans[eid].name + " (" + overall + "%)");
    return json({ ok: true, entry: store[eid] });
  } else if (action === "reopen") {
    if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
    // المنسّق (لقطاعه) أو المدير
    const ownSector = p.sid && (sectors[p.sid]?.entity_ids || []).includes(eid);
    if (p.role !== "admin" && !ownSector) return json({ error: "فكّ القفل لمنسّق القطاع أو المدير" }, 403);
    const store = (await kv.get(["entityDone", year])).value || {};
    if (store[eid]) {
      store[eid].status = "reopened"; store[eid].locked = false; store[eid].reopenedBy = whoLabel(p); store[eid].reopenedAt = new Date().toISOString();
      await kv.set(["entityDone", year], store);
      await pushNotify(kv, eid, "entityDone", "أُعيد فتح الإدارة للتعديل من " + whoLabel(p), null, p, ["entity"], year);
      await logAction(kv, actorOf(p), "entity-reopen", "فكّ قفل إدارة " + plans[eid].name);
    }
    return json({ ok: true, entry: store[eid] || null });
  } else if (action === "edit-justification") {
    // تعديل المبرر (المنسّق/المدير) دون فكّ القفل بالضرورة
    if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
    const ownSector = p.sid && (sectors[p.sid]?.entity_ids || []).includes(eid);
    if (p.role !== "admin" && !ownSector && !canAccess(p, eid)) return json({ error: "غير مصرح" }, 403);
    const store = (await kv.get(["entityDone", year])).value || {};
    if (store[eid]) { store[eid].justification = (body.justification || "").toString().trim().slice(0, 2000); store[eid].editedBy = whoLabel(p); store[eid].editedAt = new Date().toISOString(); await kv.set(["entityDone", year], store); }
    return json({ ok: true, entry: store[eid] || null });
  } else if (action === "mine") {
    const store = (await kv.get(["entityDone", year])).value || {};
    return json({ ok: true, entry: (eid && store[eid]) ? store[eid] : null });
  } else if (action === "list") {
    // المنسّق يرى إدارات قطاعه، المدير يرى الكل
    const store = (await kv.get(["entityDone", year])).value || {};
    let rows = Object.values(store);
    if (p.role !== "admin") {
      if (!p.sid) return json({ error: "غير مصرح" }, 403);
      const inSec = sectors[p.sid]?.entity_ids || [];
      rows = rows.filter((r) => inSec.includes(r.eid));
    }
    return json({ ok: true, rows });
  }
  return json({ error: "إجراء غير معروف" }, 400);
}

// الإشعارات: جلب/تعليم كمقروء
async function handleNotify(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  const year = reqYear(request, body);
  let kv; try { kv = await getKv(); } catch { return json({ ok: true, notes: [] }); }
  let key;
  if (p.sid) key = ["notify", "sector", year, p.sid];
  else if (p.eid) key = ["notify", "entity", year, p.eid];
  else if (p.role === "admin") key = ["notify", "admin", year];
  else key = null;
  if (body.action === "markRead" && key) {
    const arr = ((await kv.get(key)).value || []).map((n) => ({ ...n, read: true }));
    await kv.set(key, arr);
    return json({ ok: true });
  }
  const notes = key ? ((await kv.get(key)).value || []) : [];
  return json({ ok: true, notes, unread: notes.filter((n) => !n.read).length });
}

// مبررات التأخير (نقطة 5)
async function handleJustify(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة" }, 401);
  let body; try { body = await request.json(); } catch { return json({ error: "bad" }, 400); }
  const eid = body.eid;
  if (!eid || !plans[eid]) return json({ error: "جهة غير معروفة" }, 400);
  if (!canComment(p, eid)) return json({ error: "غير مصرح" }, 403);
  const year = reqYear(request, body);
  if (!yearEditable(year)) return json({ error: "السنة الدراسية مؤرشفة للقراءة فقط" }, 423);
  let kv; try { kv = await getKv(); } catch { return json({ error: "KV غير مربوطة" }, 503); }
  if (!(await effectiveEditable(kv, year, p.role === "admin"))) return json({ error: "السنة الدراسية " + year + " لم تُفتح بعد من مدير عام شؤون المدارس" }, 423);
  const j = (await kv.get(["justify", year, eid])).value || {};
  j[String(body.index)] = { text: (body.text || "").slice(0, 500), by: whoLabel(p), at: new Date().toISOString() };
  await kv.set(["justify", year, eid], j);
  return json({ ok: true, justify: j });
}

// إحصائيات القطاع لمنسقه (لعرض الرسوم تحت أيقونات الإدارات)
async function handleSectorStats(request) {
  const p = await verifyToken(bearer(request));
  if (!p || !p.sid) return json({ error: "غير مصرح" }, 401);
  let body; try { body = await request.json(); } catch { body = {}; }
  const year = reqYear(request, body);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  const agg = await aggregate(kv, year);
  const sec = agg.sectors.find((s) => s.id === p.sid);
  const submission = (await kv.get(["submission", year, p.sid])).value || null;
  const timeline = await recentUpdates(kv, sectors[p.sid]?.entity_ids || [], 10, year);
  const byAxis = await aggregateByAxis(kv, year, sectors[p.sid]?.entity_ids || []);
  return json({ sector: sec || null, submission, timeline, byAxis, year, currentYear: currentSchoolYear(), nextYear: nextSchoolYear(), years: schoolYears(), editableYear: await effectiveEditable(kv, year, false), yearIsOpen: await yearOpened(kv, year), canOpenYears: false, yearInWindow: yearEditable(year) });
}
// رفع تقرير القطاع للاعتماد (المنسق) / عرض المرفوعة (المدير)
async function handleSubmit(request) {
  const p = await verifyToken(bearer(request));
  if (!p) return json({ error: "انتهت الجلسة" }, 401);
  let kv;
  try { kv = await getKv(); } catch { return json({ error: "قاعدة KV غير مربوطة" }, 503); }
  let body;
  try { body = await request.json(); } catch { body = {}; }
  if (body.action === "submit") {
    if (!p.sid) return json({ error: "الرفع لمنسق القطاع فقط" }, 403);
    const sub = { sid: p.sid, sector: sectors[p.sid]?.name, by: whoLabel(p), at: new Date().toISOString(), status: "مرفوع للاعتماد", approvedBy: null, approvedAt: null };
    await kv.set(["submission", p.sid], sub);
    return json({ ok: true, submission: sub });
  }
  if (body.action === "approve") {
    if (p.role !== "admin") return json({ error: "الاعتماد للمدير العام فقط" }, 403);
    const sub = (await kv.get(["submission", body.sid])).value;
    if (sub) { sub.status = "معتمد"; sub.approvedBy = whoLabel(p); sub.approvedAt = new Date().toISOString(); await kv.set(["submission", body.sid], sub); }
    return json({ ok: true, submission: sub });
  }
  if (body.action === "list") {
    if (p.role !== "admin") return json({ error: "غير مصرح" }, 403);
    const subs = [];
    for (const sid of Object.keys(sectors)) {
      const s = (await kv.get(["submission", sid])).value;
      if (s) subs.push(s);
    }
    return json({ submissions: subs });
  }
  return json({ error: "إجراء غير معروف" }, 400);
}

// التقرير الرسمي (HTML قابل للطباعة PDF) — مكتب مدير عام شؤون المدارس
async function handleReport(request) {
  const token = new URL(request.url).searchParams.get("t") || bearer(request);
  const p = await verifyToken(token);
  if (!p || (p.role !== "admin" && !p.sid)) {
    return new Response("<h3 style='font-family:Arial;text-align:center;padding:40px'>غير مصرح — يلزم دخول المشرف أو منسق قطاع</h3>",
      { status: 401, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  let kv;
  try { kv = await getKv(); } catch {
    return new Response("<h3 style='font-family:Arial;text-align:center;padding:40px'>قاعدة KV غير مربوطة</h3>",
      { status: 503, headers: { "Content-Type": "text/html; charset=utf-8" } });
  }
  const year = reqYear(request);
  let agg = await aggregate(kv, year);
  // منسق القطاع يرى قطاعه فقط
  if (p.sid) agg = { sectors: agg.sectors.filter((s) => s.id === p.sid), unclassified: [] };
  // بيانات تفصيلية لكل إدارة (للصفحات الإضافية)
  const detail = {};
  const doneStore = (await kv.get(["entityDone", year])).value || {};
  const entIds = agg.sectors.flatMap((s) => s.entities.map((e) => e.id)).concat((agg.unclassified || []).map((e) => e.id));
  for (const eid of entIds) {
    const rec = (await kv.get(["plan", year, eid])).value || { updates: {}, times: {} };
    const ov = (await kv.get(["overrides", year, eid])).value || { edits: {}, added: [] };
    detail[eid] = { items: mergedItems(eid, ov), updates: rec.updates || {}, times: rec.times || {}, done: doneStore[eid] || null };
  }
  // مبررات الإدارات التي أعلنت الانتهاء بأقل من 100%
  const justifications = entIds.map((eid) => doneStore[eid]).filter((d) => d && d.justification).map((d) => ({ name: d.name, overall: d.overall, justification: d.justification, incomplete: (d.incomplete || []).length, at: d.at }));
  const ctx = p.sid ? { name: sectors[p.sid]?.name || "", isSector: true, year } : { year };
  // تجميع حسب المحور ضمن نطاق التقرير
  const axisScope = entIds;
  const byAxis = await aggregateByAxis(kv, year, axisScope);
  const html = renderReport(agg, detail, ctx, byAxis, justifications);
  return new Response(html, { headers: { "Content-Type": "text/html; charset=utf-8" } });
}

function bar(pct, color) {
  return `<div style="background:#eef2f7;border-radius:5px;height:9px;width:80px;display:inline-block;vertical-align:middle;overflow:hidden"><div style="height:100%;width:${pct}%;background:${color}"></div></div>`;
}
function colorFor(pct) { return pct >= 80 ? "#2e9e5b" : pct >= 50 ? "#e8a800" : "#d6453d"; }

// ===== مولّد رسوم SVG مشترك (اللوحة + التقرير) — بلا مكتبات خارجية =====
// كل دالة تُرجع نص SVG جاهز للإدراج، يعمل في المتصفح وفي طباعة PDF.

const CH_GREEN="#2e9e5b", CH_AMBER="#e8a800", CH_RED="#d6453d", CH_GREY="#cbd5e1", CH_NAVY="#1F3864", CH_BLUE="#2E5395";

// حلقة الإنجاز الكلية (donut) مع النسبة في المنتصف
function donutChart(pct, size, label){
  size=size||160; const sw=size*0.14, r=(size-sw)/2, cx=size/2, cy=size/2, circ=2*Math.PI*r;
  const col=pct>=80?CH_GREEN:pct>=50?CH_AMBER:CH_RED;
  const off=circ*(1-pct/100);
  return `<svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" style="display:block">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#eef2f7" stroke-width="${sw}"/>
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${col}" stroke-width="${sw}"
      stroke-linecap="round" stroke-dasharray="${circ}" stroke-dashoffset="${off}"
      transform="rotate(-90 ${cx} ${cy})" style="transition:stroke-dashoffset 1s ease"/>
    <text x="${cx}" y="${cy-2}" text-anchor="middle" dominant-baseline="central" font-size="${size*0.24}" font-weight="800" fill="${CH_NAVY}" font-family="Arial">${pct}%</text>
    ${label?`<text x="${cx}" y="${cy+size*0.17}" text-anchor="middle" font-size="${size*0.09}" fill="#64748b" font-family="Arial">${label}</text>`:''}
  </svg>`;
}

// أعمدة رأسية — الرسم بـ SVG والأسماء بـ HTML (لضمان اتجاه عربي سليم في PDF)
function barsChart(items, width){
  if(!items||!items.length)return '<div style="padding:30px;text-align:center;color:#94a3b8;font-size:13px">لا توجد بيانات كافية للعرض</div>';
  const chartH=200, maxBarH=150, topPad=30;
  // كل عمود: خانة flex فيها الرقم فوق + عمود ملوّن + الاسم تحته (HTML)
  let cols="";
  items.forEach((it)=>{
    const col=it.pct>=80?CH_GREEN:it.pct>=50?CH_AMBER:CH_RED;
    const bh=Math.max(4,Math.round(maxBarH*it.pct/100));
    cols+=`<div style="flex:1 1 0;min-width:0;display:flex;flex-direction:column;align-items:center;padding:0 6px">
      <div style="height:${topPad}px;display:flex;align-items:flex-end;font-size:14px;font-weight:800;color:${col};font-family:Arial">${it.pct}%</div>
      <div style="height:${maxBarH}px;width:100%;max-width:46px;display:flex;align-items:flex-end;background:#f1f5f9;border-radius:6px;overflow:hidden">
        <div style="width:100%;height:${bh}px;background:${col};border-radius:6px"></div>
      </div>
      <div style="margin-top:8px;font-size:8px;line-height:1.25;color:${CH_NAVY};font-weight:600;text-align:center;direction:rtl;overflow-wrap:break-word;word-break:break-word;min-height:32px;max-width:100%;padding:0 2px">${it.name}</div>
    </div>`;
  });
  return `<div style="display:flex;align-items:flex-start;justify-content:space-around;gap:0;width:100%;direction:rtl;padding:0 4px">${cols}</div>`;
}

// دونت توزيع حالة المؤشرات كنسبة من الإجمالي
function stackedStatus(done,prog,late,no,width){
  // دونت: كل حالة كنسبة من إجمالي المؤشرات
  const tot=done+prog+late+no||1;
  const size=200, sw=34, r=(size-sw)/2, cx=size/2, cy=size/2, circ=2*Math.PI*r;
  const segs=[[done,CH_GREEN,'مكتمل'],[prog,CH_AMBER,'قيد التنفيذ'],[late,CH_RED,'متأخر'],[no,CH_GREY,'لم يبدأ']];
  let off=0, arcs="";
  segs.forEach(([v,c])=>{
    if(v<=0)return;
    const frac=v/tot, len=circ*frac;
    arcs+=`<circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${c}" stroke-width="${sw}"
      stroke-dasharray="${len} ${circ-len}" stroke-dashoffset="${-off}"
      transform="rotate(-90 ${cx} ${cy})"/>`;
    off+=len;
  });
  const donut=`<svg viewBox="0 0 ${size} ${size}" width="200" height="200" style="display:block">
    <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#f1f5f9" stroke-width="${sw}"/>
    ${arcs}
    <text x="${cx}" y="${cy-6}" text-anchor="middle" font-size="30" font-weight="800" fill="${CH_NAVY}" font-family="Arial">${tot}</text>
    <text x="${cx}" y="${cy+18}" text-anchor="middle" font-size="12" fill="#64748b" font-family="Arial">إجمالي المؤشرات</text>
  </svg>`;
  // legend with counts + percentages
  let leg='<div style="display:flex;flex-direction:column;gap:10px;justify-content:center">';
  segs.forEach(([v,c,lbl])=>{
    const pct=Math.round(v/tot*100);
    leg+=`<div style="display:flex;align-items:center;gap:10px;font-family:Arial">
      <span style="width:16px;height:16px;border-radius:4px;background:${c};display:inline-block;flex-shrink:0"></span>
      <span style="font-size:14px;color:#334155;font-weight:600;min-width:90px">${lbl}</span>
      <span style="font-size:15px;font-weight:800;color:${c}">${pct}%</span>
      <span style="font-size:12px;color:#94a3b8">(${v})</span></div>`;
  });
  leg+='</div>';
  return `<div style="display:flex;gap:36px;align-items:center;justify-content:center;flex-wrap:wrap;direction:rtl;width:100%">${leg}${donut}</div>`;
}

function renderReport(agg, detail, sectorCtx, byAxis, justifications) {
  const escR = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const allEnts = agg.sectors.flatMap((s) => s.entities).concat(agg.unclassified || []);
  const totItems = allEnts.reduce((a, e) => a + e.total, 0);
  const totDone = allEnts.reduce((a, e) => a + e.done, 0);
  const totProg = allEnts.reduce((a, e) => a + e.prog, 0);
  const totNo = allEnts.reduce((a, e) => a + e.no, 0);
  const totLate = allEnts.reduce((a, e) => a + e.late, 0);
  // النسبة المرجّحة بعدد المؤشرات (الأدق): مجموع (نسبة كل إدارة × عدد مؤشراتها) ÷ إجمالي المؤشرات
  const wsum = allEnts.reduce((a, e) => a + (e.overall * e.total), 0);
  const weightedOverall = totItems ? Math.round(wsum / totItems) : 0;
  // متوسط نسب الإدارات (وزن متساوٍ لكل إدارة)
  const avgOverall = allEnts.length ? Math.round(allEnts.reduce((a, e) => a + e.overall, 0) / allEnts.length) : 0;
  const overall = weightedOverall; // النسبة الرسمية = المرجّحة
  // طباعة التقرير بالتاريخ فقط (لا الساعة)
  const today = new Date().toLocaleDateString("ar-BH", { year: "numeric", month: "long", day: "numeric" });
  // للقطاع: أظهر إداراته كأعمدة؛ للمدير: أظهر القطاعات
  const isSectorReport = !!(sectorCtx && sectorCtx.isSector);
  const barsData = isSectorReport
    ? (agg.sectors[0] ? agg.sectors[0].entities.map((e) => ({ name: e.name, pct: e.overall })) : [])
    : agg.sectors.map((s) => ({ name: s.name, pct: s.weighted != null ? s.weighted : s.overall }));
  const barsTitle = isSectorReport ? "إنجاز الإدارات" : "معدلات إنجاز القطاعات";
  // صفحات تفصيلية لكل إدارة
  let detailPages = "";
  if (detail) {
    const esc2 = (s) => String(s == null ? "" : s).replace(/[&<>]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;" }[c]));
    for (const e of allEnts) {
      const d = detail[e.id];
      if (!d) continue;
      let rows = "";
      d.items.forEach((it, i) => {
        const u = d.updates[i];
        const st = statusOf(it, u);
        const pv = pctOf(it, u);
        let val = "—";
        if (it.measure === "عدد-إنجاز" && u) val = `${u.done || 0} / ${u.ref || 0} (${pv}%)`;
        else if (it.measure === "نسبة" && u) val = pv + "%";
        else if (it.measure === "عدد" && u) val = (u.v || 0) + "";
        else if (u && u.v) val = esc2(u.v);
        const t = d.times[i] ? (new Date(d.times[i]).toLocaleDateString("ar-BH") + " " + new Date(d.times[i]).toLocaleTimeString("ar-BH", { hour: "2-digit", minute: "2-digit" })) : "—";
        rows += `<tr><td class="ent" style="max-width:340px">${esc2(it.proc)}</td><td class="ctr">${it.measure}</td><td class="ctr">${val}</td><td class="ctr"><span style="color:${st === "مكتمل" || st === "منجز" ? "#2e9e5b" : st === "قيد التنفيذ" ? "#e8a800" : st === "متأخر" ? "#d6453d" : "#94a3b8"};font-weight:700">${st}</span></td><td class="ctr">${t}</td></tr>`;
      });
      detailPages += `<div class="sector" style="page-break-before:always"><div class="sec-head"><span>تقرير تفصيلي — ${e.name}</span><span>الإنجاز: ${e.overall}% — ${e.total} مؤشر</span></div>
        <table><thead><tr><th style="text-align:right">المؤشر / الإجراء</th><th>القياس</th><th>القيمة</th><th>الحالة</th><th>آخر تحديث</th></tr></thead><tbody>${rows}</tbody></table></div>`;
    }
  }

  let sectorsHtml = "";
  for (const s of agg.sectors) {
    let rows = "";
    s.entities.forEach((e, i) => {
      rows += `<tr style="background:${i % 2 ? "#f7f9fc" : "#fff"}">
        <td class="ent">${e.name}</td>
        <td class="ctr">${bar(e.overall, colorFor(e.overall))} <b>${e.overall}%</b></td>
        <td class="ctr">${e.done}</td><td class="ctr">${e.prog}</td><td class="ctr">${e.late}</td><td class="ctr">${e.no}</td><td class="ctr">${e.total}</td></tr>`;
    });
    sectorsHtml += `<div class="sector">
      <div class="sec-head"><span>${s.name}</span><span>الإنجاز: ${s.overall}% — ${s.total} مؤشر</span></div>
      <table><thead><tr>
        <th style="text-align:right">الإدارة</th><th>نسبة الإنجاز</th><th>مكتمل</th><th>قيد التنفيذ</th><th>متأخر</th><th>لم يبدأ</th><th>الإجمالي</th>
      </tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  let unclHtml = "";
  if (agg.unclassified && agg.unclassified.length) {
    const u = agg.unclassified[0];
    unclHtml = `<div class="sector"><div class="sec-head" style="background:#94a3b8"><span>مؤشرات غير مصنّفة</span><span>${u.total} مؤشر</span></div>
      <table><tbody><tr><td class="ent">${u.name}</td><td class="ctr">${bar(u.overall, colorFor(u.overall))} <b>${u.overall}%</b></td><td class="ctr">${u.done}</td><td class="ctr">${u.prog}</td><td class="ctr">${u.late}</td><td class="ctr">${u.no}</td><td class="ctr">${u.total}</td></tr></tbody></table></div>`;
  }

  // ===== قسم التحليل حسب المحور (البُعد) =====
  let axisHtml = "";
  if (byAxis && byAxis.length) {
    const esc2 = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const troubledAxes = byAxis.filter((a) => a.troubled);
    const isExemptYear = byAxis.length && byAxis[0].exempt;
    const exemptNote = isExemptYear
      ? `<div style="background:#eef6ff;border:1px solid #bcdcff;color:#1e5fa8;border-radius:10px;padding:11px 14px;margin:14px 0;font-size:12.5px"><b>ملاحظة:</b> السنة الدراسية ٢٠٢٥-٢٠٢٦ مستثناة من احتساب التأخّر (فُعّلت المنصة بعد انتهائها) — تُعرض نسب الإنجاز الفعلية دون اعتبار أي جهة "خلف الجدول الزمني".</div>`
      : "";
    // 1) جدول ملخّص كل المحاور (مرتّب: الأكثر تعثراً أولاً)
    let axisRows = "";
    byAxis.forEach((a, i) => {
      const flag = a.troubled ? '<span style="color:#d6453d;font-weight:800">●</span> ' : '<span style="color:#2e9e5b">●</span> ';
      axisRows += `<tr style="background:${a.troubled ? "#fdf0ef" : (i % 2 ? "#f7f9fc" : "#fff")}">
        <td class="ent">${flag}${esc2(a.axis)}</td>
        <td class="ctr">${bar(a.overall, colorFor(a.overall))} <b>${a.overall}%</b></td>
        <td class="ctr">${a.done}</td><td class="ctr">${a.prog}</td>
        <td class="ctr" style="${a.late ? "color:#d6453d;font-weight:700" : ""}">${a.late}</td>
        <td class="ctr" style="${a.no ? "color:#b45309;font-weight:700" : ""}">${a.no}</td>
        <td class="ctr">${a.total}</td></tr>`;
    });
    // شبكة دونتات مصغّرة لكل محور (عدّادات بصرية)
    const miniDonut = (pct, name) => {
      const size = 76, sw = 9, r = (size - sw) / 2, cx = size / 2, cy = size / 2, circ = 2 * Math.PI * r;
      const col = pct >= 80 ? "#2e9e5b" : pct >= 50 ? "#e8a800" : "#d6453d";
      const off = circ * (1 - pct / 100);
      return `<div class="mdon"><svg viewBox="0 0 ${size} ${size}" width="${size}" height="${size}" style="display:block">
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="#eef2f7" stroke-width="${sw}"/>
        <circle cx="${cx}" cy="${cy}" r="${r}" fill="none" stroke="${col}" stroke-width="${sw}" stroke-linecap="round" stroke-dasharray="${circ}" stroke-dashoffset="${off}" transform="rotate(-90 ${cx} ${cy})"/>
        <text x="${cx}" y="${cy + 5}" text-anchor="middle" font-size="16" font-weight="800" fill="#1F3864" font-family="Arial">${pct}%</text>
      </svg><div class="mdon-name">${esc2(name)}</div></div>`;
    };
    const donutGrid = `<div class="donut-grid">${byAxis.map((a) => miniDonut(a.overall, a.axis)).join("")}</div>`;
    const summaryTable = `<div class="sector">
      <div class="sec-head" style="background:#0f766e"><span>التحليل حسب المحور (عبر الإدارات والقطاعات)</span><span>${byAxis.length} محور</span></div>
      <div class="donut-legend"><span style="color:#2e9e5b;font-weight:800">●</span> ٨٠٪ فأكثر &nbsp;•&nbsp; <span style="color:#e8a800;font-weight:800">●</span> ٥٠–٧٩٪ &nbsp;•&nbsp; <span style="color:#d6453d;font-weight:800">●</span> أقل من ٥٠٪</div>
      ${donutGrid}
      <table><thead><tr>
        <th style="text-align:right">المحور</th><th>نسبة الإنجاز</th><th>مكتمل</th><th>قيد التنفيذ</th><th>متأخر</th><th>لم يبدأ</th><th>الإجمالي</th>
      </tr></thead><tbody>${axisRows}</tbody></table></div>`;

    // 2) تفاصيل المحاور المتعثرة فقط: الإدارات المعطّلة + ما لم يُنجز
    let troubledHtml = "";
    if (troubledAxes.length) {
      troubledHtml += `<h2 style="font-size:15px;color:#d6453d;margin:22px 0 10px;border-right:4px solid #d6453d;padding-right:10px">المحاور المتعثرة — الجهات خلف الجدول الزمني وما لم يُنجز (${troubledAxes.length})</h2>`;
      for (const a of troubledAxes) {
        // جمّع المؤشرات غير المنجزة حسب الجهة
        const byEnt = {};
        (a.notDone || []).forEach((n) => { (byEnt[n.eid] = byEnt[n.eid] || []).push(n); });
        // لكل جهة: صف رأس + مؤشراتها المتأخرة مفصّلة تحته
        const entBlocks = (a.behind || []).map((b) => {
          const indRows = (byEnt[b.eid] || []).map((n) =>
            `<tr><td style="font-size:10.5px;color:#334155;padding:4px 8px;border-bottom:1px solid #f4f4f5">${esc2(n.proc || "").slice(0, 140)}</td>
             <td style="font-size:10px;color:#b45309;text-align:center;white-space:nowrap;padding:4px 8px;border-bottom:1px solid #f4f4f5">${esc2(n.delay || "")}</td>
             <td style="text-align:center;padding:4px 8px;border-bottom:1px solid #f4f4f5"><span style="background:${n.status === "متأخر" ? "#fde8e6;color:#d6453d" : "#fef3e2;color:#b45309"};padding:1px 7px;border-radius:6px;font-size:9.5px;font-weight:700">${esc2(n.status)}</span></td></tr>`
          ).join("");
          return `<div style="border:1px solid #fcd9a5;border-radius:9px;margin-bottom:9px;overflow:hidden;page-break-inside:avoid">
            <div style="background:#fff8ef;padding:7px 11px;display:flex;justify-content:space-between;align-items:center;border-bottom:1px solid #fcd9a5">
              <div style="font-size:12px;font-weight:700;color:#1F3864">${esc2(b.name)}${b.sector ? ' <span style="color:#94a3b8;font-weight:400">— ' + esc2(b.sector) + '</span>' : ""}</div>
              <div style="font-size:10.5px;color:#64748b"><span style="background:#fde8e6;color:#d6453d;padding:2px 8px;border-radius:6px;font-weight:700">${b.delayed} متأخر</span> من ${b.total} • <b style="color:#b45309">${esc2(b.delayLabel)}</b></div>
            </div>
            <table style="box-shadow:none"><tbody>${indRows}</tbody></table>
          </div>`;
        }).join("");
        troubledHtml += `<div class="sector" style="margin-bottom:16px">
          <div class="sec-head" style="background:#b45309;font-size:13px"><span>${esc2(a.axis)}</span><span>الإنجاز: ${a.overall}% • أُنجز ${a.done} من ${a.total}</span></div>
          <div style="border:1px solid #e2e8f0;border-top:none;border-radius:0 0 8px 8px;padding:11px 12px">
            <div style="font-size:12px;color:#475569;margin-bottom:8px"><b>الجهات خلف الجدول الزمني — ومؤشرات كل جهة:</b></div>
            ${entBlocks || '<span style="color:#94a3b8;font-size:11px">—</span>'}
          </div></div>`;
      }
    }
    axisHtml = `<div style="page-break-before:always"></div>${summaryTable}${exemptNote}${troubledHtml}`;
  }


  return `<!DOCTYPE html><html lang="ar" dir="rtl"><head><meta charset="UTF-8">
<title>التقرير الرسمي — جاهزية المدارس ${(sectorCtx&&sectorCtx.year)?sectorCtx.year:"2025-2026"}</title>
<style>
*{box-sizing:border-box;margin:0;padding:0;font-family:'Segoe UI','Tahoma',Arial,sans-serif;}
body{background:#fff;color:#1a2533;padding:28px;line-height:1.7;direction:rtl;text-align:right;}
td,th,.ent,.sec-head span{word-break:normal;overflow-wrap:break-word;}
td.ent{line-height:1.6;}
.sheet{max-width:900px;margin:0 auto;}
.logo{text-align:center;margin-bottom:8px;}
.logo img{max-width:520px;width:100%;}
.rule{height:3px;background:linear-gradient(90deg,#c8102e,#1F3864);border-radius:2px;margin:14px 0 20px;}
.office{text-align:center;font-size:15px;font-weight:700;color:#1F3864;margin-bottom:4px;}
.title{text-align:center;font-size:20px;font-weight:800;color:#1F3864;margin:14px 0 4px;}
.subtitle{text-align:center;font-size:13px;color:#64748b;margin-bottom:6px;}
.meta{display:flex;justify-content:space-between;font-size:12px;color:#475569;border-top:1px dashed #cbd5e1;border-bottom:1px dashed #cbd5e1;padding:8px 4px;margin:14px 0;}
.summary{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:16px 0 22px;}
.scard{background:#f7f9fc;border:1px solid #e2e8f0;border-radius:10px;padding:12px;text-align:center;}
.just-report-box{background:#fff8ec;border:1.5px solid #f0d9a8;border-radius:11px;padding:14px 16px;margin:0 0 18px;}
.just-report-h{font-size:14px;font-weight:800;color:#8a6d00;margin-bottom:11px;}
.just-report-item{background:#fff;border:1px solid #eee2c8;border-radius:9px;padding:10px 13px;margin-bottom:9px;}
.just-report-top{display:flex;justify-content:space-between;align-items:center;margin-bottom:5px;}
.just-report-name{font-size:13px;font-weight:700;color:#1F3864;}
.just-report-pct{font-size:13px;font-weight:800;color:#b45309;background:#fff3cd;border-radius:8px;padding:2px 10px;}
.just-report-text{font-size:12px;color:#334155;line-height:1.8;}
.just-report-meta{font-size:10.5px;color:#94a3b8;margin-top:6px;}
.scard .n{font-size:22px;font-weight:800;color:#1F3864;} .scard .l{font-size:11px;color:#64748b;margin-top:2px;}
.scard.hl .n{color:#2e9e5b;}
.charts{display:flex;gap:16px;margin:18px 0;align-items:stretch;}
.chart-box{background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:14px;display:flex;flex-direction:column;align-items:center;justify-content:center;page-break-inside:avoid;}
.chart-box.wide{flex:1;}
.chart-box.full{margin:0 0 22px;align-items:center;display:flex;flex-direction:column;}
.chart-title{font-size:12px;font-weight:700;color:#1F3864;margin-bottom:10px;text-align:center;}
.sector{margin-bottom:20px;page-break-inside:avoid;}
.sec-head{background:#1F3864;color:#fff;padding:9px 14px;border-radius:8px 8px 0 0;font-weight:700;font-size:14px;display:flex;justify-content:space-between;}
table{width:100%;border-collapse:collapse;box-shadow:0 1px 4px rgba(0,0,0,.06);}
th{background:#2E5395;color:#fff;padding:8px 6px;font-size:12px;text-align:center;}
td{padding:8px 6px;font-size:12px;border-bottom:1px solid #e2e8f0;}
td.ent{text-align:right;font-weight:600;color:#1F3864;} td.ctr{text-align:center;}
.foot{margin-top:34px;display:flex;justify-content:space-between;align-items:flex-end;}
.sign{text-align:center;font-size:13px;width:260px;}
.sign .line{border-top:1.5px solid #1a2533;margin-top:44px;padding-top:6px;font-weight:700;color:#1F3864;}
.sign .role{font-size:11px;color:#64748b;margin-top:2px;}
.stamp{font-size:10px;color:#94a3b8;text-align:left;}
.print-btn{position:fixed;top:16px;left:16px;background:#1F3864;color:#fff;border:none;padding:11px 20px;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer;box-shadow:0 3px 10px rgba(0,0,0,.2);}
.donut-grid{display:flex;flex-wrap:wrap;gap:8px;padding:12px;background:#f7fafc;border:1px solid #e2e8f0;border-top:none;direction:rtl;justify-content:flex-start;}
.mdon{width:88px;background:#fff;border:1px solid #e8edf3;border-radius:10px;padding:6px 3px 5px;text-align:center;display:inline-flex;flex-direction:column;align-items:center;vertical-align:top;page-break-inside:avoid;}
.mdon svg{display:block;}
.mdon-name{font-size:8.5px;color:#475569;margin-top:3px;line-height:1.25;min-height:22px;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;font-weight:600;word-break:break-word;padding:0 2px;}
.donut-legend{font-size:11px;color:#64748b;padding:8px 12px 0;background:#f7fafc;border:1px solid #e2e8f0;border-top:none;}
@media print{
  .print-btn{display:none;}
  body{padding:0;}
  /* الجداول الطويلة: اسمح بالتقسيم عبر الصفحات مع تكرار الرأس ومنع قطع الصف */
  table{page-break-inside:auto;}
  thead{display:table-header-group;}
  tr{page-break-inside:avoid;}
  /* لا تمنع تقسيم الأقسام الكبيرة (كي لا تُقتطع) */
  .sector{page-break-inside:auto;}
  /* اجعل رأس القسم لا ينفصل عمّا بعده */
  .sec-head{page-break-after:avoid;}
}
</style></head><body>
<button class="print-btn" onclick="window.print()">طباعة / حفظ PDF</button>
<div class="sheet">
  <div class="logo"><img src="${MOE_LOGO}" alt="وزارة التربية والتعليم"></div>
  <div class="rule"></div>
  <div class="office">${(sectorCtx && sectorCtx.isSector) ? sectorCtx.name : "مكتب مدير عام شؤون المدارس"}</div>
  <div class="title">${(sectorCtx && sectorCtx.isSector) ? "تقرير جاهزية المدارس — " + sectorCtx.name : "التقرير الموحّد لجاهزية المدارس — النتائج النهائية"}</div>
  <div class="subtitle">استمارة بدء العام الدراسي ${(sectorCtx&&sectorCtx.year)?sectorCtx.year.replace("-"," / "):"2025 / 2026"}${(sectorCtx&&sectorCtx.year&&sectorCtx.year<currentSchoolYear())?" — (أرشيف)":""}</div>
  <div class="meta"><span>تاريخ الإصدار: ${today}</span><span>مرجع: جاهزية المدارس / ${new Date().getFullYear()}</span></div>

  <div class="summary">
    <div class="scard hl"><div class="n">${weightedOverall}%</div><div class="l">نسبة الإنجاز (مرجّحة بالمؤشرات)</div></div>
    <div class="scard"><div class="n">${avgOverall}%</div><div class="l">متوسط نسب الإدارات</div></div>
    <div class="scard"><div class="n">${agg.sectors.length}</div><div class="l">عدد القطاعات</div></div>
    <div class="scard"><div class="n">${allEnts.length}</div><div class="l">عدد الإدارات</div></div>
    <div class="scard"><div class="n">${totItems}</div><div class="l">إجمالي المؤشرات</div></div>
  </div>
  <div style="background:#f7f9fc;border:1px solid #e2e8f0;border-radius:9px;padding:9px 13px;margin:0 0 18px;font-size:11.5px;color:#64748b;line-height:1.7">
    <b style="color:#1F3864">الفرق بين النسبتين:</b> النسبة المرجّحة (${weightedOverall}%) تحسب كل مؤشر بوزن متساوٍ (${totDone} مكتمل من ${totItems})، وهي الأدق للنتيجة الكلية.
    أما متوسط نسب الإدارات (${avgOverall}%) فيعطي كل إدارة وزناً متساوياً بغضّ النظر عن عدد مؤشراتها. الإدارات التي لا تملك مؤشرات مُستبعدة من الحسابين.
  </div>
  ${(justifications && justifications.length) ? `
  <div class="just-report-box">
    <div class="just-report-h">📋 مبررات الإدارات التي أعلنت الانتهاء بأقل من 100%</div>
    ${justifications.map((j) => `
      <div class="just-report-item">
        <div class="just-report-top"><span class="just-report-name">${escR(j.name)}</span><span class="just-report-pct">${j.overall}%</span></div>
        <div class="just-report-text">${escR(j.justification)}</div>
        <div class="just-report-meta">عدد المؤشرات غير المكتملة: ${j.incomplete} • تاريخ الإعلان: ${new Date(j.at).toLocaleDateString("ar")}</div>
      </div>`).join("")}
  </div>` : ""}

  <div class="chart-box full">
    <div class="chart-title">توزيع حالة المؤشرات على مستوى الوزارة</div>
    ${stackedStatus(totDone, totProg, totLate, totNo, 820)}
  </div>
  <div class="chart-box full">
    <div class="chart-title">${barsTitle}</div>
    ${barsChart(barsData, 820)}
  </div>

  ${sectorsHtml}
  ${unclHtml}
  ${axisHtml}

  <div class="foot">
    <div class="stamp">تقرير آلي صادر من منظومة متابعة جاهزية المدارس<br>وزارة التربية والتعليم — مملكة البحرين</div>
    <div class="sign"><div class="line">${(sectorCtx && sectorCtx.isSector) ? "وكيل " + sectorCtx.name : "مدير عام شؤون المدارس"}</div><div class="role">${(sectorCtx && sectorCtx.isSector) ? "اعتماد القطاع" : "الاعتماد النهائي"}</div></div>
  </div>
  ${detailPages}
</div>
</body></html>`;
}

// ===== static frontend =====
const INDEX_HTML = await Deno.readTextFile(new URL("./index.html", import.meta.url));

// ===== main server =====
Deno.serve(async (request) => {
  try {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/api/login" && request.method === "POST") return await handleLogin(request);
    if (path === "/api/entity" && request.method === "GET") return await handleEntity(request);
    if (path === "/api/save" && request.method === "POST") return await handleSave(request);
    if (path === "/api/indicator" && request.method === "POST") return await handleIndicator(request);
    if (path === "/api/transfer" && request.method === "POST") return await handleTransfer(request);
    if (path === "/api/upload" && request.method === "POST") return await handleUpload(request);
    if (path === "/api/comment" && request.method === "POST") return await handleComment(request);
    if (path === "/api/comment-edit" && request.method === "POST") return await handleCommentEdit(request);
    if (path === "/api/admin" && request.method === "POST") return await handleAdmin(request);
    if (path === "/api/year-open" && request.method === "POST") return await handleYearOpen(request);
    if (path === "/api/admin-reset" && request.method === "POST") return await handleAdminReset(request);
    if (path === "/api/scoped-reset" && request.method === "POST") return await handleScopedReset(request);
    if (path === "/api/sysadmin" && request.method === "POST") return await handleSysadmin(request);
    if (path === "/api/announce" && request.method === "POST") return await handleAnnounce(request);
    if (path === "/api/my-announcements" && request.method === "GET") return await handleMyAnnouncements(request);
    if (path === "/api/sector-stats" && request.method === "POST") return await handleSectorStats(request);
    if (path === "/api/notify" && request.method === "POST") return await handleNotify(request);
    if (path === "/api/justify" && request.method === "POST") return await handleJustify(request);
    if (path === "/api/report-submit" && request.method === "POST") return await handleReportSubmit(request);
    if (path === "/api/entity-done" && request.method === "POST") return await handleEntityDone(request);
    if (path === "/api/submit" && request.method === "POST") return await handleSubmit(request);
    if (path === "/api/report" && request.method === "GET") return await handleReport(request);
    if (path.startsWith("/api/")) return json({ error: "not found" }, 404);
    // serve frontend for everything else
    return new Response(INDEX_HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
  } catch (err) {
    return json({ error: "خطأ داخلي: " + (err && err.message ? err.message : String(err)) }, 500);
  }
});
