const JSON_HEADERS = {
  'content-type': 'application/json; charset=utf-8',
  'cache-control': 'no-store',
  'x-content-type-options': 'nosniff',
};

const enc = new TextEncoder();

function json(status, data) {
  return new Response(JSON.stringify(data), { status, headers: JSON_HEADERS });
}

function esc(value = '') {
  return String(value).replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
}

function hex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacSha256(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return crypto.subtle.sign('HMAC', key, enc.encode(message));
}

async function validateInitData(initData, env) {
  if (!env.BOT_TOKEN) throw new Error('BOT_TOKEN is not configured');
  if (!initData) return null;

  const params = new URLSearchParams(initData);
  const receivedHash = params.get('hash');
  if (!receivedHash) return null;
  params.delete('hash');

  const dataCheck = [...params.entries()]
    .sort(([a], [b]) => a.localeCompare(b))
    .map(([k, v]) => `${k}=${v}`)
    .join('\n');

  const secret = await hmacSha256(enc.encode('WebAppData'), env.BOT_TOKEN);
  const expected = hex(await hmacSha256(new Uint8Array(secret), dataCheck));
  if (!safeEqual(receivedHash.toLowerCase(), expected.toLowerCase())) return null;

  const maxAge = Number(env.INIT_DATA_MAX_AGE_SEC || 86400);
  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || Math.abs(Date.now() / 1000 - authDate) > maxAge) return null;

  try {
    return JSON.parse(params.get('user') || 'null');
  } catch {
    return null;
  }
}

async function telegram(method, payload, env) {
  if (!env.BOT_TOKEN) throw new Error('BOT_TOKEN is not configured');
  const res = await fetch(`https://api.telegram.org/bot${env.BOT_TOKEN}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
  const data = await res.json();
  if (!data.ok) throw new Error(data.description || 'telegram_api_error');
  return data.result;
}

async function isChannelMember(userId, env) {
  if (!env.BOT_TOKEN || !env.CHANNEL_ID) throw new Error('BOT_TOKEN / CHANNEL_ID not configured');
  const url = `https://api.telegram.org/bot${env.BOT_TOKEN}/getChatMember?chat_id=${encodeURIComponent(env.CHANNEL_ID)}&user_id=${encodeURIComponent(userId)}`;
  const res = await fetch(url);
  const data = await res.json();
  if (!data.ok) return false;
  const member = data.result || {};
  return ['creator', 'administrator', 'member'].includes(member.status) ||
    (member.status === 'restricted' && member.is_member === true);
}

async function readBody(request) {
  const text = await request.text();
  if (text.length > 200000) throw new Error('body_too_large');
  return text ? JSON.parse(text) : {};
}

async function verifiedUser(body, env, requireMembership = true) {
  const user = await validateInitData(body.initData || '', env);
  if (!user?.id) return { error: 'invalid_init_data' };
  if (requireMembership && !(await isChannelMember(user.id, env))) return { error: 'not_member', user };
  return { user };
}

async function apiAccess(request, env) {
  try {
    const body = await readBody(request);
    const v = await verifiedUser(body, env, false);
    if (v.error) return json(401, { allowed: false, error: v.error });
    const allowed = await isChannelMember(v.user.id, env);
    return json(200, {
      allowed,
      user: {
        id: v.user.id,
        first_name: v.user.first_name || '',
        username: v.user.username || '',
      },
    });
  } catch (error) {
    console.error('access', error);
    return json(500, { allowed: false, error: 'access_check_failed' });
  }
}

async function apiEvent(request, env) {
  try {
    const body = await readBody(request);
    const v = await verifiedUser(body, env, true);
    if (v.error) return json(v.error === 'not_member' ? 403 : 401, { ok: false, error: v.error });
    const event = String(body.event || '').slice(0, 64);
    if (!event) return json(400, { ok: false, error: 'event_required' });

    // MVP analytics: available in Cloudflare Worker logs without a database.
    console.log(JSON.stringify({
      type: 'business_lab_event',
      ts: new Date().toISOString(),
      userId: v.user.id,
      username: v.user.username || '',
      event,
      meta: body.meta && typeof body.meta === 'object' ? body.meta : {},
    }));
    return json(200, { ok: true });
  } catch (error) {
    console.error('event', error);
    return json(500, { ok: false, error: 'event_failed' });
  }
}

async function apiLead(request, env) {
  try {
    if (!env.OWNER_CHAT_ID) return json(503, { ok: false, error: 'owner_chat_not_configured' });
    const body = await readBody(request);
    const v = await verifiedUser(body, env, true);
    if (v.error) return json(v.error === 'not_member' ? 403 : 401, { ok: false, error: v.error });

    const d = body.diagnostic || {};
    const overall = Math.max(0, Math.min(100, Number(d.overall) || 0));
    const weak = String(d.weak || '').slice(0, 40);
    const weakScore = Math.max(0, Math.min(100, Number(d.weakScore) || 0));
    const rawPct = d.pct && typeof d.pct === 'object' ? d.pct : {};
    const names = {
      context: 'Цель и контекст',
      client: 'Клиент',
      competition: 'Конкуренты и альтернативы',
      journey: 'Путь клиента',
      architecture: 'Система и MVP',
      ai: 'Контекст для AI',
    };
    const pct = {};
    for (const k of Object.keys(names)) pct[k] = Math.max(0, Math.min(100, Number(rawPct[k]) || 0));

    const fullName = [v.user.first_name, v.user.last_name].filter(Boolean).join(' ') || 'Без имени';
    const username = v.user.username ? `@${v.user.username}` : 'username не указан';
    const userLink = v.user.username
      ? `https://t.me/${encodeURIComponent(v.user.username)}`
      : `tg://user?id=${v.user.id}`;
    const map = Object.keys(names).map((k) => `• ${names[k]}: <b>${pct[k]}%</b>`).join('\n');

    const text = `🟣 <b>НОВАЯ ЗАЯВКА · BUSINESS LAB</b>\n\n👤 <a href="${userLink}">${esc(fullName)}</a>\n${esc(username)} · ID <code>${v.user.id}</code>\n\n<b>Результат диагностики</b>\nОбщая ясность: <b>${overall}%</b>\nГлавная точка роста: <b>${esc(names[weak] || weak || 'не определено')} · ${weakScore}%</b>\n\n${map}\n\n<b>Группа:</b> старт 5 сентября · 10 человек · 7 000 ₽\n\n👉 Нажми на имя сверху, чтобы открыть диалог.`;

    await telegram('sendMessage', {
      chat_id: env.OWNER_CHAT_ID,
      text,
      parse_mode: 'HTML',
      disable_web_page_preview: true,
    }, env);

    console.log(JSON.stringify({
      type: 'business_lab_lead',
      ts: new Date().toISOString(),
      userId: v.user.id,
      username: v.user.username || '',
      overall,
      weak,
      weakScore,
    }));

    return json(200, { ok: true });
  } catch (error) {
    console.error('lead', error);
    return json(500, { ok: false, error: 'lead_failed' });
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (request.method === 'POST' && url.pathname === '/api/access') return apiAccess(request, env);
    if (request.method === 'POST' && url.pathname === '/api/event') return apiEvent(request, env);
    if (request.method === 'POST' && url.pathname === '/api/lead') return apiLead(request, env);
    if ((request.method === 'GET' || request.method === 'HEAD') && url.pathname === '/health') {
      return json(200, { ok: true, platform: 'cloudflare' });
    }

    return env.ASSETS.fetch(request);
  },
};
