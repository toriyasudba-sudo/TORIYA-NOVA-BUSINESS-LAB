const textEncoder = new TextEncoder();

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
  });
}

function hex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmac(keyBytes, message) {
  const key = await crypto.subtle.importKey(
    'raw', keyBytes,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, textEncoder.encode(message)));
}

async function validateInitData(initData, botToken, maxAgeSec = 86400) {
  if (!initData) return { ok: false, error: 'init_data_missing' };
  if (!botToken) return { ok: false, error: 'bot_token_missing' };

  const params = new URLSearchParams(initData);
  const hash = params.get('hash');
  if (!hash) return { ok: false, error: 'hash_missing' };

  const authDate = Number(params.get('auth_date') || 0);
  if (!authDate || Math.floor(Date.now() / 1000) - authDate > maxAgeSec) {
    return { ok: false, error: 'init_data_expired' };
  }

  const pairs = [];
  for (const [key, value] of params.entries()) {
    if (key !== 'hash') pairs.push([key, value]);
  }
  pairs.sort((a, b) => a[0].localeCompare(b[0]));
  const dataCheckString = pairs.map(([k, v]) => `${k}=${v}`).join('\n');

  const secretKey = await hmac(textEncoder.encode('WebAppData'), botToken);
  const calculated = hex(await hmac(secretKey, dataCheckString));
  if (!timingSafeEqual(calculated, hash.toLowerCase())) return { ok: false, error: 'hash_mismatch' };

  let user = null;
  try { user = JSON.parse(params.get('user') || 'null'); } catch {}
  if (!user?.id) return { ok: false, error: 'telegram_user_not_found' };

  return { ok: true, user, authDate };
}

async function telegram(env, method, body) {
  const token = env.BOT_TOKEN;
  if (!token) throw new Error('BOT_TOKEN missing');
  const r = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body)
  });
  const data = await r.json();
  if (!data.ok) {
    const e = new Error(data.description || `telegram_${method}_failed`);
    e.telegram = data;
    throw e;
  }
  return data.result;
}

function channelId(env) {
  return env.CHANNEL_ID || '@tori_ya_nova';
}

async function ensureUser(env, user) {
  const now = new Date().toISOString();
  const username = user.username || null;
  const firstName = user.first_name || null;
  const lastName = user.last_name || null;
  const language = user.language_code || null;

  await env.DB.prepare(`
    INSERT INTO users (telegram_user_id, username, first_name, last_seen)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(telegram_user_id) DO UPDATE SET
      username=excluded.username,
      first_name=excluded.first_name,
      last_seen=excluded.last_seen
  `).bind(String(user.id), username, firstName, now).run();
}

async function accessCheck(env, user) {
  if (!env.BOT_TOKEN) return { allowed: false, error: 'bot_token_missing' };
  const chatId = channelId(env);
  if (!chatId) return { allowed: false, error: 'channel_id_missing' };

  try {
    // First make sure Telegram can resolve the configured channel.
    await telegram(env, 'getChat', { chat_id: chatId });
  } catch (e) {
    const desc = e?.telegram?.description || e?.message || '';
    const lower = desc.toLowerCase();
    if (lower.includes('bot token') || lower.includes('unauthorized')) {
      return { allowed: false, error: 'bot_token_invalid', detail: desc };
    }
    if (lower.includes('chat not found') || lower.includes('username is invalid')) {
      return { allowed: false, error: 'channel_not_found', detail: desc };
    }
    return { allowed: false, error: 'telegram_api_error', detail: desc };
  }

  let member;
  try {
    member = await telegram(env, 'getChatMember', {
      chat_id: chatId,
      user_id: user.id
    });
  } catch (e) {
    const desc = e?.telegram?.description || e?.message || '';
    const lower = desc.toLowerCase();
    if (lower.includes('bot token') || lower.includes('unauthorized')) {
      return { allowed: false, error: 'bot_token_invalid', detail: desc };
    }
    if (lower.includes('chat not found') || lower.includes('username is invalid')) {
      return { allowed: false, error: 'channel_not_found', detail: desc };
    }
    if (lower.includes('administrator rights') || lower.includes('not enough rights') || lower.includes('member list')) {
      return { allowed: false, error: 'bot_not_admin', detail: desc };
    }
    if (lower.includes('user not found') || lower.includes('user_id_invalid')) {
      return { allowed: false, error: 'telegram_user_not_found', detail: desc };
    }
    return { allowed: false, error: 'telegram_api_error', detail: desc };
  }

  const allowed = ['member', 'administrator', 'creator'].includes(member.status) ||
    (member.status === 'restricted' && member.is_member === true);
  return {
    allowed,
    error: allowed ? null : 'not_member',
    memberStatus: member.status,
    detail: allowed ? null : `Telegram status: ${member.status}`
  };
}

function userLabel(user) {
  const name = [user.first_name, user.last_name].filter(Boolean).join(' ').trim();
  const handle = user.username ? `@${user.username}` : 'без username';
  return `${name || 'Без имени'} · ${handle} · ID ${user.id}`;
}

function prettyDiagnostic(d) {
  const labels = {
    context: 'Контекст', client: 'Клиент', competition: 'Конкуренты',
    journey: 'Путь', architecture: 'Система / MVP', ai: 'AI-контекст'
  };
  const pct = d?.pct || {};
  return Object.entries(pct).map(([k, v]) => `${labels[k] || k}: ${v}%`).join(' · ');
}

async function sendOwner(env, title, lines) {
  if (!env.OWNER_CHAT_ID || !env.BOT_TOKEN) return;
  const message = [title, ...lines].join('\n');
  try {
    await telegram(env, 'sendMessage', {
      chat_id: env.OWNER_CHAT_ID,
      text: message,
      disable_web_page_preview: true
    });
  } catch (_) {}
}

async function handleAccess(request, env) {
  const body = await request.json().catch(() => ({}));
  const auth = await validateInitData(body.initData, env.BOT_TOKEN, Number(env.INIT_DATA_MAX_AGE_SEC || 86400));
  if (!auth.ok) return json({ allowed: false, error: auth.error }, 401);

  await ensureUser(env, auth.user);
  const access = await accessCheck(env, auth.user);
  if (!access.allowed) return json({ allowed: false, error: access.error, user: { id: String(auth.user.id), first_name: auth.user.first_name || '', username: auth.user.username || '' } });

  await env.DB.prepare(`INSERT INTO events (telegram_user_id, session_id, event, screen, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(String(auth.user.id), null, 'ACCESS_GRANTED', '#access', JSON.stringify({ channel: channelId(env), status: access.memberStatus }), new Date().toISOString()).run()
    .catch(() => {});

  return json({ allowed: true, user: { id: String(auth.user.id), first_name: auth.user.first_name || '', username: auth.user.username || '' } });
}

async function handleEvent(request, env) {
  const body = await request.json().catch(() => ({}));
  const auth = await validateInitData(body.initData, env.BOT_TOKEN, Number(env.INIT_DATA_MAX_AGE_SEC || 86400));
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  await ensureUser(env, auth.user);
  const now = new Date().toISOString();
  await env.DB.prepare(`INSERT INTO events (telegram_user_id, session_id, event, screen, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(String(auth.user.id), body.session_id || null, String(body.event || 'EVENT').slice(0, 80), body.screen || null, JSON.stringify(body.meta || {}), now).run();
  return json({ ok: true });
}

async function handleConsultation(request, env) {
  const body = await request.json().catch(() => ({}));
  const auth = await validateInitData(body.initData, env.BOT_TOKEN, Number(env.INIT_DATA_MAX_AGE_SEC || 86400));
  if (!auth.ok) return json({ ok: false, error: auth.error }, 401);

  await ensureUser(env, auth.user);
  const access = await accessCheck(env, auth.user);
  if (!access.allowed) return json({ ok: false, error: access.error }, 403);

  const product = String(body.product || '').trim().slice(0, 4000);
  const requestText = String(body.request || '').trim().slice(0, 4000);
  const diagnostic = body.diagnostic || {};
  const meta = { product, request: requestText, diagnostic };
  const now = new Date().toISOString();

  await env.DB.prepare(`INSERT INTO events (telegram_user_id, session_id, event, screen, meta, created_at) VALUES (?, ?, ?, ?, ?, ?)`)
    .bind(String(auth.user.id), body.session_id || null, 'CONSULTATION_REQUEST', '#consultation', JSON.stringify(meta), now).run();

  await sendOwner(env, '🎧 НОВАЯ ЗАЯВКА НА МИНИ-КОНСУЛЬТАЦИЮ', [
    `Кто: ${userLabel(auth.user)}`,
    `Продукт / услуга: ${product || 'не указано'}`,
    `Что хочет получить: ${requestText || 'не указано'}`,
    `Результат: ${diagnostic.overall ?? '—'}%` ,
    `Главная точка: ${diagnostic.weak || '—'} · ${diagnostic.weakScore ?? '—'}%`,
    `Метрики: ${prettyDiagnostic(diagnostic)}`,
    `Время: ${now}`
  ]);

  return json({ ok: true, consultationUrl: env.CONSULTATION_URL || 'https://t.me/toriya_nova' });
}

async function handleHealth(env) {
  return json({ ok: true, app: env.MINI_APP_URL || 'toriya-nova-mini-app' });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    try {
      if (url.pathname === '/api/access' && request.method === 'POST') return handleAccess(request, env);
      if (url.pathname === '/api/event' && request.method === 'POST') return handleEvent(request, env);
      if (url.pathname === '/api/consultation' && request.method === 'POST') return handleConsultation(request, env);
      if (url.pathname === '/health') return handleHealth(env);
      return env.ASSETS.fetch(request);
    } catch (e) {
      return json({ ok: false, error: 'server_error', detail: String(e?.message || e || 'unknown_error') }, 500);
    }
  }
};
