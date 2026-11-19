const $ = (s) => document.querySelector(s);
const el = (tag, attrs = {}, children = []) => {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'text') node.textContent = String(v ?? '');
    else if (k === 'className') node.className = v;
    else node.setAttribute(k, String(v));
  }
  for (const child of children) {
    if (child !== null && child !== undefined) node.append(child);
  }
  return node;
};
const api = async (path, opts = {}) => {
  const res = await fetch(path, {
    credentials: 'include',
    headers: { 'content-type': 'application/json', ...(opts.headers || {}) },
    ...opts,
  });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error_description: res.statusText }));
    throw new Error(body.error_description || res.statusText);
  }
  return res.json();
};
let current = 'overview';
function notice(msg, ok = false) {
  const box = $('#notice');
  box.replaceChildren();
  if (msg) {
    box.append(el('div', { className: ok ? 'ok' : 'error', text: msg }));
  }
}
function vectorFromText(text, dim) {
  const out = Array(dim).fill(0);
  for (let i = 0; i < text.length; i++) out[i % dim] += ((text.charCodeAt(i) % 31) - 15) / 15;
  return out;
}
function parseFiniteVector(raw) {
  const parsed = JSON.parse(raw);
  if (!Array.isArray(parsed) || parsed.some((v) => typeof v !== 'number' || !Number.isFinite(v))) {
    throw new Error('Vector must be a JSON array of finite numbers');
  }
  return parsed;
}
async function boot() {
  try {
    const me = await api('/auth/me');
    $('#login').classList.add('hidden');
    $('#shell').classList.remove('hidden');
    $('#me').textContent = `${me.email} \u00b7 ${me.roles.join(', ')}`;
    await load(current);
  } catch {
    $('#login').classList.remove('hidden');
    $('#shell').classList.add('hidden');
  }
}
async function load(view) {
  current = view;
  document.querySelectorAll('nav button').forEach((b) => b.classList.toggle('active', b.dataset.view === view));
  document.querySelectorAll('.view').forEach((v) => v.classList.add('hidden'));
  $('#' + view).classList.remove('hidden');
  $('#title').textContent = ({ overview: 'Overview', collections: 'Collections', search: 'Vector Search', users: 'Users / RBAC', audit: 'Audit' })[view];
  notice('');
  try {
    if (view === 'overview') return await overview();
    if (view === 'collections') return await collections();
    if (view === 'search') return await searchView();
    if (view === 'users') return await users();
    if (view === 'audit') return await audit();
  } catch (err) {
    notice(err.message);
  }
}
async function overview() {
  const s = await api('/api/stats');
  const cards = Object.entries(s).map(([k, v]) =>
    el('div', { className: 'stat' }, [el('span', { text: k }), el('b', { text: v })])
  );
  $('#overview').replaceChildren(...cards);
}
async function collections() {
  const data = await api('/api/collections');
  const form = el('form', { id: 'createCol', className: 'toolbar', method: 'post' }, [
    el('input', { name: 'name', placeholder: 'name' }),
    el('input', { name: 'dim', type: 'number', placeholder: 'dimension' }),
    el('select', { name: 'metric' }, [
      el('option', { value: 'cosine', text: 'cosine' }),
      el('option', { value: 'l2', text: 'l2' }),
      el('option', { value: 'dot', text: 'dot' }),
    ]),
    el('button', { text: 'Create' }),
  ]);
  const table = el('table', {}, [
    el('tr', {}, ['Name', 'Dim', 'Metric', 'Vectors', 'Created'].map((h) => el('th', { text: h }))),
    ...data.collections.map((c) =>
      el('tr', {}, [
        el('td', {}, [el('span', { className: 'pill', text: c.name })]),
        el('td', { text: c.dim }),
        el('td', { text: c.metric }),
        el('td', { text: c.count }),
        el('td', { text: c.created_at }),
      ])
    ),
  ]);
  const card = el('div', { className: 'card' }, [
    el('h2', { text: 'Create collection' }),
    form,
    el('h2', { text: 'Collections' }),
    table,
  ]);
  $('#collections').replaceChildren(card);
  form.onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api('/api/collections', {
        method: 'POST',
        body: JSON.stringify({ name: f.get('name'), dim: Number(f.get('dim')), metric: f.get('metric') }),
      });
      notice('Collection created', true);
      await collections();
    } catch (err) {
      notice(err.message);
    }
  };
}
async function searchView() {
  const cols = (await api('/api/collections')).collections;
  const select = el(
    'select',
    { id: 'scol' },
    cols.map((c) => el('option', { value: c.name, 'data-dim': c.dim, text: `${c.name} (${c.dim})` }))
  );
  const leftCard = el('div', { className: 'card' }, [
    el('h2', { text: 'Search' }),
    el('label', { text: 'Collection' }, [select]),
    el('label', { text: 'Query vector JSON' }, [el('textarea', { id: 'qvec', placeholder: '[0.1,0.2,0.3]' })]),
    el('label', { text: 'or text (hashed client-side)' }, [el('input', { id: 'qtext', placeholder: 'semantic query text' })]),
    el('label', { text: 'k' }, [el('input', { id: 'k', type: 'number', value: '5' })]),
    el('button', { id: 'runSearch', type: 'button', text: 'Run search' }),
    el('h3', { text: 'Insert vector' }),
    el('input', { id: 'pid', placeholder: 'id' }),
    el('textarea', { id: 'pvec', placeholder: '[0.1,0.2]' }),
    el('textarea', { id: 'pmeta', placeholder: '{"label":"demo"}' }),
    el('button', { id: 'insertPoint', type: 'button', text: 'Insert / upsert' }),
  ]);
  const resultsPre = el('pre', { id: 'results', text: '[]' });
  const rightCard = el('div', { className: 'card' }, [el('h2', { text: 'Results' }), resultsPre]);
  $('#search').replaceChildren(el('div', { className: 'split' }, [leftCard, rightCard]));
  $('#runSearch').onclick = async () => {
    try {
      const opt = $('#scol').selectedOptions[0];
      if (!opt) throw new Error('Create a collection first');
      const vector = $('#qvec').value.trim()
        ? parseFiniteVector($('#qvec').value)
        : vectorFromText($('#qtext').value, Number(opt.dataset.dim));
      const out = await api(`/api/collections/${encodeURIComponent(opt.value)}/search`, {
        method: 'POST',
        body: JSON.stringify({ vector, k: Number($('#k').value) || 5 }),
      });
      resultsPre.textContent = JSON.stringify(out, null, 2);
    } catch (e) {
      notice(e.message);
    }
  };
  $('#insertPoint').onclick = async () => {
    try {
      const col = $('#scol').value;
      if (!col) throw new Error('Create a collection first');
      const meta = $('#pmeta').value.trim() ? JSON.parse($('#pmeta').value) : null;
      await api(`/api/collections/${encodeURIComponent(col)}/vectors`, {
        method: 'POST',
        body: JSON.stringify({ points: [{ id: $('#pid').value, vector: parseFiniteVector($('#pvec').value), metadata: meta }] }),
      });
      notice('Vector inserted', true);
    } catch (e) {
      notice(e.message);
    }
  };
}
async function users() {
  const [u, r] = await Promise.all([api('/admin/users'), api('/admin/roles')]);
  const form = el('form', { id: 'createUser', method: 'post' }, [
    el('label', { text: 'Email' }, [el('input', { name: 'email' })]),
    el('label', { text: 'Username' }, [el('input', { name: 'username' })]),
    el('label', { text: 'Password' }, [el('input', { type: 'password', name: 'password' })]),
    el('label', { text: 'Roles' }, [el('input', { name: 'roles', placeholder: 'user,admin' })]),
    el('button', { text: 'Create' }),
  ]);
  const leftCard = el('div', { className: 'card' }, [
    el('h2', { text: 'Create user' }),
    form,
    el('h2', { text: 'Roles' }),
    el('pre', { text: JSON.stringify(r.roles, null, 2) }),
  ]);
  const table = el('table', {}, [
    el('tr', {}, ['Email', 'Roles', 'Status'].map((h) => el('th', { text: h }))),
    ...u.users.map((x) =>
      el('tr', {}, [
        el('td', { text: x.email }),
        el('td', { text: x.roles.join(', ') }),
        el('td', { text: x.disabled ? 'disabled' : 'active' }),
      ])
    ),
  ]);
  const rightCard = el('div', { className: 'card' }, [el('h2', { text: 'Users' }), table]);
  $('#users').replaceChildren(el('div', { className: 'split' }, [leftCard, rightCard]));
  form.onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api('/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          email: f.get('email'),
          username: f.get('username'),
          password: f.get('password'),
          roles: String(f.get('roles') || 'user').split(',').map((x) => x.trim()).filter(Boolean),
        }),
      });
      notice('User created', true);
      await users();
    } catch (err) {
      notice(err.message);
    }
  };
}
async function audit() {
  const a = await api('/admin/audit?limit=100');
  const table = el('table', {}, [
    el('tr', {}, ['Time', 'Actor', 'Event', 'Target'].map((h) => el('th', { text: h }))),
    ...a.events.map((e) =>
      el('tr', {}, [
        el('td', { text: e.created_at }),
        el('td', { text: e.actor_user_id || '' }),
        el('td', { text: e.event }),
        el('td', { text: e.target || '' }),
      ])
    ),
  ]);
  $('#audit').replaceChildren(el('div', { className: 'card' }, [el('h2', { text: 'Audit log' }), table]));
}
document.querySelectorAll('nav button').forEach((b) => (b.onclick = () => load(b.dataset.view)));
$('#logout').onclick = async () => {
  try {
    await api('/auth/logout', { method: 'POST', body: '{}' });
  } catch {}
  location.reload();
};
$('#loginForm').onsubmit = async (e) => {
  e.preventDefault();
  const f = new FormData(e.target);
  try {
    await api('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email: f.get('email'), password: f.get('password') }),
    });
    await boot();
  } catch (err) {
    notice(err.message);
  }
};
boot();
