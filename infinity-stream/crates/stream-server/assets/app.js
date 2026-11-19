"use strict";
const api = {
  async req(method, path, body) {
    const opts = {
      method,
      headers: { "X-Requested-With": "InfinityStream" },
      credentials: "same-origin",
    };
    if (body !== undefined) {
      opts.headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(body);
    }
    const res = await fetch(path, opts);
    const text = await res.text();
    let data = null;
    try {
      data = text ? JSON.parse(text) : null;
    } catch (_) {
      data = { raw: text };
    }
    if (!res.ok) {
      throw new Error((data && (data.error_description || data.error)) || `HTTP ${res.status}`);
    }
    return data;
  },
  get: (p) => api.req("GET", p),
  post: (p, b) => api.req("POST", p, b),
  del: (p) => api.req("DELETE", p),
};

const $ = (s) => document.querySelector(s);
const esc = (s) =>
  String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function toast(msg, kind = "ok") {
  const t = $("#toast");
  t.textContent = msg;
  t.className = `toast show ${kind}`;
  setTimeout(() => (t.className = "toast"), 3200);
}

let ME = null;
let SOCKET = null;

async function boot() {
  try {
    ME = await api.get("/auth/me");
    showApp();
  } catch (_) {
    showLogin();
  }
}

function showLogin() {
  if (SOCKET) {
    SOCKET.close();
    SOCKET = null;
  }
  $("#app-view").classList.add("hidden");
  $("#login-view").classList.remove("hidden");
}

function showApp() {
  $("#login-view").classList.add("hidden");
  $("#app-view").classList.remove("hidden");
  const who = $("#who");
  who.replaceChildren(
    el("b", "", ME.username || ME.kind || ""),
    document.createElement("br"),
    document.createTextNode(ME.email || ME.id || ""),
    document.createElement("br"),
    el("span", "tag", (ME.roles && ME.roles[0]) || "user")
  );
  navigate("overview");
}

$("#login-form").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("#login-error").textContent = "";
  try {
    const r = await api.post("/auth/login", {
      email: $("#login-email").value.trim(),
      password: $("#login-password").value,
    });
    $("#login-password").value = "";
    ME = r.user;
    showApp();
  } catch (err) {
    $("#login-error").textContent = err.message;
  }
});

$("#logout").addEventListener("click", async () => {
  try {
    await api.post("/auth/logout", {});
  } catch (_) {}
  ME = null;
  showLogin();
});

const TITLES = {
  overview: "Overview",
  topics: "Topics",
  search: "Search",
  consumers: "Consumers",
  keys: "Keys",
  settings: "Settings",
};

document.querySelectorAll(".nav-item").forEach((n) => n.addEventListener("click", () => navigate(n.dataset.view)));

function navigate(view) {
  if (SOCKET) {
    SOCKET.close();
    SOCKET = null;
  }
  document.querySelectorAll(".nav-item").forEach((n) => n.classList.toggle("active", n.dataset.view === view));
  $("#view-title").textContent = TITLES[view] || view;
  const root = $("#view-root");
  root.replaceChildren(el("div", "muted", "Loading…"));
  ({ overview: viewOverview, topics: viewTopics, search: viewSearch, consumers: viewConsumers, keys: viewKeys, settings: viewSettings }[view] ||
    viewOverview)(root).catch((e) => {
    const panel = el("div", "panel");
    panel.append(el("h2", "", "Error"), el("p", "error", e.message));
    root.replaceChildren(panel);
  });
}

async function viewOverview(root) {
  const s = await api.get("/v1/stats");
  root.innerHTML = `<div class="cards"><div class="stat"><div class="num">${esc(s.topicCount)}</div><div class="lbl">Topics</div></div><div class="stat"><div class="num">${esc(s.totalMessages)}</div><div class="lbl">Messages</div></div><div class="stat"><div class="num">${esc(s.indexCount)}</div><div class="lbl">Indexes</div></div><div class="stat"><div class="num">${esc(s.totalDocs)}</div><div class="lbl">Documents</div></div><div class="stat"><div class="num">${esc(s.messagesPerMin)}</div><div class="lbl">Messages/min</div></div></div><div class="panel"><h2>Infinity Stream</h2><p class="muted">Kafka-style append-only topics, Pusher-style websocket fan-out, and Algolia-style BM25 search in a single binary.</p><div class="codebox">POST /v1/topics/:name/produce\nGET  /v1/topics/:name/subscribe\nPOST /v1/indexes/:name/docs\nGET  /v1/indexes/:name/search?q=rust</div></div>`;
}

async function viewTopics(root) {
  const { topics } = await api.get("/v1/topics");
  root.innerHTML = `<div class="panel"><h2>Create topic</h2><div class="form-row"><input id="topic-name" placeholder="orders"/><input id="topic-parts" type="number" value="3" min="1" max="1024"/><button id="topic-create" class="btn primary">Create</button></div></div><div class="panel"><div class="panel-head"><h2>Topics</h2><span class="muted">${topics.length} total</span></div><table><thead><tr><th>Name</th><th>Partitions</th><th>Created</th><th></th></tr></thead><tbody>${topics
    .map(
      (t) =>
        `<tr><td><b>${esc(t.name)}</b></td><td>${esc(t.partitions)}</td><td class="muted mono">${esc(t.created_at)}</td><td><button class="btn sm ghost" data-open="${esc(t.name)}">Open</button> <button class="btn sm danger" data-del="${esc(t.name)}">Delete</button></td></tr>`
    )
    .join("")}</tbody></table></div><div id="topic-detail"></div>`;
  $("#topic-create").onclick = async () => {
    try {
      await api.post("/v1/topics", { name: $("#topic-name").value.trim(), partitions: Number($("#topic-parts").value) });
      toast("Topic created");
      viewTopics(root);
    } catch (e) {
      toast(e.message, "err");
    }
  };
  root.querySelectorAll("[data-del]").forEach(
    (b) =>
      (b.onclick = async () => {
        if (!confirm("Delete topic?")) return;
        try {
          await api.del(`/v1/topics/${encodeURIComponent(b.dataset.del)}`);
          toast("Deleted");
          viewTopics(root);
        } catch (e) {
          toast(e.message, "err");
        }
      })
  );
  root.querySelectorAll("[data-open]").forEach((b) => (b.onclick = () => openTopic(b.dataset.open)));
}

function openTopic(name) {
  if (SOCKET) {
    SOCKET.close();
    SOCKET = null;
  }
  const d = $("#topic-detail");
  d.innerHTML = `<div class="panel"><h2>${esc(name)}</h2><div class="form-row"><input id="prod-key" placeholder="key (optional)"/><input id="prod-part" type="number" min="0" placeholder="partition"/><textarea id="prod-value" placeholder='{"hello":"world"}'></textarea><button id="prod-send" class="btn primary">Produce</button></div><h2>Live tail</h2><div id="tail" class="tail"></div></div>`;
  $("#prod-send").onclick = async () => {
    try {
      let value;
      try {
        value = JSON.parse($("#prod-value").value);
      } catch (_) {
        value = $("#prod-value").value;
      }
      const part = $("#prod-part").value;
      await api.post(`/v1/topics/${encodeURIComponent(name)}/produce`, {
        key: $("#prod-key").value || null,
        partition: part === "" ? null : Number(part),
        value,
      });
      toast("Produced");
    } catch (e) {
      toast(e.message, "err");
    }
  };
  const proto = location.protocol === "https:" ? "wss" : "ws";
  SOCKET = new WebSocket(`${proto}://${location.host}/v1/topics/${encodeURIComponent(name)}/subscribe`);
  SOCKET.onmessage = (ev) => {
    const tail = $("#tail");
    if (!tail) return;
    tail.prepend(el("div", "", ev.data));
    while (tail.childElementCount > 200) {
      tail.lastElementChild.remove();
    }
  };
  SOCKET.onerror = () => toast("WebSocket error", "err");
}

async function viewSearch(root) {
  const { indexes } = await api.get("/v1/indexes");
  root.innerHTML = `<div class="panel"><h2>Create index</h2><div class="form-row"><input id="idx-name" placeholder="products"/><button id="idx-create" class="btn primary">Create</button></div></div><div class="panel"><h2>Indexes</h2><table><thead><tr><th>Name</th><th>Created</th><th></th></tr></thead><tbody>${indexes
    .map(
      (i) =>
        `<tr><td><b>${esc(i.name)}</b></td><td class="mono muted">${esc(i.created_at)}</td><td><button class="btn sm ghost" data-idx="${esc(i.name)}">Open</button> <button class="btn sm danger" data-delidx="${esc(i.name)}">Delete</button></td></tr>`
    )
    .join("")}</tbody></table></div><div id="idx-detail"></div>`;
  $("#idx-create").onclick = async () => {
    try {
      await api.post("/v1/indexes", { name: $("#idx-name").value.trim() });
      toast("Index created");
      viewSearch(root);
    } catch (e) {
      toast(e.message, "err");
    }
  };
  root.querySelectorAll("[data-delidx]").forEach(
    (b) =>
      (b.onclick = async () => {
        try {
          await api.del(`/v1/indexes/${encodeURIComponent(b.dataset.delidx)}`);
          toast("Deleted");
          viewSearch(root);
        } catch (e) {
          toast(e.message, "err");
        }
      })
  );
  root.querySelectorAll("[data-idx]").forEach((b) => (b.onclick = () => openIndex(b.dataset.idx)));
}

function openIndex(name) {
  $("#idx-detail").innerHTML = `<div class="panel"><h2>${esc(name)}</h2><div class="form-row"><textarea id="doc-json" placeholder='[{"id":"1","title":"Rust streams"}]'></textarea><button id="doc-add" class="btn primary">Upsert docs</button></div><div class="form-row"><input id="search-q" placeholder="query"/><input id="search-k" type="number" value="10" min="1" max="100"/><button id="search-run" class="btn primary">Search</button></div><div id="search-results"></div></div>`;
  $("#doc-add").onclick = async () => {
    try {
      await api.post(`/v1/indexes/${encodeURIComponent(name)}/docs`, JSON.parse($("#doc-json").value));
      toast("Indexed");
    } catch (e) {
      toast(e.message, "err");
    }
  };
  $("#search-run").onclick = async () => {
    try {
      const k = Math.max(1, Math.min(100, Number($("#search-k").value) || 10));
      const r = await api.get(`/v1/indexes/${encodeURIComponent(name)}/search?q=${encodeURIComponent($("#search-q").value)}&k=${k}`);
      $("#search-results").replaceChildren(el("div", "codebox", JSON.stringify(r.hits, null, 2)));
    } catch (e) {
      toast(e.message, "err");
    }
  };
}

async function viewConsumers(root) {
  const { offsets } = await api.get("/v1/consumers");
  root.innerHTML = `<div class="panel"><h2>Committed offsets</h2><table><thead><tr><th>Topic</th><th>Group</th><th>Partition</th><th>Offset</th><th>Updated</th></tr></thead><tbody>${offsets
    .map((o) => `<tr><td>${esc(o.topic)}</td><td>${esc(o.consumer_group)}</td><td>${esc(o.partition)}</td><td>${esc(o.offset)}</td><td class="mono muted">${esc(o.updated_at)}</td></tr>`)
    .join("")}</tbody></table></div>`;
}

async function viewKeys(root) {
  const { keys } = await api.get("/v1/keys");
  root.innerHTML = `<div class="panel"><h2>Create API key</h2><div class="form-row"><input id="key-name" placeholder="ci-producer"/><button id="key-create" class="btn primary">Create</button></div><div id="key-new"></div></div><div class="panel"><h2>API keys</h2><table><thead><tr><th>Name</th><th>ID</th><th>Status</th><th></th></tr></thead><tbody>${keys
    .map(
      (k) =>
        `<tr><td>${esc(k.name)}</td><td class="mono">${esc(k.id)}</td><td>${k.revoked_at ? "revoked" : "active"}</td><td><button class="btn sm danger" data-key="${esc(k.id)}">Revoke</button></td></tr>`
    )
    .join("")}</tbody></table></div>`;
  $("#key-create").onclick = async () => {
    try {
      const r = await api.post("/v1/keys", { name: $("#key-name").value.trim() || "dashboard" });
      $("#key-new").replaceChildren(el("div", "codebox", r.key));
      toast("Key created");
    } catch (e) {
      toast(e.message, "err");
    }
  };
  root.querySelectorAll("[data-key]").forEach(
    (b) =>
      (b.onclick = async () => {
        try {
          await api.del(`/v1/keys/${encodeURIComponent(b.dataset.key)}`);
          toast("Revoked");
          viewKeys(root);
        } catch (e) {
          toast(e.message, "err");
        }
      })
  );
}

async function viewSettings(root) {
  root.innerHTML = `<div class="panel"><h2>Settings</h2><p class="muted">Default bind: 0.0.0.0:8092. Config loads from defaults, Config.toml, INFINITY_ env, then STREAM_ env using __ nesting. Set STREAM_ADMIN_PASSWORD before first run or read the generated password once from logs.</p></div>`;
}

boot();
