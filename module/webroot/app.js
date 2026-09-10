'use strict';

// Ningshi WebUI.
//
// Loaded as an external script so the page can run under a strict CSP
// (`script-src 'self'`): there is no inline script and no inline event handler
// anywhere. Every interactive element carries a `data-act` attribute and one of
// the four delegated listeners below dispatches on it, so no user-controlled
// value is ever interpolated into a JavaScript string - which matters here
// because `ksu.exec` runs as root.

// ---------- i18n ----------
const I18N = {
  zh: {
    apps: '应用', groups: '组', module: '模块',
    search: '搜索应用名或包名',
    refresh: '刷新', show_system: '显示系统应用', hide_system: '隐藏系统应用',
    no_apps: '无匹配应用',
    blocked: '已封禁',
    new_group: '新建组', no_groups: '暂无组',
    members: '{n} 个成员', on: '启用中', off: '已停用',
    settings: '设置',
    always_on: '总是开启',
    lock_block: '锁屏后封禁', lock_hint: '屏幕关闭时立即停止',
    add_window: '添加时间段', window_mode: '时间段策略',
    mode_block: '窗内禁止', mode_allow: '仅窗内可用',
    every_day: '每天',
    day_short: ['一', '二', '三', '四', '五', '六', '日'],
    duration: '时长时期（分钟）', duration_hint: '0 = 不使用时长功能',
    cooldown: '冷却期（分钟）', cooldown_hint: '0 = 每日凌晨重置',
    ext_remaining: '延时时长', ext_hint: '每日上限 2 小时', min_unit: '分钟',
    scope: '计时口径', scope_fg: '前台', scope_any: '运行（含后台）',
    group_name: '组名', delete_group: '删除组', shared_pool: '共用计时池（时长）', shared_pool_hint: '切换后已计时长保留，冷却期重置',
    select_members: '选择应用', member_hint: '其他组中的应用不可选',
    language: '模块语言',
    timezone: '时区',
    status: 'daemon 状态', log: 'daemon 日志',
    refresh_log: '刷新日志', clear_log: '清空日志', log_cleared: '日志已清空',
    to: '至', remove: '删除', deleted: '已删除',
    unmanaged: '未管控', protected: '受保护',
    stats_used: '已用 {min} 分钟 · 拦截 {n} 次',
    stats_kills: '拦截 {n} 次',
    clear_on_boot: '重启模块自动清空日志',
    save_failed: '保存失败',
    health_daemon_down: '凝时未在运行，规则当前不生效',
    health_gate_down: '内核钩子未挂载，拦截可能不生效',
    health_rules_fallback: '正在使用备用规则（配置文件解析失败）',
    health_version_mismatch: '模块与 daemon 版本不一致，请重新刷入模块',
    health_hint: '打开模块页可查看状态与日志',
    not_ksu: '不在 KernelSU WebUI 中运行'
  },
  en: {
    apps: 'Apps', groups: 'Groups', module: 'Module',
    search: 'Search name or package',
    refresh: 'Refresh', show_system: 'Show system apps', hide_system: 'Hide system apps',
    no_apps: 'No matching apps',
    blocked: 'Blocked',
    new_group: 'New group', no_groups: 'No groups',
    members: '{n} members', on: 'Enabled', off: 'Disabled',
    settings: 'Settings',
    always_on: 'Always on',
    lock_block: 'Block on screen lock', lock_hint: 'Block immediately when the screen turns off',
    add_window: 'Add time window', window_mode: 'Window policy',
    mode_block: 'Block in windows', mode_allow: 'Allow only in windows',
    every_day: 'Every day',
    day_short: ['M', 'T', 'W', 'T', 'F', 'S', 'S'],
    duration: 'Usage period (min)', duration_hint: '0 = duration disabled',
    cooldown: 'Cooldown (min)', cooldown_hint: '0 = reset at midnight',
    ext_remaining: 'Extension', ext_hint: 'Max 2h per day', min_unit: 'min',
    scope: 'Counting scope', scope_fg: 'Foreground', scope_any: 'Running (incl. background)',
    group_name: 'Group name', delete_group: 'Delete group', shared_pool: 'Shared pool (usage)', shared_pool_hint: 'Usage is kept; cooldown resets on toggle',
    select_members: 'Select apps', member_hint: 'Apps in other groups cannot be selected',
    language: 'Language',
    timezone: 'Timezone',
    status: 'Daemon status', log: 'Daemon log',
    refresh_log: 'Refresh log', clear_log: 'Clear log', log_cleared: 'Log cleared',
    to: 'to', remove: 'Remove', deleted: 'Deleted',
    unmanaged: 'Not managed', protected: 'Protected',
    stats_used: 'Used {min} min, blocked {n} times',
    stats_kills: 'Blocked {n} times',
    clear_on_boot: 'Clear log on module restart',
    save_failed: 'Save failed',
    health_daemon_down: 'Ningshi is not running — rules are inactive',
    health_gate_down: 'Kernel hooks are not attached — blocking may be inactive',
    health_rules_fallback: 'Running on fallback rules (rules.json could not be parsed)',
    health_version_mismatch: 'Module and daemon versions differ — reinstall the module',
    health_hint: 'Open the Module tab for status and logs',
    not_ksu: 'Not running inside the KernelSU WebUI'
  }
};

// ---------- helpers ----------
function esc(s) {
  return String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}
function isKSUWebUI() { return typeof ksu !== 'undefined'; }
function toast(msg) { try { ksu.toast(msg); } catch (e) {} }
function exec(cmd, opts) {
  opts = opts || {};
  return new Promise((resolve, reject) => {
    const cb = 'cb_' + Date.now() + '_' + Math.floor(Math.random() * 1e6);
    window[cb] = (errno, stdout, stderr) => {
      resolve({ errno, stdout: stdout || '', stderr: stderr || '' });
      try { delete window[cb]; } catch (e) {}
    };
    try { ksu.exec(cmd, JSON.stringify(opts), cb); }
    catch (e) { reject(e); try { delete window[cb]; } catch (e2) {} }
  });
}
async function readFile(path) {
  const { errno, stdout, stderr } = await exec(`[ -f "${path}" ] && cat "${path}"`);
  if (errno !== 0) throw new Error(stderr || 'cannot read ' + path);
  return stdout.trim();
}
// base64 through the shell: the device shell interprets backslash escapes in
// `echo`, which would corrupt any JSON containing a "\".
async function writeFile(path, content) {
  const bytes = new TextEncoder().encode(content);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  const { errno, stderr } = await exec(`echo "${btoa(bin)}" | base64 -d > "${path}"`);
  if (errno !== 0) throw new Error(stderr || ('cannot write ' + path));
}
function listPackages(type) {
  try { return JSON.parse(ksu.listPackages(type)); } catch (e) { return null; }
}
function getPackagesInfo(pkgs) {
  try { return JSON.parse(ksu.getPackagesInfo(JSON.stringify(pkgs))); } catch (e) { return null; }
}

// ---------- state ----------
let MODDIR = '/data/adb/modules/ningshi';
const DATADIR = '/data/adb/ningshi';
let rules = { version: 1, settings: {}, apps: {}, groups: {} };
let status = {};
let statusErr = '';
let moduleVersion = '';
let lang = 'zh';
let showSystem = false;
let searchQuery = '';
let lastBlockedKey = '';
let currentView = 'apps';
let appInfoCache = {};
let currentAppKey = '';
let currentGroupGid = '';

// Fallback for the never-manageable list; the daemon is the source of truth
// (status.protected) because it also resolves the device's own IME and launcher.
const PROTECTED_FALLBACK = ['me.weishu.kernelsu', 'com.android.systemui', 'com.android.settings'];
function protectedSet() {
  const list = (status && Array.isArray(status.protected) && status.protected.length)
    ? status.protected : PROTECTED_FALLBACK;
  return new Set(list);
}

function detectModuleDir() {
  try {
    const mi = JSON.parse(ksu.moduleInfo());
    if (mi.dir) MODDIR = mi.dir;
    else if (mi.moduleDir) MODDIR = mi.moduleDir;
    else if (mi.id) MODDIR = '/data/adb/modules/' + mi.id;
  } catch (e) {}
}

function resolveLang() {
  const s = (rules.settings && rules.settings.language) || 'en';
  lang = (s === 'zh') ? 'zh' : 'en';
}
function t(key) { return (I18N[lang] && I18N[lang][key]) || key; }
function tf(key, obj) { let s = t(key); for (const k in obj) s = s.replace('{' + k + '}', obj[k]); return s; }

function applyLanguage() {
  const title = lang === 'zh' ? '凝时' : 'Ningshi';
  document.getElementById('page-title').textContent = title;
  document.title = title;
  document.getElementById('btn-refresh').textContent = t('refresh');
  document.getElementById('btn-system').textContent = t(showSystem ? 'hide_system' : 'show_system');
  document.getElementById('btn-new-group').textContent = t('new_group');
  document.querySelector('input[type="search"]').placeholder = t('search');
  document.getElementById('bottom-nav').querySelectorAll('button').forEach(b => {
    b.querySelector('span').textContent = t(b.dataset.view);
  });
}

async function loadRules() {
  try { rules = JSON.parse(await readFile(DATADIR + '/rules.json')); }
  catch (e) { rules = { version: 1, settings: {}, apps: {}, groups: {} }; }
}

// The daemon validates the candidate file and only then replaces the live one,
// so a bad payload can never disarm the module. On failure the in-memory model is
// re-read from disk and the view re-rendered, so the UI never diverges.
async function saveRules() {
  try {
    const text = JSON.stringify(rules, null, 2);
    const tmp = DATADIR + '/rules.json.tmp';
    await writeFile(tmp, text);
    await exec(`chmod 600 "${tmp}"`);
    const r = await exec(MODDIR + '/bin/ningshi apply ' + tmp);
    if (r.errno !== 0) throw new Error((r.stderr || r.stdout || 'apply failed').trim());
    return true;
  } catch (e) {
    toast(t('save_failed') + ': ' + (e && e.message ? e.message : e));
    await loadRules();
    refreshCurrentView();
    return false;
  }
}

function refreshCurrentView() {
  if (currentView === 'apps') loadApps();
  else if (currentView === 'groups') loadGroups();
  else if (currentView === 'app-set') renderAppSettings(currentAppKey);
  else if (currentView === 'group-set') renderGroupSettings(currentGroupGid);
  else if (currentView === 'module') renderModuleSettings();
}

async function readModuleVersion() {
  try {
    const text = await readFile(MODDIR + '/module.prop');
    const m = text.match(/^version=(.+)$/m);
    if (m) return 'v' + m[1].trim();
  } catch (e) {}
  return '';
}

// ---------- views ----------
function showView(name) {
  currentView = name;
  document.querySelectorAll('.view').forEach(v => v.classList.add('hidden'));
  document.getElementById('view-' + name).classList.remove('hidden');
  const navTab = name === 'app-set' ? 'apps' : (name === 'group-set' ? 'groups' : name);
  document.querySelectorAll('#bottom-nav button').forEach(b => {
    b.classList.toggle('active', b.dataset.view === navTab);
  });
  if (name === 'apps') loadApps();
  if (name === 'groups') loadGroups();
  if (name === 'module') renderModuleSettings();
}

function ripple(event, el) {
  const rect = el.getBoundingClientRect();
  const size = Math.max(rect.width, rect.height) * 1.5;
  const span = document.createElement('span');
  span.className = 'ripple';
  span.style.width = span.style.height = size + 'px';
  span.style.left = (event.clientX - rect.left - size / 2) + 'px';
  span.style.top = (event.clientY - rect.top - size / 2) + 'px';
  el.appendChild(span);
  setTimeout(() => span.remove(), 500);
}

// ---------- health banner ----------
function renderHealth() {
  const el = document.getElementById('health');
  if (!el) return;
  let msg = '';
  let detail = '';
  const gate = status && status.gate;
  if (statusErr) {
    msg = t('health_daemon_down');
    detail = statusErr;
  } else if (gate && !gate.binder_entry && !gate.uid_switch) {
    msg = t('health_gate_down');
  } else if (status && status.rules_source && status.rules_source !== 'file') {
    msg = t('health_rules_fallback');
    detail = String(status.rules_source);
  } else if (status && status.version && moduleVersion && ('v' + status.version) !== moduleVersion) {
    msg = t('health_version_mismatch');
    detail = 'module ' + moduleVersion + ' / daemon v' + status.version;
  }
  if (!msg) {
    el.classList.add('hidden');
    el.textContent = '';
    return;
  }
  el.textContent = '';
  const head = document.createElement('div');
  head.textContent = msg;
  const det = document.createElement('div');
  det.className = 'detail';
  det.textContent = detail || t('health_hint');
  el.appendChild(head);
  el.appendChild(det);
  el.classList.remove('hidden');
}

// ---------- status / log ----------
async function fetchStatus() {
  try {
    const r = await exec(MODDIR + '/bin/ningshi status');
    if (r.errno !== 0 || !r.stdout.trim()) {
      statusErr = (r.stderr || ('exit ' + r.errno)).trim();
      status = {};
      return;
    }
    status = JSON.parse(r.stdout);
    statusErr = '';
  } catch (e) {
    statusErr = String(e && e.message ? e.message : e);
    status = {};
  }
}

async function loadStatus() {
  await fetchStatus();
  renderHealth();
  const key = JSON.stringify(status.blocked_uids || []);
  if (key !== lastBlockedKey) {
    lastBlockedKey = key;
    if (currentView === 'apps') loadApps();
  } else if (currentView === 'apps') {
    updateStats();
  }
  const el = document.getElementById('status-pre');
  if (el) el.textContent = JSON.stringify(status, null, 2);
}

function effectiveDuration(key) {
  const ar = rules.apps[key];
  if (ar && ar.enabled && ar.duration && ar.duration.limit_minutes > 0) {
    return ar.duration;
  }
  const gid = findGroupOf(key);
  if (gid) {
    const g = rules.groups[gid];
    if (g && g.enabled && g.duration && g.duration.limit_minutes > 0) {
      return g.duration;
    }
  }
  return null;
}

function scopedUsage(uid, scope) {
  const any = (status.usage_seconds && status.usage_seconds[uid]) || 0;
  const fg = (status.usage_fg_seconds && status.usage_fg_seconds[uid]) || 0;
  if (scope === 'any') return any;
  if (scope === 'background') return Math.max(0, any - fg);
  return fg;
}

function updateStats() {
  document.querySelectorAll('[data-stat-uid]').forEach(el => {
    const uid = parseInt(el.dataset.statUid, 10);
    const key = el.dataset.statKey || '';
    const kills = (status.kill_counts && status.kill_counts[uid]) || 0;
    const d = effectiveDuration(key);
    if (d) {
      const min = Math.round(scopedUsage(uid, d.scope || 'foreground') / 60);
      el.textContent = tf('stats_used', { min, n: kills });
    } else {
      el.textContent = tf('stats_kills', { n: kills });
    }
  });
}

async function loadLog() {
  const el = document.getElementById('log-pre');
  if (!el) return;
  try { el.textContent = await readFile(MODDIR + '/ningshi.log'); }
  catch (e) { el.textContent = ''; }
}
async function clearLog() {
  await exec(MODDIR + '/bin/ningshi clear_log');
  toast(t('log_cleared'));
  await loadLog();
}

// ---------- groups lookup ----------
function findGroupOf(key) {
  for (const gid in (rules.groups || {})) {
    if ((rules.groups[gid].members || []).includes(key)) return gid;
  }
  return null;
}
function groupName(gid) {
  const g = (rules.groups || {})[gid];
  return (g && g.name) || 'Group';
}

// ---------- apps view ----------
async function loadApps(animate) {
  await loadRules();
  await fetchStatus();
  renderHealth();
  lastBlockedKey = JSON.stringify(status.blocked_uids || []);
  const prot = protectedSet();
  const pkgs = listPackages(showSystem ? 'all' : 'user') || [];
  const infos = pkgs.length ? (getPackagesInfo(pkgs) || []) : [];
  const list = document.getElementById('app-list');
  list.innerHTML = '';
  appInfoCache = {};
  const items = [];
  for (const info of infos) {
    const uid = info.uid || 0;
    if (!showSystem && uid < 10000) continue;
    const pkg = info.packageName;
    const user = Math.floor(uid / 100000);
    const key = user + ':' + pkg;
    const label = info.appLabel || pkg;
    const isSystem = uid < 10000 || prot.has(pkg);
    const rule = rules.apps[key];
    const enabled = !!(rule && rule.enabled);
    const gid = findGroupOf(key);
    appInfoCache[key] = { label, pkg, uid };
    if (searchQuery) {
      const q = searchQuery.toLowerCase();
      if (!label.toLowerCase().includes(q) && !pkg.toLowerCase().includes(q)) continue;
    }
    items.push({ key, pkg, label, uid, isSystem, enabled, gid });
  }
  items.sort((a, b) => {
    const ma = (a.enabled || a.gid) ? 1 : 0;
    const mb = (b.enabled || b.gid) ? 1 : 0;
    if (ma !== mb) return mb - ma;
    return a.label.localeCompare(b.label);
  });
  if (!items.length) {
    list.innerHTML = '<div class="card muted-text">' + esc(t('no_apps')) + '</div>';
    return;
  }
  let idx = 0;
  for (const it of items) {
    const blocked = (status.blocked_uids || []).includes(it.uid);
    const managed = it.enabled || it.gid;
    const row = document.createElement('div');
    row.className = 'card' + (animate ? ' anim' : '') + (managed ? ' managed' : (it.isSystem ? '' : ' unmanaged'));
    if (animate) row.style.animationDelay = (idx++ * 20) + 'ms';
    row.innerHTML = `
      <div class="app" data-act="app-card" data-key="${esc(it.key)}" data-sys="${it.isSystem ? '1' : '0'}">
        <img class="icon" src="ksu://icon/${esc(it.pkg)}">
        <div class="info">
          <div class="name">${esc(it.label)}</div>
          <div class="pkg2">${esc(it.pkg)}</div>
          <div class="sub">
            ${it.isSystem ? `<span class="tag">${esc(t('protected'))}</span>` : ''}
            ${(!it.isSystem && !managed) ? `<span class="stat">${esc(t('unmanaged'))}</span>` : ''}
            ${(!it.isSystem && managed) ? `<span class="stat" data-stat-uid="${it.uid}" data-stat-key="${esc(it.key)}"></span>` : ''}
            ${it.gid ? `<span class="tag group">${esc(groupName(it.gid))}</span>` : ''}
            ${blocked ? `<span class="tag blocked">${esc(t('blocked'))}</span>` : ''}
          </div>
        </div>
        ${it.isSystem ? '' : (it.gid ? `
        <label class="switch grouped">
          <input type="checkbox" checked disabled>
          <span class="slider"></span>
        </label>` : `
        <label class="switch">
          <input type="checkbox" data-act="toggle-app" data-key="${esc(it.key)}" ${it.enabled ? 'checked' : ''}>
          <span class="slider"></span>
        </label>`)}
      </div>`;
    list.appendChild(row);
  }
  updateStats();
}

function onSearch(v) { searchQuery = v.trim(); loadApps(); }

async function toggleSystem() {
  showSystem = !showSystem;
  document.getElementById('btn-system').textContent = t(showSystem ? 'hide_system' : 'show_system');
  await loadApps();
}

function onAppCard(el, event) {
  const key = el.dataset.key || '';
  if (event) ripple(event, el.parentElement || el);
  if (el.dataset.sys === '1') return;
  const gid = findGroupOf(key);
  if (gid) { openGroupSettings(gid); return; }
  // A disabled rule still holds settings worth reaching from the card.
  if (rules.apps[key]) { openAppSettings(key); return; }
}

async function toggleApp(key, on) {
  if (on) {
    // An app is either managed alone or by a group, never both.
    for (const gid in (rules.groups || {})) {
      const m = rules.groups[gid].members || [];
      const i = m.indexOf(key);
      if (i >= 0) m.splice(i, 1);
    }
    const existing = rules.apps[key];
    if (existing) {
      // Turning the switch back on must not throw the old policy away.
      existing.enabled = true;
    } else {
      // New rules start on the default policy: windows mean "only usable in
      // them", so an app with no window yet is simply allowed.
      rules.apps[key] = {
        enabled: true, always_on: false,
        time_windows: { mode: 'allow', windows: [] },
        duration: { limit_minutes: 0, scope: 'foreground' }
      };
    }
  } else if (rules.apps[key]) {
    // Keep the rule (disabled) so the settings survive an accidental toggle.
    rules.apps[key].enabled = false;
  }
  await saveRules();
  await loadStatus();
}

function getAppRule(key) {
  if (!rules.apps[key]) rules.apps[key] = {};
  return rules.apps[key];
}

// ---------- app settings ----------
function openAppSettings(key) {
  currentAppKey = key;
  renderAppSettings(key);
  showView('app-set');
}

// ---------- weekday chips ----------
// A window with no days means "every day"; picking all seven collapses back to
// that default so the stored JSON stays small.
const ALL_DAYS = [1, 2, 3, 4, 5, 6, 7];

function dayRowHTML(scope, key, idx, days) {
  const names = t('day_short');
  const every = !days || days.length === 0;
  let html = '<div class="day-row">';
  for (let d = 1; d <= 7; d++) {
    const on = every || days.indexOf(d) >= 0;
    const attr = scope === 'group' ? `data-gid="${esc(key)}"` : `data-key="${esc(key)}"`;
    html += `<button class="day-chip${on ? ' on' : ''}" data-act="day" data-scope="${scope}" ${attr} data-idx="${idx}" data-day="${d}">${esc(names[d - 1])}</button>`;
  }
  html += `<span class="day-hint">${every ? esc(t('every_day')) : ''}</span></div>`;
  return html;
}

function ruleOwner(scope, key) {
  return scope === 'group' ? (rules.groups || {})[key] : getAppRule(key);
}

function toggleDay(scope, key, idx, day, el) {
  const owner = ruleOwner(scope, key);
  if (!owner) return;
  const tw = owner.time_windows || (owner.time_windows = { mode: 'allow', windows: [] });
  const w = tw.windows[idx];
  if (!w) return;
  let days = (w.days && w.days.length) ? w.days.slice() : ALL_DAYS.slice();
  const i = days.indexOf(day);
  if (i >= 0) {
    if (days.length === 1) return; // at least one day stays selected
    days.splice(i, 1);
  } else {
    days.push(day);
  }
  days.sort((a, b) => a - b);
  w.days = (days.length === 7) ? [] : days;
  saveRules();
  if (el && el.parentElement) {
    el.parentElement.outerHTML = dayRowHTML(scope, key, idx, w.days);
  }
}

function windowRows(scope, key, tw) {
  const attr = scope === 'group' ? `data-gid="${esc(key)}"` : `data-key="${esc(key)}"`;
  let html = '';
  (tw.windows || []).forEach((w, i) => {
    html += `
      <div class="win-row">
        <input type="text" maxlength="5" placeholder="HH:MM" value="${esc(w.start)}" data-act="win-time" data-scope="${scope}" ${attr} data-idx="${i}" data-field="start">
        <span>${esc(t('to'))}</span>
        <input type="text" maxlength="5" placeholder="HH:MM" value="${esc(w.end)}" data-act="win-time" data-scope="${scope}" ${attr} data-idx="${i}" data-field="end">
        <button class="btn small" data-act="win-del" data-scope="${scope}" ${attr} data-idx="${i}">${esc(t('remove'))}</button>
      </div>` + dayRowHTML(scope, key, i, w.days);
  });
  return html;
}

function renderAppSettings(key) {
  const r = rules.apps[key] || {};
  const info = appInfoCache[key] || {};
  const pkg = info.pkg || key.split(':')[1] || key;
  const label = info.label || pkg;
  const alwaysOn = !!(r.enabled && r.always_on);
  const tw = r.time_windows || { mode: 'allow', windows: [] };
  const dur = r.duration || { limit_minutes: 0, scope: 'foreground' };
  document.getElementById('app-set-content').innerHTML = `
    <div class="subhead"><button class="back" data-act="back" data-view="apps">←</button><h2>${esc(t('settings'))}</h2></div>
    <div class="card">
      <div class="set-head">
        <img class="icon" src="ksu://icon/${esc(pkg)}">
        <div class="info">
          <div class="name">${esc(label)}</div>
          <div class="pkg">${esc(pkg)}</div>
        </div>
        <span style="display:flex;gap:6px;flex-shrink:0">
          <button class="btn small" data-act="extend" data-key="${esc(key)}" data-min="5">+5</button>
          <button class="btn small" data-act="extend" data-key="${esc(key)}" data-min="20">+20</button>
        </span>
      </div>
      <div class="set-row" style="border-bottom:none;padding-bottom:0">
        <div class="label">${esc(t('ext_remaining'))}<div class="hint">${esc(t('ext_hint'))}</div></div>
        <span id="ext-remaining-app" style="font-size:13px">0</span>
      </div>
    </div>
    <div class="card">
      <div class="set-row"><div class="label">${esc(t('always_on'))}</div>
        <label class="switch"><input type="checkbox" data-act="set" data-scope="app" data-key="${esc(key)}" data-field="always_on" ${alwaysOn ? 'checked' : ''}><span class="slider"></span></label></div>
      <div class="set-row"><div class="label">${esc(t('lock_block'))}<div class="hint">${esc(t('lock_hint'))}</div></div>
        <label class="switch"><input type="checkbox" data-act="set" data-scope="app" data-key="${esc(key)}" data-field="lock_block" ${r.lock_block ? 'checked' : ''}><span class="slider"></span></label></div>
      <div class="set-row"><div class="label">${esc(t('add_window'))}</div>
        <button class="btn small" data-act="win-add" data-scope="app" data-key="${esc(key)}">+</button></div>
      ${windowRows('app', key, tw)}
      <div class="set-row"><div class="label">${esc(t('window_mode'))}</div>
        <select data-act="set" data-scope="app" data-key="${esc(key)}" data-field="window_mode">
          <option value="allow"${tw.mode === 'block' ? '' : ' selected'}>${esc(t('mode_allow'))}</option>
          <option value="block"${tw.mode === 'block' ? ' selected' : ''}>${esc(t('mode_block'))}</option>
        </select></div>
      <div class="set-row"><div class="label">${esc(t('duration'))}<div class="hint">${esc(t('duration_hint'))}</div></div>
        <input type="number" min="0" style="width:80px" value="${dur.limit_minutes || 0}" data-act="set" data-scope="app" data-key="${esc(key)}" data-field="duration"></div>
      <div class="set-row"><div class="label">${esc(t('cooldown'))}<div class="hint">${esc(t('cooldown_hint'))}</div></div>
        <input type="number" min="0" style="width:80px" value="${dur.freeze_minutes || 0}" data-act="set" data-scope="app" data-key="${esc(key)}" data-field="cooldown"></div>
      <div class="set-row"><div class="label">${esc(t('scope'))}</div>
        <select data-act="set" data-scope="app" data-key="${esc(key)}" data-field="scope">
          <option value="foreground"${dur.scope !== 'any' ? ' selected' : ''}>${esc(t('scope_fg'))}</option>
          <option value="any"${dur.scope === 'any' ? ' selected' : ''}>${esc(t('scope_any'))}</option>
        </select></div>
    </div>`;
  updateExtDisplay();
}

function hhmm(v) { return /^([01]?[0-9]|2[0-3]):[0-5][0-9]$/.test(v); }

async function addWindow(scope, key) {
  const owner = ruleOwner(scope, key);
  if (!owner) return;
  if (scope !== 'group') owner.enabled = true;
  const tw = owner.time_windows || (owner.time_windows = { mode: 'allow', windows: [] });
  tw.windows.push({ start: '00:00', end: '01:00', days: [] });
  await saveRules();
  if (scope === 'group') renderGroupSettings(key); else renderAppSettings(key);
}

async function removeWindow(scope, key, idx) {
  const owner = ruleOwner(scope, key);
  if (!owner || !owner.time_windows) return;
  owner.time_windows.windows.splice(idx, 1);
  await saveRules();
  if (scope === 'group') renderGroupSettings(key); else renderAppSettings(key);
}

async function setWindowTime(scope, key, idx, field, val) {
  const owner = ruleOwner(scope, key);
  const w = owner && owner.time_windows && owner.time_windows.windows[idx];
  if (!hhmm(val)) {
    if (scope === 'group') renderGroupSettings(key); else renderAppSettings(key);
    return;
  }
  if (w) {
    w[field] = val;
    await saveRules();
  }
}

async function doExtend(key, mins) {
  const r = await exec(MODDIR + '/bin/ningshi extension ' + key + ' ' + mins);
  if (r.errno !== 0) {
    toast((r.stderr || 'error').trim());
    return;
  }
  let added = mins;
  try { added = JSON.parse(r.stdout || '{}').minutes || mins; } catch (e) {}
  toast('+' + added + ' ' + t('min_unit'));
  await loadStatus();
  updateExtDisplay();
}

function updateExtDisplay() {
  const now = Math.floor(Date.now() / 1000);
  const appEl = document.getElementById('ext-remaining-app');
  if (appEl) {
    const info = appInfoCache[currentAppKey] || {};
    if (info.uid) {
      const until = (status.extensions || {})[info.uid];
      const left = (until && until > now) ? Math.ceil((until - now) / 60) : 0;
      appEl.textContent = left + ' ' + t('min_unit');
    }
  }
  const groupEl = document.getElementById('ext-remaining-group');
  if (groupEl) {
    const until = (status.group_extensions || {})[currentGroupGid];
    const left = (until && until > now) ? Math.ceil((until - now) / 60) : 0;
    groupEl.textContent = left + ' ' + t('min_unit');
  }
}

// ---------- groups ----------
async function loadGroups() {
  await loadRules();
  const list = document.getElementById('group-list');
  list.innerHTML = '';
  const ids = Object.keys(rules.groups || {});
  if (!ids.length) {
    list.innerHTML = '<div class="card muted-text">' + esc(t('no_groups')) + '</div>';
    return;
  }
  for (const gid of ids) {
    const g = rules.groups[gid];
    const row = document.createElement('div');
    row.className = 'card';
    row.innerHTML = `
      <div class="app" data-act="group-card" data-gid="${esc(gid)}">
        <div class="info">
          <div class="name">${esc(g.name || gid)}</div>
          <div class="sub">
            <span class="pkg">${esc(tf('members', { n: (g.members || []).length }))}</span>
            <span class="tag ${g.enabled ? 'group' : ''}">${esc(g.enabled ? t('on') : t('off'))}</span>
          </div>
        </div>
        <label class="switch">
          <input type="checkbox" data-act="toggle-group" data-gid="${esc(gid)}" ${g.enabled ? 'checked' : ''}>
          <span class="slider"></span>
        </label>
      </div>`;
    list.appendChild(row);
  }
}

function onGroupCard(el, event) {
  if (event) ripple(event, el.parentElement || el);
  openGroupSettings(el.dataset.gid);
}

async function createGroup() {
  const gid = 'g' + Date.now();
  const seq = (rules.group_seq || 0) + 1;
  rules.group_seq = seq;
  rules.groups[gid] = {
    name: 'Group ' + seq, enabled: false, shared_pool: false, members: [],
    always_on: false,
    time_windows: { mode: 'allow', windows: [] },
    duration: { limit_minutes: 0, scope: 'foreground' }
  };
  await saveRules();
  await loadGroups();
}

async function toggleGroup(gid, on) {
  const g = rules.groups[gid];
  if (!g) return;
  g.enabled = on;
  await saveRules();
  await loadStatus();
}

// ---------- group settings ----------
function openGroupSettings(gid) {
  currentGroupGid = gid;
  renderGroupSettings(gid);
  showView('group-set');
}

function toggleMemberList(gid) {
  const el = document.getElementById('member-list');
  if (el && el.innerHTML) {
    el.innerHTML = '';
    return;
  }
  renderMemberList(gid);
}

function renderMemberList(gid) {
  const g = rules.groups[gid];
  if (!g) return;
  const prot = protectedSet();
  const pkgsU = listPackages('user') || [];
  const pkgsS = listPackages('system') || [];
  const pkgs = pkgsU.concat(pkgsS.filter(p => !pkgsU.includes(p)));
  const infos = pkgs.length ? (getPackagesInfo(pkgs) || []) : [];
  const userSet = new Set(pkgsU);
  infos.sort((a, b) => {
    const ua = userSet.has(a.packageName) ? 1 : 0;
    const ub = userSet.has(b.packageName) ? 1 : 0;
    if (ua !== ub) return ub - ua;
    return (a.appLabel || a.packageName).localeCompare(b.appLabel || b.packageName);
  });
  let html = '';
  for (const info of infos) {
    const uid = info.uid || 0;
    if (uid < 10000 || prot.has(info.packageName)) continue;
    const key = Math.floor(uid / 100000) + ':' + info.packageName;
    const label = info.appLabel || info.packageName;
    const other = findGroupOf(key);
    const inThis = (g.members || []).includes(key);
    const disabled = other && other !== gid;
    html += `<div class="member-row"><label>
      <img class="m-icon" src="ksu://icon/${esc(info.packageName)}">
      <span class="m-label">${esc(label)}<div class="uid">${esc(info.packageName)}</div></span>
      <input type="checkbox" data-act="member" data-gid="${esc(gid)}" data-mkey="${esc(key)}" ${inThis ? 'checked' : ''} ${disabled ? 'disabled' : ''}>
      ${disabled ? `<span class="tag group">${esc(groupName(other))}</span>` : ''}
    </label></div>`;
  }
  const el = document.getElementById('member-list');
  if (el) el.innerHTML = html;
}

function renderGroupSettings(gid) {
  const g = rules.groups[gid];
  if (!g) { showView('groups'); return; }
  const tw = g.time_windows || { mode: 'allow', windows: [] };
  const dur = g.duration || { limit_minutes: 0, scope: 'foreground' };
  document.getElementById('group-set-content').innerHTML = `
    <div class="subhead"><button class="back" data-act="back" data-view="groups">←</button><h2>${esc(t('groups'))}</h2></div>
    <div class="card">
      <div class="set-row"><div class="label">${esc(t('group_name'))}</div>
        <input value="${esc(g.name || '')}" data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="group_name"></div>
      <div class="set-row"><div class="label">${esc(t('delete_group'))}</div>
        <button class="btn small danger" data-act="group-del" data-gid="${esc(gid)}">${esc(t('remove'))}</button></div>
      <div class="set-row"><div class="label">${esc(t('shared_pool'))}<div class="hint">${esc(t('shared_pool_hint'))}</div></div>
        <label class="switch"><input type="checkbox" data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="shared_pool" ${g.shared_pool ? 'checked' : ''}><span class="slider"></span></label></div>
      <div class="set-row"><div class="label">${esc(t('select_members'))}<div class="hint">${esc(t('member_hint'))}</div></div>
        <button class="btn small" data-act="members-toggle" data-gid="${esc(gid)}">${(g.members || []).length}</button></div>
      <div id="member-list"></div>
    </div>
    <div class="card">
      <div class="set-row"><div class="label">${esc(t('always_on'))}</div>
        <label class="switch"><input type="checkbox" data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="always_on" ${g.always_on ? 'checked' : ''}><span class="slider"></span></label></div>
      <div class="set-row"><div class="label">${esc(t('lock_block'))}<div class="hint">${esc(t('lock_hint'))}</div></div>
        <label class="switch"><input type="checkbox" data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="lock_block" ${g.lock_block ? 'checked' : ''}><span class="slider"></span></label></div>
      <div class="set-row"><div class="label">${esc(t('add_window'))}</div>
        <button class="btn small" data-act="win-add" data-scope="group" data-gid="${esc(gid)}">+</button></div>
      ${windowRows('group', gid, tw)}
      <div class="set-row"><div class="label">${esc(t('window_mode'))}</div>
        <select data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="window_mode">
          <option value="allow"${tw.mode === 'block' ? '' : ' selected'}>${esc(t('mode_allow'))}</option>
          <option value="block"${tw.mode === 'block' ? ' selected' : ''}>${esc(t('mode_block'))}</option>
        </select></div>
      <div class="set-row"><div class="label">${esc(t('duration'))}<div class="hint">${esc(t('duration_hint'))}</div></div>
        <input type="number" min="0" style="width:80px" value="${dur.limit_minutes || 0}" data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="duration"></div>
      <div class="set-row"><div class="label">${esc(t('cooldown'))}<div class="hint">${esc(t('cooldown_hint'))}</div></div>
        <input type="number" min="0" style="width:80px" value="${dur.freeze_minutes || 0}" data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="cooldown"></div>
      <div class="set-row"><div class="label">${esc(t('scope'))}</div>
        <select data-act="set" data-scope="group" data-gid="${esc(gid)}" data-field="scope">
          <option value="foreground"${dur.scope !== 'any' ? ' selected' : ''}>${esc(t('scope_fg'))}</option>
          <option value="any"${dur.scope === 'any' ? ' selected' : ''}>${esc(t('scope_any'))}</option>
        </select></div>
    </div>
    <div class="card">
      <div class="set-row" style="border-bottom:none;padding-bottom:4px">
        <div class="label">${esc(t('ext_remaining'))}<div class="hint">${esc(t('ext_hint'))}</div></div>
        <span style="display:flex;gap:6px">
          <button class="btn small" data-act="extend" data-key="${esc(gid)}" data-min="5">+5</button>
          <button class="btn small" data-act="extend" data-key="${esc(gid)}" data-min="20">+20</button>
        </span>
      </div>
      <div style="font-size:13px;padding-bottom:2px" id="ext-remaining-group">0</div>
    </div>`;
  updateExtDisplay();
}

async function deleteGroup(gid) {
  delete rules.groups[gid];
  await saveRules();
  toast(t('deleted'));
  showView('groups');
}

async function toggleMember(gid, key, on) {
  const g = rules.groups[gid];
  if (!g) return;
  const m = g.members || (g.members = []);
  const i = m.indexOf(key);
  if (on && i < 0) {
    m.push(key);
    // An app is either managed alone or by a group, never both: park the
    // standalone rule instead of deleting it (its settings stay around).
    if (rules.apps[key]) rules.apps[key].enabled = false;
  }
  if (!on && i >= 0) m.splice(i, 1);
  await saveRules();
}

// ---------- module settings ----------
function renderModuleSettings() {
  const s = rules.settings || {};
  const langVal = s.language || 'en';
  const tzVal = s.timezone || 'UTC';
  let tzOpts = '';
  for (let n = -12; n <= 14; n++) {
    const v = (n === 0) ? 'UTC' : 'UTC' + (n > 0 ? '+' : '') + n;
    const label = (n === 0) ? 'UTC' : 'UTC' + (n > 0 ? '+' + n : n);
    tzOpts += `<option value="${v}"${tzVal === v ? ' selected' : ''}>${label}</option>`;
  }
  document.getElementById('module-settings').innerHTML = `
    <div class="card">
      <div class="set-row"><div class="label">${esc(t('language'))}</div>
        <select data-act="set" data-scope="module" data-field="language">
          <option value="zh"${langVal === 'zh' ? ' selected' : ''}>中文</option>
          <option value="en"${langVal === 'en' ? ' selected' : ''}>English</option>
        </select></div>
      <div class="set-row"><div class="label">${esc(t('timezone'))}</div>
        <select data-act="set" data-scope="module" data-field="timezone">${tzOpts}</select></div>
    </div>
    <div class="card">
      <div class="set-row"><div class="label">${esc(t('status'))}</div>
        <button class="btn small" data-act="status-refresh">${esc(t('refresh'))}</button></div>
      <pre id="status-pre" class="pre-block"></pre>
    </div>
    <div class="card">
      <div class="set-row"><div class="label">${esc(t('log'))}</div>
        <span style="display:flex;gap:6px">
          <button class="btn small" data-act="log-refresh">${esc(t('refresh_log'))}</button>
          <button class="btn small" data-act="log-clear">${esc(t('clear_log'))}</button>
        </span></div>
      <div class="set-row"><div class="label">${esc(t('clear_on_boot'))}</div>
        <label class="switch"><input type="checkbox" data-act="set" data-scope="module" data-field="clear_log_on_boot" ${s.clear_log_on_boot ? 'checked' : ''}><span class="slider"></span></label></div>
      <pre id="log-pre" class="pre-block"></pre>
    </div>`;
  const pre = document.getElementById('status-pre');
  if (pre) pre.textContent = JSON.stringify(status, null, 2);
  loadLog();
}

async function setSetting(k, v) {
  rules.settings = rules.settings || {};
  if (k === 'clear_log_on_boot') {
    rules.settings[k] = !!v;
  } else {
    rules.settings[k] = v;
  }
  await saveRules();
  if (k === 'language') {
    resolveLang();
    applyLanguage();
    renderModuleSettings();
  }
}

// ---------- settings dispatch ----------
async function applySetting(el) {
  const field = el.dataset.field;
  const scope = el.dataset.scope || 'app';
  const key = el.dataset.key || el.dataset.gid || '';
  const val = (el.type === 'checkbox') ? el.checked : el.value;
  if (scope === 'module') return setSetting(field, val);

  const owner = ruleOwner(scope, key);
  if (!owner) return;
  // Editing a rule of a standalone app turns it on, like the switch does; a
  // group keeps its own switch untouched.
  const enable = scope !== 'group';
  const num = () => Math.max(0, parseInt(val, 10) || 0);
  switch (field) {
    case 'always_on':
      owner.always_on = val;
      if (val) owner.enabled = true;
      break;
    case 'lock_block':
      if (enable) owner.enabled = true;
      owner.lock_block = val;
      break;
    case 'window_mode': {
      if (enable) owner.enabled = true;
      const tw = owner.time_windows || (owner.time_windows = { mode: 'allow', windows: [] });
      tw.mode = val;
      break;
    }
    case 'duration': {
      if (enable) owner.enabled = true;
      const d = owner.duration || (owner.duration = { limit_minutes: 0, scope: 'foreground' });
      d.limit_minutes = num();
      break;
    }
    case 'cooldown': {
      if (enable) owner.enabled = true;
      const d = owner.duration || (owner.duration = { limit_minutes: 0, scope: 'foreground' });
      d.freeze_minutes = num();
      break;
    }
    case 'scope': {
      if (enable) owner.enabled = true;
      const d = owner.duration || (owner.duration = { limit_minutes: 0, scope: 'foreground' });
      d.scope = val;
      break;
    }
    case 'shared_pool':
      owner.shared_pool = val;
      break;
    case 'group_name':
      owner.name = val;
      break;
    default:
      return;
  }
  await saveRules();
  if (field === 'always_on' || field === 'shared_pool') await loadStatus();
}

// ---------- delegated events ----------
function closestAct(e) {
  const el = e.target && e.target.closest ? e.target.closest('[data-act]') : null;
  return el;
}
function scopeKey(el) {
  return {
    scope: el.dataset.scope || 'app',
    key: el.dataset.key || el.dataset.gid || '',
    idx: parseInt(el.dataset.idx, 10),
  };
}

function onClick(e) {
  // The switch labels wrap their checkbox: let the native label behaviour do
  // the toggling instead of treating the click as a card tap (the old markup
  // used event.stopPropagation() for this).
  if (e.target && e.target.closest && e.target.closest('label.switch')) return;
  const el = closestAct(e);
  if (!el) return;
  const act = el.dataset.act;
  const { scope, key, idx } = scopeKey(el);
  switch (act) {
    case 'refresh': loadApps(true); break;
    case 'toggle-system': toggleSystem(); break;
    case 'app-card': onAppCard(el, e); break;
    case 'group-card': onGroupCard(el, e); break;
    case 'new-group': createGroup(); break;
    case 'back': showView(el.dataset.view); break;
    case 'extend': doExtend(el.dataset.key, parseInt(el.dataset.min, 10)); break;
    case 'win-add': addWindow(scope, key); break;
    case 'win-del': removeWindow(scope, key, idx); break;
    case 'day': toggleDay(scope, key, idx, parseInt(el.dataset.day, 10), el); break;
    case 'members-toggle': toggleMemberList(el.dataset.gid); break;
    case 'group-del': deleteGroup(el.dataset.gid); break;
    case 'status-refresh': loadStatus(); break;
    case 'log-refresh': loadLog(); break;
    case 'log-clear': clearLog(); break;
    default: break;
  }
}

function onChange(e) {
  const el = closestAct(e);
  if (!el) return;
  const { scope, key, idx } = scopeKey(el);
  switch (el.dataset.act) {
    case 'toggle-app': toggleApp(el.dataset.key, el.checked); break;
    case 'toggle-group': toggleGroup(el.dataset.gid, el.checked); break;
    case 'set': applySetting(el); break;
    case 'win-time': setWindowTime(scope, key, idx, el.dataset.field, el.value); break;
    case 'member': toggleMember(el.dataset.gid, el.dataset.mkey, el.checked); break;
    default: break;
  }
}

function onInput(e) {
  const el = closestAct(e);
  if (!el) return;
  if (el.dataset.act === 'search') onSearch(el.value);
}

// Replaces onerror="" on app icons: a missing icon just disappears.
function onImgError(e) {
  const el = e.target;
  if (el && (el.tagName === 'IMG') && (el.classList.contains('icon') || el.classList.contains('m-icon'))) {
    el.style.visibility = 'hidden';
  }
}

document.addEventListener('click', onClick, false);
document.addEventListener('change', onChange, false);
document.addEventListener('input', onInput, false);
document.addEventListener('error', onImgError, true);

// ---------- init ----------
document.querySelectorAll('#bottom-nav button').forEach(b => {
  b.addEventListener('click', () => showView(b.dataset.view));
});

(async () => {
  if (!isKSUWebUI()) {
    document.getElementById('page-version').textContent = I18N.zh.not_ksu;
    return;
  }
  detectModuleDir();
  await loadRules();
  resolveLang();
  applyLanguage();
  moduleVersion = await readModuleVersion();
  document.getElementById('page-version').textContent = moduleVersion;
  await loadApps();
  setInterval(loadStatus, 15000);
})();
