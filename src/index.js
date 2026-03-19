export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // --- 1. 播放路由重定向 ---
    if (path.startsWith('/play/')) {
      return await handlePlay(request, env, url);
    }

    // --- 2. 获取订阅 ---
    if (path === '/sub') {
      return await generateUserM3U(request, env, url);
    }

    // --- 3. 后台管理 API ---
    if (path.startsWith('/admin/api/')) {
      if (!await checkAuth(request, env)) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Basic' } });
      return await handleAdminAPI(request, env, url);
    }

    // --- 4. 后台管理页面 ---
    if (path === '/admin') {
      if (!await checkAuth(request, env)) return new Response('Unauthorized', { status: 401, headers: { 'WWW-Authenticate': 'Basic' } });
      return new Response(renderAdminPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    // --- 5. Linux DO OAuth2 登录路由 ---
    if (path === '/api/auth/linuxdo') {
      return handleLinuxDoAuth(request, env, url);
    }
    if (path === '/api/auth/linuxdo/callback') {
      return await handleLinuxDoCallback(request, env, url);
    }

    // --- 6. 用户端 API (注册/登录/看板操作) ---
    if (path.startsWith('/api/user/')) {
      return await handleUserAPI(request, env, url);
    }

    // --- 7. 用户前端页面路由 ---
    if (path === '/login') {
      return new Response(renderLoginPage(), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }
    
    if (path === '/') {
      const username = await getUserSession(request, env);
      if (!username) return Response.redirect(url.origin + '/login', 302);
      return new Response(renderUserDashboard(username), { headers: { 'Content-Type': 'text/html;charset=UTF-8' } });
    }

    return new Response('Not Found', { status: 404 });
  },

  async scheduled(event, env, ctx) {
    await updateM3USource(env);
  }
};

// ================= 会话与鉴权辅助函数 =================

async function getUserSession(request, env) {
  const cookieHeader = request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/session_id=([^;]+)/);
  if (!match) return null;
  const sessionId = match[1];
  return await env.IPTV_KV.get('session:' + sessionId);
}

// ================= Linux DO OAuth2 逻辑 =================

function handleLinuxDoAuth(request, env, url) {
  if (!env.LINUXDO_CLIENT_ID) {
    return new Response('未配置 LINUXDO_CLIENT_ID', { status: 500 });
  }
  const redirectUri = url.origin + '/api/auth/linuxdo/callback';
  const state = crypto.randomUUID(); // 简易防 CSRF
  
  // 构造授权链接
  const authUrl = 'https://connect.linux.do/oauth2/authorize' + 
    '?client_id=' + env.LINUXDO_CLIENT_ID + 
    '&response_type=code' + 
    '&redirect_uri=' + encodeURIComponent(redirectUri) + 
    '&state=' + state;
    
  return Response.redirect(authUrl, 302);
}

async function handleLinuxDoCallback(request, env, url) {
  const code = url.searchParams.get('code');
  if (!code) return new Response('Authorization Failed: No code provided', { status: 400 });

  const redirectUri = url.origin + '/api/auth/linuxdo/callback';

  try {
    // 1. 获取 Access Token
    const tokenRes = await fetch('https://connect.linux.do/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: env.LINUXDO_CLIENT_ID,
        client_secret: env.LINUXDO_CLIENT_SECRET,
        grant_type: 'authorization_code',
        code: code,
        redirect_uri: redirectUri
      })
    });
    
    if (!tokenRes.ok) throw new Error('Failed to fetch access token');
    const tokenData = await tokenRes.json();
    const accessToken = tokenData.access_token;

    // 2. 获取用户信息
    const userRes = await fetch('https://connect.linux.do/api/user', {
      headers: { 'Authorization': 'Bearer ' + accessToken }
    });
    
    if (!userRes.ok) throw new Error('Failed to fetch user info');
    const userData = await userRes.json();
    
    // 我们使用 Linux DO 的 username 作为系统内的用户名
    const username = 'linuxdo_' + userData.username;

    // 3. 生成 Session 自动登录 (存活 7 天)
    const sessionId = crypto.randomUUID();
    await env.IPTV_KV.put('session:' + sessionId, username, { expirationTtl: 604800 });
    
    return new Response(null, {
      status: 302,
      headers: {
        'Location': '/',
        'Set-Cookie': 'session_id=' + sessionId + '; Path=/; Max-Age=604800; HttpOnly'
      }
    });

  } catch (err) {
    return new Response('OAuth Error: ' + err.message, { status: 500 });
  }
}

// ================= 核心业务函数 =================

async function handlePlay(request, env, url) {
  const token = url.searchParams.get('token');
  const channelId = url.pathname.replace('/play/', '').replace(/\/$/, '');
  
  if (!token) return new Response('Missing Token', { status: 401 });

  const tokenLimitStr = await env.IPTV_KV.get('token:' + token);
  if (!tokenLimitStr) return new Response('Invalid Token or Expired', { status: 403 });
  
  const limit = parseInt(tokenLimitStr);
  const clientIP = request.headers.get('CF-Connecting-IP') || '127.0.0.1';
  
  if (limit > 0) {
    let ips = await env.IPTV_KV.get('ips:' + token, 'json') || [];
    if (!ips.includes(clientIP)) {
      if (ips.length >= limit) {
        return new Response('Security Triggered: IP limit exceeded. Please go to dashboard to reset IPs.', { status: 403 });
      }
      ips.push(clientIP);
      await env.IPTV_KV.put('ips:' + token, JSON.stringify(ips));
    }
  }

  const channelsStr = await env.IPTV_KV.get('data:channels');
  if (!channelsStr) return new Response('No Channels Data', { status: 500 });
  
  const channels = JSON.parse(channelsStr);
  const target = channels.find(c => c.id === channelId);
  
  if (!target) return new Response('Channel Not Found', { status: 404 });

  return new Response(null, {
    status: 302,
    headers: {
      'Location': target.url,
      'Access-Control-Allow-Origin': '*',
      'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate',
      'Pragma': 'no-cache',
      'Expires': '0'
    }
  });
}

async function updateM3USource(env) {
  const sourceUrl = await env.IPTV_KV.get('config:source_url');
  if (!sourceUrl) return { success: false, msg: 'No source URL configured' };

  try {
    const res = await fetch(sourceUrl);
    const text = await res.text();
    const channels = parseM3U(text);
    
    if (channels.length > 0) {
      await env.IPTV_KV.put('data:channels', JSON.stringify(channels));
      return { success: true, count: channels.length };
    }
    return { success: false, msg: 'No valid channels found' };
  } catch (err) {
    return { success: false, msg: err.message };
  }
}

function generateFixedId(name, url) {
  const str = name + url;
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = Math.imul(31, hash) + str.charCodeAt(i) | 0;
  }
  return 'ch_' + Math.abs(hash).toString(36);
}

function parseM3U(content) {
  const lines = content.split('\n');
  const channels = [];
  let info = {};
  
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('#EXTINF:')) {
      const nameMatch = line.match(/,(.+)$/);
      const logoMatch = line.match(/tvg-logo="([^"]+)"/);
      const groupMatch = line.match(/group-title="([^"]+)"/);
      info = {
        name: nameMatch ? nameMatch[1].trim() : 'Channel ' + i,
        logo: logoMatch ? logoMatch[1] : '',
        group: groupMatch ? groupMatch[1] : 'Default'
      };
    } else if (line.startsWith('http')) {
      channels.push({
        id: generateFixedId(info.name || '', line),
        url: line,
        name: info.name,
        logo: info.logo,
        group: info.group
      });
      info = {};
    }
  }
  return channels;
}

async function generateUserM3U(request, env, url) {
  const token = url.searchParams.get('token');
  if (!token) return new Response('Missing Token', { status: 401 });

  const isValid = await env.IPTV_KV.get('token:' + token);
  if (!isValid) return new Response('Invalid Token or Expired', { status: 403 });

  const channelsStr = await env.IPTV_KV.get('data:channels');
  const channels = JSON.parse(channelsStr || '[]');
  const origin = url.origin;
  
  let m3u = '#EXTM3U\n';
  channels.forEach(c => {
    m3u += '#EXTINF:-1 tvg-logo="' + c.logo + '" group-title="' + c.group + '",' + c.name + '\n';
    m3u += origin + '/play/' + c.id + '?token=' + token + '\n';
  });

  return new Response(m3u, { headers: { 'Content-Type': 'application/vnd.apple.mpegurl' } });
}

// ================= 用户端 API (注册/看板) =================

async function handleUserAPI(request, env, url) {
  const route = url.pathname.replace('/api/user/', '');

  if (request.method === 'POST' && route === 'register') {
    const body = await request.json();
    if (!body.username || !body.password) return Response.json({ success: false, msg: '缺少账密' });
    const exists = await env.IPTV_KV.get('user:' + body.username);
    if (exists) return Response.json({ success: false, msg: '用户名已存在' });
    
    await env.IPTV_KV.put('user:' + body.username, body.password);
    return Response.json({ success: true });
  }

  if (request.method === 'POST' && route === 'login') {
    const body = await request.json();
    const storedPass = await env.IPTV_KV.get('user:' + body.username);
    if (!storedPass || storedPass !== body.password) return Response.json({ success: false, msg: '账号或密码错误' });
    
    const sessionId = crypto.randomUUID();
    await env.IPTV_KV.put('session:' + sessionId, body.username, { expirationTtl: 604800 });
    
    return new Response(JSON.stringify({ success: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session_id=' + sessionId + '; Path=/; Max-Age=604800; HttpOnly'
      }
    });
  }

  const username = await getUserSession(request, env);
  if (!username) return Response.json({ success: false, msg: '未登录' }, { status: 401 });

  if (request.method === 'POST' && route === 'bind') {
    const body = await request.json();
    const tokenExists = await env.IPTV_KV.get('token:' + body.token);
    if (!tokenExists) return Response.json({ success: false, msg: '无效的或已过期的 Token' });

    const owner = await env.IPTV_KV.get('owner:' + body.token);
    if (owner && owner !== username) return Response.json({ success: false, msg: '该 Token 已被其他用户绑定' });
    
    await env.IPTV_KV.put('owner:' + body.token, username);
    
    let list = await env.IPTV_KV.get('user_tokens:' + username, 'json') || [];
    if (!list.includes(body.token)) {
      list.push(body.token);
      await env.IPTV_KV.put('user_tokens:' + username, JSON.stringify(list));
    }
    return Response.json({ success: true });
  }

  if (request.method === 'GET' && route === 'tokens') {
    let list = await env.IPTV_KV.get('user_tokens:' + username, 'json') || [];
    let result = [];
    for (let t of list) {
      const limitStr = await env.IPTV_KV.get('token:' + t);
      if (limitStr) {
        const ips = await env.IPTV_KV.get('ips:' + t, 'json') || [];
        result.push({ token: t, limit: parseInt(limitStr), used: ips.length });
      }
    }
    return Response.json(result);
  }

  if (request.method === 'POST' && route === 'reset_ip') {
    const body = await request.json();
    const owner = await env.IPTV_KV.get('owner:' + body.token);
    if (owner !== username) return Response.json({ success: false, msg: '无权操作' });
    
    await env.IPTV_KV.put('ips:' + body.token, '[]');
    return Response.json({ success: true });
  }

  if (request.method === 'POST' && route === 'logout') {
    const cookieHeader = request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/session_id=([^;]+)/);
    if (match) await env.IPTV_KV.delete('session:' + match[1]);
    
    return new Response(JSON.stringify({ success: true }), {
      headers: {
        'Content-Type': 'application/json',
        'Set-Cookie': 'session_id=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT'
      }
    });
  }

  return new Response('Not Found', { status: 404 });
}

// ================= 后台管理 API & 鉴权 =================

async function checkAuth(request, env) {
  const authHeader = request.headers.get('Authorization');
  if (!authHeader) return false;
  
  const [scheme, encoded] = authHeader.split(' ');
  if (scheme !== 'Basic') return false;
  
  const decoded = atob(encoded);
  const [user, pass] = decoded.split(':');
  
  const expectedUser = await env.IPTV_KV.get('config:admin_user') || env.DEFAULT_ADMIN_USER || 'admin';
  const expectedPass = await env.IPTV_KV.get('config:admin_pass') || env.DEFAULT_ADMIN_PASS || 'admin123';
  
  return user === expectedUser && pass === expectedPass;
}

async function handleAdminAPI(request, env, url) {
  const route = url.pathname.replace('/admin/api/', '');
  
  if (request.method === 'GET' && route === 'status') {
    const sourceUrl = await env.IPTV_KV.get('config:source_url') || '';
    const channels = JSON.parse(await env.IPTV_KV.get('data:channels') || '[]');
    return Response.json({ sourceUrl, channelCount: channels.length });
  }
  
  if (request.method === 'POST' && route === 'sync') {
    const result = await updateM3USource(env);
    return Response.json(result);
  }

  if (request.method === 'POST' && route === 'config') {
    const body = await request.json();
    await env.IPTV_KV.put('config:source_url', body.sourceUrl);
    return Response.json({ success: true });
  }

  if (request.method === 'GET' && route === 'tokens') {
    const list = await env.IPTV_KV.list({ prefix: 'token:' });
    const tokens = await Promise.all(list.keys.map(async k => {
      const t = k.name.replace('token:', '');
      const limit = await env.IPTV_KV.get(k.name);
      const ips = await env.IPTV_KV.get('ips:' + t, 'json') || [];
      const owner = await env.IPTV_KV.get('owner:' + t) || '未绑定';
      
      let expireText = '永久有效';
      if (k.expiration) {
        const d = new Date(k.expiration * 1000);
        expireText = d.toLocaleString('zh-CN', { timeZone: 'Asia/Shanghai' });
      }

      return { token: t, limit: parseInt(limit), used: ips.length, ips: ips, expireText: expireText, owner: owner };
    }));
    return Response.json(tokens);
  }

  if (request.method === 'POST' && route === 'token') {
    const body = await request.json();
    const options = {};
    if (body.expireHours && Number(body.expireHours) > 0) {
       options.expirationTtl = Math.max(60, Number(body.expireHours) * 3600);
    }
    const limitVal = body.limit === '' ? '0' : body.limit.toString();
    await env.IPTV_KV.put('token:' + body.token, limitVal, options);
    return Response.json({ success: true });
  }

  if (request.method === 'DELETE' && route === 'token') {
    const body = await request.json();
    await env.IPTV_KV.delete('token:' + body.token);
    await env.IPTV_KV.delete('ips:' + body.token);
    await env.IPTV_KV.delete('owner:' + body.token);
    return Response.json({ success: true });
  }

  if (request.method === 'POST' && route === 'reset_ip') {
    const body = await request.json();
    await env.IPTV_KV.put('ips:' + body.token, '[]');
    return Response.json({ success: true });
  }

  return new Response('Not Found', { status: 404 });
}

// ================= 前端页面渲染 =================

function renderLoginPage() {
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>系统登录/注册</title>
  <style>
    body { font-family: system-ui; background: #f4f4f5; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
    .card { background: white; padding: 2rem; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.1); width: 300px; text-align: center; }
    input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ddd; border-radius: 4px; box-sizing: border-box; }
    button { color: white; border: none; padding: 10px; border-radius: 4px; cursor: pointer; width: 100%; margin-top: 10px; }
    .btn-login { background: #3b82f6; }
    .btn-reg { background: #10b981; }
    .btn-linuxdo { background: #232323; margin-top: 20px; display: flex; align-items: center; justify-content: center; gap: 8px; }
    .divider { margin: 20px 0; color: #999; font-size: 14px; display: flex; align-items: center; }
    .divider::before, .divider::after { content: ""; flex: 1; border-bottom: 1px solid #eee; }
    .divider::before { margin-right: 10px; } .divider::after { margin-left: 10px; }
  </style>
</head>
<body>
  <div class="card">
    <h2>IPTV 订阅系统</h2>
    <input type="text" id="user" placeholder="用户名">
    <input type="password" id="pass" placeholder="密码">
    <button class="btn-login" onclick="doAction('login')">登录</button>
    <button class="btn-reg" onclick="doAction('register')">注册新账号</button>
    
    <div class="divider">或者</div>
    
    <button class="btn-linuxdo" onclick="window.location.href='/api/auth/linuxdo'">
      <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm0 18c-4.41 0-8-3.59-8-8s3.59-8 8-8 8 3.59 8 8-3.59 8-8 8zm-2-5.5l7-4.5-7-4.5v9z"/></svg>
      使用 Linux DO 登录
    </button>
  </div>
  <script>
    async function doAction(action) {
      const u = document.getElementById('user').value;
      const p = document.getElementById('pass').value;
      if(!u || !p) return alert('请输入账密');
      
      const res = await fetch('/api/user/' + action, {
        method: 'POST', body: JSON.stringify({username: u, password: p})
      });
      const data = await res.json();
      if(data.success) {
        if(action === 'register') alert('注册成功，请登录！');
        else window.location.href = '/';
      } else {
        alert(data.msg);
      }
    }
  </script>
</body>
</html>`;
}

function renderUserDashboard(username) {
  // 此处与上个版本相同，渲染用户仪表盘
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>用户控制台</title>
  <style>
    body { font-family: system-ui; background: #f9fafb; margin: 0; padding: 20px; }
    .container { max-width: 800px; margin: auto; }
    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
    input { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
    button { background: #3b82f6; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
    button.warning { background: #f59e0b; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
    .header { display: flex; justify-content: space-between; align-items: center; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <h1>欢迎回来, ` + username + `</h1>
      <button class="warning" onclick="logout()">退出登录</button>
    </div>
    
    <div class="card">
      <h2>绑定新 Token</h2>
      <p>请输入管理员分发给您的 Token 激活码进行绑定：</p>
      <input type="text" id="bindToken" placeholder="输入 Token">
      <button onclick="bind()">立即绑定</button>
    </div>

    <div class="card">
      <h2>我的订阅列表</h2>
      <table>
        <thead><tr>
          <th>Token</th>
          <th>状态/限制</th>
          <th>M3U 订阅链接</th>
          <th>操作</th>
        </tr></thead>
        <tbody id="list"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function loadData() {
      const res = await fetch('/api/user/tokens');
      const data = await res.json();
      const tbody = document.getElementById('list');
      let html = '';
      for(let i=0; i<data.length; i++) {
        let t = data[i];
        let limitTxt = t.limit === 0 ? '无限 IP' : (t.used + ' / ' + t.limit + ' IP');
        let subLink = window.location.origin + '/sub?token=' + t.token;
        
        html += '<tr>' +
          '<td>' + t.token + '</td>' +
          '<td>' + limitTxt + '</td>' +
          '<td><button onclick="copy(\\'' + subLink + '\\')">复制订阅链接</button></td>' +
          '<td><button class="warning" onclick="resetIp(\\'' + t.token + '\\')">解除IP封锁</button></td>' +
        '</tr>';
      }
      tbody.innerHTML = html;
    }

    async function bind() {
      const t = document.getElementById('bindToken').value;
      if(!t) return;
      const res = await fetch('/api/user/bind', { method: 'POST', body: JSON.stringify({token: t}) });
      const data = await res.json();
      if(data.success) { alert('绑定成功'); document.getElementById('bindToken').value=''; loadData(); }
      else alert(data.msg);
    }

    async function resetIp(token) {
      await fetch('/api/user/reset_ip', { method: 'POST', body: JSON.stringify({token: token}) });
      alert('已重置该 Token 的 IP 记录');
      loadData();
    }

    async function logout() {
      await fetch('/api/user/logout', { method: 'POST' });
      window.location.href = '/login';
    }

    function copy(text) {
      navigator.clipboard.writeText(text).then(() => alert('已复制！'));
    }

    loadData();
  </script>
</body>
</html>`;
}

function renderAdminPage() {
  // 此处与上个版本的管理员后台完全相同
  return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
  <meta charset="UTF-8">
  <title>管理后台</title>
  <style>
    body { font-family: system-ui; background: #f9fafb; margin: 0; padding: 20px; }
    .container { max-width: 900px; margin: auto; }
    .card { background: white; padding: 20px; border-radius: 8px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); margin-bottom: 20px; }
    input { padding: 8px; border: 1px solid #ddd; border-radius: 4px; }
    button { background: #10b981; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; }
    button.danger { background: #ef4444; }
    button.warning { background: #f59e0b; }
    table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 14px; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
  </style>
</head>
<body>
  <div class="container">
    <h1>管理后台</h1>
    
    <div class="card">
      <h2>1. 原始直播源</h2>
      <p>频道数 <span id="chCount">0</span></p>
      <input type="text" id="sourceUrl" placeholder="输入 M3U 订阅链接" style="width: 70%;">
      <button onclick="saveConfig()">保存</button>
      <button onclick="syncM3U()" style="background:#3b82f6;">立即抓取</button>
    </div>

    <div class="card">
      <h2>2. Token 管理 (激活码)</h2>
      <p style="color:#666; font-size:12px;">给用户分发下方的 Token。IP限制填 0 代表无限IP。</p>
      <div style="display:flex; gap: 10px; margin-bottom: 10px;">
        <input type="text" id="newToken" placeholder="生成新 Token" style="flex: 2;">
        <input type="number" id="newLimit" placeholder="IP限制(0为无限)" value="3" style="flex: 1;">
        <input type="number" id="expireHours" placeholder="有效期(小时)" style="flex: 1.5;">
        <button onclick="addToken()" style="flex: 1;">生成</button>
      </div>
      
      <table>
        <thead><tr>
          <th>Token</th><th>归属用户</th><th>IP 状态</th><th>过期时间</th><th>操作</th>
        </tr></thead>
        <tbody id="tokenList"></tbody>
      </table>
    </div>
  </div>

  <script>
    async function loadData() {
      const statusRes = await fetch('/admin/api/status');
      const status = await statusRes.json();
      document.getElementById('sourceUrl').value = status.sourceUrl;
      document.getElementById('chCount').innerText = status.channelCount;

      const tokensRes = await fetch('/admin/api/tokens');
      const tokens = await tokensRes.json();
      const tbody = document.getElementById('tokenList');
      
      let html = '';
      for(let i=0; i<tokens.length; i++) {
        let t = tokens[i];
        let limitTxt = t.limit === 0 ? '无限' : (t.used + '/' + t.limit);
        html += '<tr>' +
          '<td>' + t.token + '</td>' +
          '<td>' + t.owner + '</td>' +
          '<td><span title="' + t.ips.join(', ') + '">' + limitTxt + '</span></td>' +
          '<td>' + t.expireText + '</td>' +
          '<td>' +
            '<button class="warning" onclick="resetIp(\\'' + t.token + '\\')" style="margin-right:5px;">清IP</button>' +
            '<button class="danger" onclick="delToken(\\'' + t.token + '\\')">删</button>' +
          '</td>' +
        '</tr>';
      }
      tbody.innerHTML = html;
    }

    async function saveConfig() {
      const url = document.getElementById('sourceUrl').value;
      await fetch('/admin/api/config', { method: 'POST', body: JSON.stringify({ sourceUrl: url }) });
      alert('保存成功');
    }

    async function syncM3U() {
      const res = await fetch('/admin/api/sync', { method: 'POST' });
      const data = await res.json();
      alert(data.success ? '成功更新频道' : '失败: ' + data.msg);
      loadData();
    }

    async function addToken() {
      const token = document.getElementById('newToken').value;
      const limit = document.getElementById('newLimit').value;
      const expireHours = document.getElementById('expireHours').value;
      if(!token) return alert('请输入 Token');
      
      await fetch('/admin/api/token', { method: 'POST', body: JSON.stringify({ token: token, limit: limit, expireHours: expireHours }) });
      document.getElementById('newToken').value = '';
      loadData();
    }

    async function delToken(token) {
      if(!confirm('确定删除吗？')) return;
      await fetch('/admin/api/token', { method: 'DELETE', body: JSON.stringify({ token: token }) });
      loadData();
    }

    async function resetIp(token) {
      await fetch('/admin/api/reset_ip', { method: 'POST', body: JSON.stringify({ token: token }) });
      loadData();
    }

    loadData();
  </script>
</body>
</html>`;
}
