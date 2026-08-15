import { Hono } from 'hono'
import { jwt, sign, verify } from 'hono/jwt'
import { cors } from 'hono/cors'
//import { bcrypt } from 'bcryptjs'
// import { uploadFiles } from '@huggingface/hub'
import {HuggingFaceAPI} from './huggingfaceAPI.js'

// ---------- 全局配置 ----------
const ALLOWED_MIME_TYPES = new Set([
  'text/csv',
  'application/json',
  'application/parquet',
  'application/octet-stream',
  'image/png',
  'image/jpeg',
  'application/pdf'
])

// ---------- 创建 Hono 应用 ----------
const app = new Hono()
// ---------- 辅助函数 ----------
// ---------- 密码哈希工具（基于 Web Crypto API） ----------
async function hashPassword(password, salt) {
  const encoder = new TextEncoder()
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    { name: 'PBKDF2' },
    false,
    ['deriveBits']
  )
  const hashBuffer = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: encoder.encode(salt),
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    256
  )
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}
// ---------- 工具函数：计算 SHA256 ----------
async function sha256(buffer) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}
// ---------- 工具函数：ArrayBuffer 转 Base64 ----------
function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i])
  }
  return btoa(binary)
}
async function generateSalt(length = 16) {
  const array = new Uint8Array(length)
  crypto.getRandomValues(array)
  return Array.from(array).map(b => b.toString(16).padStart(2, '0')).join('')
}

async function verifyPassword(password, hash, salt) {
  const computedHash = await hashPassword(password, salt)
  return computedHash === hash
}
// ---------- 管理员名单 ----------
// 管理员人数少、身份单一：直接读 Secret（ADMIN_USER_IDS，逗号分隔的用户 ID），
// 不在数据库里维护管理员标记
function getAdminIds(env) {
  return (env.ADMIN_USER_IDS || '').split(',').map((s) => s.trim()).filter(Boolean)
}
// ---------- Turnstile 人机验证 ----------
async function verifyTurnstile(token, secret) {
  const body = new FormData()
  body.append('secret', secret)
  body.append('response', token)
  const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
    method: 'POST',
    body,
  })
  return res.json()
}
// 计算 MD5（用于 Gravatar）
async function md5(message) {
  const msgUint8 = new TextEncoder().encode(message)
  const hashBuffer = await crypto.subtle.digest('MD5', msgUint8)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}
// ---------- 徽章授予（示例：根据条件自动授予，这里简单实现） ----------
async function awardBadgeIfNotExists(userId, badgeId, env) {
  const existing = await env.DB.prepare(
    'SELECT 1 FROM user_badges WHERE user_id = ? AND badge_id = ?'
  ).bind(userId, badgeId).first();
  if (existing) return;
  const now = Date.now();
  await env.DB.prepare(
    'INSERT INTO user_badges (user_id, badge_id, awarded_at) VALUES (?, ?, ?)'
  ).bind(userId, badgeId, now).run();
}
// 生成 Gravatar URL
async function getGravatarUrl(email, size = 200) {
  if (!email) return null
  const normalized = email.trim().toLowerCase()
  const hash = await md5(normalized)
  return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=identicon`
}
async function saveFileRecord(userId, fileInfo, env) {
  // fileInfo: { fileName, filePath, fileUrl, fileSize, mimeType, sha256 }
  const id = crypto.randomUUID()
  const now = Date.now()
  const stmt = env.DB.prepare(
    `INSERT INTO files (id, user_id, file_name, file_path, file_url, file_size, mime_type, sha256, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  await stmt.bind(
    id,
    userId,
    fileInfo.fileName,
    fileInfo.filePath,
    fileInfo.fileUrl,
    fileInfo.fileSize,
    fileInfo.mimeType || null,
    fileInfo.sha256 || null,
    now,
    now
  ).run()
  return id
}
// 上传文件到 Hugging Face
// 不再需要 sha256 和 base64 辅助函数，改用原生 Blob 和 FormData 方式（推荐）

// ---------- 上传到 Hugging Face（使用 LFS 协议） ----------
async function uploadFileToHF(fileBuffer, fileName, userId, env) {
  const hfToken = env.HF_TOKEN
  const repoId = env.HF_REPO_ID
  if (!hfToken || !repoId) {
    throw new Error('Hugging Face credentials not configured')
  }

  // 文件大小限制（建议设为 50MB，但 Workers 内存可能受限，可调整为 10MB）
  const maxBytes = parseInt(env.MAX_FILE_BYTES || '10485760') // 默认 10MB
  if (fileBuffer.byteLength > maxBytes) {
    throw new Error(`File too large: ${fileBuffer.byteLength} bytes (max ${maxBytes} bytes)`)
  }

  const timestamp = Date.now()
  const safeName = fileName.replace(/[^a-zA-Z0-9_.-]/g, '_')
  const filePath = `uploads/${userId}/${timestamp}_${safeName}`

  // 将 ArrayBuffer 转换为 Blob（HuggingFaceAPI 需要）
  const blob = new Blob([fileBuffer])

  // 创建 API 实例
  const api = new HuggingFaceAPI(hfToken, repoId, false) // 默认为公开仓库

  // 上传文件（自动处理 LFS 或直接提交）
  const result = await api.uploadFile(
    blob,
    filePath,
    `Upload ${safeName}`
    // 不传入预计算 SHA256，让 API 内部计算（小文件没问题）
  )

  if (!result.success) {
    throw new Error('Upload failed: ' + JSON.stringify(result))
  }

  return {
    path: result.filePath,
    url: result.fileUrl,
    fileName: safeName,
    fileSize: fileBuffer.byteLength,
    sha256: result.oid || null,
    mimeType: blob.type || 'application/octet-stream'
  }
}

// 校验上传的文件
async function validateUploadedFile(file, env) {
  if (!file || !(file instanceof File)) return null

  const buffer = await file.arrayBuffer()
  const maxBytes = parseInt(env.MAX_FILE_BYTES || '10485760')
  if (buffer.byteLength > maxBytes) {
    throw new Error(`File too large (max ${maxBytes} bytes)`)
  }

  const ext = '.' + file.name.split('.').pop().toLowerCase()
  const allowedExts = (env.ALLOWED_EXTENSIONS || '')
    .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
  if (allowedExts.length && !allowedExts.includes(ext)) {
    throw new Error(`Extension not allowed. Allowed: ${allowedExts.join(', ')}`)
  }

  const mimeType = file.type || 'application/octet-stream'
  if (!ALLOWED_MIME_TYPES.has(mimeType) && !allowedExts.includes(ext)) {
    throw new Error(`MIME type "${mimeType}" not allowed`)
  }

  return { buffer, fileName: file.name }
}

// ---------- 全局中间件 ----------
// 1. CORS
app.use('*', cors({
  origin: '*',
  allowMethods: ['GET', 'POST', 'PATCH', 'OPTIONS'],
  allowHeaders: ['Content-Type', 'Authorization'],
  maxAge: 86400,
}))

// 2. 安全头
app.use('*', async (c, next) => {
  await next()
  c.res.headers.set('X-Content-Type-Options', 'nosniff')
  c.res.headers.set('X-Frame-Options', 'DENY')
  c.res.headers.set('Referrer-Policy', 'strict-origin-when-cross-origin')
})

app.use('/api/*', async (c, next) => {
  if (c.req.path.startsWith('/api/auth/')) {
    await next()
    return
  }
  const authHeader = c.req.header('Authorization')
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return c.json({ error: 'Missing or invalid Authorization header' }, 401)
  }
  const token = authHeader.slice(7)
  try {
    const payload = await verify(token, c.env.JWT_SECRET,"HS256")
    c.set('jwtPayload', payload)
    c.set('userId', payload.sub)
    await next()
  } catch (err) {
    console.error('Verify error:', err)
    return c.json({ error: 'Unauthorized', detail: err.message, token }, 401)
  }
})
// 4. 限流中间件（基于 userId，公开路径用 'anonymous'）
app.use('/api/*', async (c, next) => {
  let userId = 'anonymous'
  const payload = c.get('jwtPayload')
  if (payload?.sub) {
    userId = payload.sub
  }
  c.set('userId', userId)

  const limiter = c.env.RATE_LIMITER
  // 如果限流器未绑定，跳过限流（避免报错）
  if (limiter) {
    const { success } = await limiter.limit({
      key: userId,
      limit: 20,
      duration: 60,
    })
    if (!success) {
      return c.json({ error: 'Too Many Requests' }, 429, {
        'Retry-After': '60'
      })
    }
  }
  await next()
})
// ---------- 认证路由 ----------
// 注册
app.post('/api/auth/register', async (c) => {
  const { username, email, password, turnstile_token } = await c.req.json()
  if (!username || !email || !password) {
    return c.json({ error: 'Username, email and password required' }, 400)
  }
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  if (!emailRegex.test(email)) {
    return c.json({ error: 'Invalid email format' }, 400)
  }
  if (password.length < 6) {
    return c.json({ error: 'Password must be at least 6 characters' }, 400)
  }

  // Turnstile 人机验证（fail closed：密钥缺失或验证异常一律拒绝注册）
  if (typeof turnstile_token !== 'string' || !turnstile_token) {
    return c.json({ error: 'Captcha token required' }, 400)
  }
  const turnstileSecret = c.env.TURNSTILE_SECRET
  if (!turnstileSecret) {
    console.error('TURNSTILE_SECRET is not configured')
    return c.json({ error: 'Server configuration error' }, 500)
  }
  let siteverify
  try {
    siteverify = await verifyTurnstile(turnstile_token, turnstileSecret)
  } catch (err) {
    console.error('Turnstile siteverify request failed:', err)
    return c.json({ error: 'Server configuration error' }, 500)
  }
  if (!siteverify.success) {
    return c.json({ error: 'Captcha verification failed' }, 400)
  }

  // 检查用户名或邮箱是否已存在
  const existing = await c.env.DB.prepare(
    'SELECT id FROM users WHERE username = ? OR email = ?'
  ).bind(username, email.trim().toLowerCase()).first()
  if (existing) {
    return c.json({ error: 'Username or email already taken' }, 409)
  }

  // 生成盐并哈希密码
  const salt = await generateSalt(16)
  const hash = await hashPassword(password, salt)

  const id = crypto.randomUUID()
  const now = Date.now()
  const stmt = c.env.DB.prepare(
    `INSERT INTO users (id, username, email, password_hash, salt, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
  // 注意：users 表需要增加 salt 列
  await stmt.bind(id, username, email.trim().toLowerCase(), hash, salt, now, now).run()

  return c.json({ message: 'User registered successfully', user_id: id }, 201)
})
// 登录
app.post('/api/auth/login', async (c) => {
  const { username, password } = await c.req.json()
  if (!username || !password) {
    return c.json({ error: 'Username and password required' }, 400)
  }

  const user = await c.env.DB.prepare(
    'SELECT id, username, email, password_hash, salt FROM users WHERE username = ?'
  ).bind(username).first()
  if (!user) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }

  const valid = await verifyPassword(password, user.password_hash, user.salt)
  if (!valid) {
    return c.json({ error: 'Invalid credentials' }, 401)
  }
  const secret = c.env.JWT_SECRET
  if (!secret || typeof secret !== 'string' || secret.length < 10) {
    console.error('JWT_SECRET is invalid or missing')
    return c.json({ error: 'Server configuration error' }, 500)
  }
  const payload = {
    sub: user.id,
    username: user.username,
    exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24 * 7,
  }
  const token = await sign(payload, c.env.JWT_SECRET)

  return c.json({
    token,
    user: {
      id: user.id,
      username: user.username,
      email: user.email,
    }
  })
})

// ---------- 个人主页路由 ----------
// 获取当前用户信息（含 Gravatar）
app.get('/api/me', async (c) => {
  const userId = c.get('userId');
  const user = await c.env.DB.prepare(
    'SELECT id, username, email, bio, created_at FROM users WHERE id = ?'
  ).bind(userId).first();
  if (!user) return c.json({ error: 'User not found' }, 404);

  // 获取用户徽章
  const badges = await c.env.DB.prepare(
    `SELECT b.id, b.name, b.description, b.icon_url, ub.awarded_at
     FROM user_badges ub
     JOIN badges b ON ub.badge_id = b.id
     WHERE ub.user_id = ? ORDER BY ub.awarded_at DESC`
  ).bind(userId).all();

  // 头像统一使用 Gravatar（由注册邮箱决定），不再支持自定义头像上传
  const avatar = await getGravatarUrl(user.email);

  return c.json({
    id: user.id,
    username: user.username,
    avatar,
    bio: user.bio || '',
    created_at: Math.floor(user.created_at / 1000),
    is_admin: getAdminIds(c.env).includes(userId),
    badges: (badges.results || []).map((b) => ({ ...b, awarded_at: Math.floor(b.awarded_at / 1000) })),
  });
});
// 更新个人信息（仅 bio；头像由 Gravatar 提供，不接受自定义）
app.patch('/api/me', async (c) => {
  const userId = c.get('userId')
  const { bio } = await c.req.json()
  if (bio === undefined) {
    return c.json({ error: 'No fields to update' }, 400)
  }
  await c.env.DB.prepare(
    'UPDATE users SET bio = ?, updated_at = ? WHERE id = ?'
  ).bind(bio, Date.now(), userId).run()
  return c.json({ message: 'Profile updated' })
})

// 我的帖子（分页）
app.get('/api/me/posts', async (c) => {
  const userId = c.get('userId')
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit

  const stmt = c.env.DB.prepare(
    `SELECT id, title, content, reply_count, attachment_url, created_at / 1000 AS created_at
     FROM posts WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(userId, limit, offset).all()
  const totalStmt = c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM posts WHERE user_id = ?'
  )
  const total = (await totalStmt.bind(userId).first()).total

  return c.json({
    data: rows.results || [],
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})

// 我的题目（分页）
app.get('/api/me/questions', async (c) => {
  const userId = c.get('userId')
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit

  const stmt = c.env.DB.prepare(
    `SELECT id, title, content, answer, attachment_url, created_at / 1000 AS created_at
     FROM questions WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(userId, limit, offset).all()
  const totalStmt = c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM questions WHERE user_id = ?'
  )
  const total = (await totalStmt.bind(userId).first()).total

  return c.json({
    data: rows.results || [],
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})
app.get('/api/me/files', async (c) => {
  const userId = c.get('userId')
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '20'), 100)
  const offset = (page - 1) * limit

  const stmt = c.env.DB.prepare(
    `SELECT id, file_name, file_path, file_url, file_size, mime_type, created_at / 1000 AS created_at
     FROM files WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(userId, limit, offset).all()
  const totalStmt = c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM files WHERE user_id = ?'
  )
  const total = (await totalStmt.bind(userId).first()).total

  return c.json({
    data: rows.results || [],
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})
// ---------- 帖子路由 ----------
// ---------- 公告 ----------
// 获取公告列表（分页）
app.get('/api/announcements', async (c) => {
  const page = parseInt(c.req.query('page') || '1');
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50);
  const offset = (page - 1) * limit;

  const stmt = c.env.DB.prepare(
    `SELECT a.id, a.title, a.content, a.author_id, a.created_at / 1000 AS created_at,
            u.username AS author_username, u.email AS author_email
     FROM announcements a
     LEFT JOIN users u ON u.id = a.author_id
     ORDER BY a.created_at DESC LIMIT ? OFFSET ?`
  );
  const rows = await stmt.bind(limit, offset).all();
  const totalStmt = c.env.DB.prepare('SELECT COUNT(*) as total FROM announcements');
  const total = (await totalStmt.first()).total;

  return c.json({
    data: await Promise.all((rows.results || []).map((row) => withAuthor(row, 'author_id'))),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  });
});

// 发布公告（仅管理员）
app.post('/api/announcements', async (c) => {
  const userId = c.get('userId');
  // 检查管理员权限：名单来自 Secret（ADMIN_USER_IDS），见 getAdminIds
  if (!getAdminIds(c.env).includes(userId)) {
    return c.json({ error: 'Forbidden' }, 403);
  }

  const { title, content } = await c.req.json();
  if (!title || !content) {
    return c.json({ error: 'Title and content required' }, 400);
  }

  const id = crypto.randomUUID();
  const now = Date.now();
  await c.env.DB.prepare(
    `INSERT INTO announcements (id, title, content, author_id, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  ).bind(id, title, content, userId, now, now).run();

  const author = await fetchAuthor(c.env, userId);
  return c.json({ id, title, content, author, created_at: Math.floor(now / 1000) }, 201);
});
// 帖子详情（带缓存）
app.get('/api/posts/:id', async (c) => {
  const postId = c.req.param('id')
  if (!/^[0-9a-f-]{36}$/.test(postId)) {
    return c.json({ error: 'Invalid post ID format' }, 400)
  }

  // v4：头像改为 Gravatar，缓存键带版本号使旧条目（可能含自定义头像）失效
  const cacheKey = new Request(c.req.url + (c.req.url.includes('?') ? '&v=4' : '?v=4'), c.req.raw)
  const cache = caches.default

  // 1. Cache API
  let cached = await cache.match(cacheKey)
  if (cached) return cached

  // 2. KV
  const kv = c.env.POSTS_CACHE
  const kvKey = `post:v4:${postId}` // v4：头像改为 Gravatar（旧缓存键作废）
  let kvData = await kv.get(kvKey, 'json')
  if (kvData) {
    const resp = c.json(kvData)
    c.executionCtx.waitUntil(cache.put(cacheKey, resp.clone()))
    return resp
  }

  // 3. D1
  const stmt = c.env.DB.prepare(
    `SELECT p.id, p.title, p.content, p.user_id, p.reply_count, p.likes_count, p.attachment_url,
            p.created_at / 1000 AS created_at,
            u.username AS author_username, u.email AS author_email
     FROM posts p
     LEFT JOIN users u ON u.id = p.user_id
     WHERE p.id = ?`
  )
  const post = await stmt.bind(postId).first()
  if (!post) {
    return c.json({ error: 'Post not found' }, 404)
  }

  const body = await withAuthor(post)

  // 异步回填缓存
  c.executionCtx.waitUntil((async () => {
    await kv.put(kvKey, JSON.stringify(body), { expirationTtl: 3600 })
    const resp = c.json(body)
    await cache.put(cacheKey, resp.clone())
  })())

  return c.json(body)
})

// 帖子回复列表（分页）
app.get('/api/posts/:id/replies', async (c) => {
  const postId = c.req.param('id')
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit

  if (!/^[0-9a-f-]{36}$/.test(postId)) {
    return c.json({ error: 'Invalid post ID' }, 400)
  }

  const stmt = c.env.DB.prepare(
    `SELECT r.id, r.content, r.user_id, r.attachment_url, r.created_at / 1000 AS created_at,
            u.username AS author_username, u.email AS author_email
     FROM replies r
     LEFT JOIN users u ON u.id = r.user_id
     WHERE r.post_id = ? AND r.status = 'active'
     ORDER BY r.created_at DESC
     LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(postId, limit, offset).all()
  const totalStmt = c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM replies WHERE post_id = ? AND status = "active"'
  )
  const total = (await totalStmt.bind(postId).first()).total

  return c.json({
    data: await Promise.all((rows.results || []).map((row) => withAuthor(row))),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})
// ---------- 帖子点赞 ----------
app.post('/api/posts/:id/like', async (c) => {
  const postId = c.req.param('id');
  const userId = c.get('userId');
  const now = Date.now();

  // 检查帖子是否存在
  const post = await c.env.DB.prepare('SELECT id FROM posts WHERE id = ?').bind(postId).first();
  if (!post) return c.json({ error: 'Post not found' }, 404);

  // 检查是否已点赞
  const existing = await c.env.DB.prepare(
    'SELECT 1 FROM post_likes WHERE user_id = ? AND post_id = ?'
  ).bind(userId, postId).first();

  if (existing) {
    // 取消点赞（删除记录，减少计数）
    await c.env.DB.prepare('DELETE FROM post_likes WHERE user_id = ? AND post_id = ?')
      .bind(userId, postId).run();
    await c.env.DB.prepare('UPDATE posts SET likes_count = likes_count - 1 WHERE id = ?')
      .bind(postId).run();
  } else {
    // 添加点赞
    await c.env.DB.prepare(
      'INSERT INTO post_likes (user_id, post_id, created_at) VALUES (?, ?, ?)'
    ).bind(userId, postId, now).run();
    await c.env.DB.prepare('UPDATE posts SET likes_count = likes_count + 1 WHERE id = ?')
      .bind(postId).run();
  }
  // 计数已变化：详情缓存失效
  await invalidatePostCache(postId, c);
  return c.json({ liked: !existing, likes_count: await getLikesCount(postId, c.env) });
});

// 辅助：获取点赞数（可复用）
async function getLikesCount(postId, env) {
  const result = await env.DB.prepare('SELECT likes_count FROM posts WHERE id = ?')
    .bind(postId).first();
  return result ? result.likes_count : 0;
}

// 辅助：把联表查出的作者字段（author_username / author_email）组装成 author 对象
// 头像统一为 Gravatar（由邮箱决定）；LEFT JOIN 查不到用户时返回 null（如用户已删除）
async function withAuthor(row, idField = 'user_id') {
  const { author_username, author_email, ...rest } = row
  return {
    ...rest,
    author: author_username
      ? { id: row[idField], username: author_username, avatar_url: await getGravatarUrl(author_email) }
      : null,
  }
}

// 辅助：按 id 取用户，供创建接口返回作者信息（头像为 Gravatar）
async function fetchAuthor(env, userId) {
  const user = await env.DB.prepare(
    'SELECT username, email FROM users WHERE id = ?'
  ).bind(userId).first()
  return user
    ? { id: userId, username: user.username, avatar_url: await getGravatarUrl(user.email) }
    : null
}
// 辅助：帖子详情缓存失效（点赞数/回复数变化后调用；KV 键见 GET /api/posts/:id）
async function invalidatePostCache(postId, c) {
  await c.env.POSTS_CACHE.delete(`post:v4:${postId}`);
  const detailUrl = new URL(c.req.url);
  detailUrl.pathname = `/api/posts/${postId}`;
  detailUrl.search = 'v=4';
  c.executionCtx.waitUntil(caches.default.delete(detailUrl.toString()));
}
// ---------- 帖子列表（分页、排序、筛选） ----------
app.get('/api/posts', async (c) => {
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit
  const userId = c.req.query('userId') || null   // 可选：按用户筛选
  const sortBy = c.req.query('sortBy') || 'created_at' // created_at, likes_count, reply_count
  const order = c.req.query('order') || 'DESC'   // DESC 或 ASC

  // 构建查询参数
  const params = []
  let whereClause = ''
  if (userId) {
    whereClause = 'WHERE p.user_id = ?'
    params.push(userId)
  }

  // 允许的排序字段（防止注入）
  const allowedSortFields = ['created_at', 'likes_count', 'reply_count', 'updated_at']
  const safeSort = allowedSortFields.includes(sortBy) ? sortBy : 'created_at'
  const safeOrder = order.toUpperCase() === 'ASC' ? 'ASC' : 'DESC'

  const sql = `
    SELECT p.id, p.title, p.content, p.user_id, p.reply_count, p.likes_count, p.attachment_url,
           p.created_at / 1000 AS created_at,
           u.username AS author_username, u.email AS author_email
    FROM posts p
    LEFT JOIN users u ON u.id = p.user_id
    ${whereClause}
    ORDER BY p.${safeSort} ${safeOrder}
    LIMIT ? OFFSET ?
  `
  params.push(limit, offset)

  // 查询数据
  const stmt = c.env.DB.prepare(sql)
  const rows = await stmt.bind(...params).all()

  // 查询总数
  const countSql = `
    SELECT COUNT(*) as total
    FROM posts p
    ${whereClause}
  `
  const countParams = userId ? [userId] : []
  const totalStmt = c.env.DB.prepare(countSql)
  const totalResult = await totalStmt.bind(...countParams).first()
  const total = totalResult ? totalResult.total : 0

  // 缓存策略：列表缓存 30 秒（可选的，因为分页参数多样，这里简单不缓存，或使用 Cache API）
  // 我们使用 Cache API 缓存 30 秒，但注意查询参数不同会导致多个缓存项
  const cacheKey = new Request(c.req.url, c.req.raw)
  const cache = caches.default
  let cached = await cache.match(cacheKey)
  if (cached) return cached

  const response = c.json({
    data: await Promise.all((rows.results || []).map((row) => withAuthor(row))),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
  response.headers.set('Cache-Control', 'public, max-age=30, s-maxage=30, stale-while-revalidate=30')
  c.executionCtx.waitUntil(cache.put(cacheKey, response.clone()))
  return response
})
// 创建帖子（支持附件）
app.post('/api/posts', async (c) => {
  const userId = c.get('userId')
  const formData = await c.req.formData()
  const title = formData.get('title')?.toString() || ''
  const content = formData.get('content')?.toString() || ''
  const file = formData.get('file')

  if (!title || !content) {
    return c.json({ error: 'Title and content are required' }, 400)
  }

  let attachmentUrl = null
  if (file) {
    try {
      const { buffer, fileName } = await validateUploadedFile(file, c.env)
      const uploadResult = await uploadFileToHF(buffer, fileName, userId, c.env)
      attachmentUrl = uploadResult.url
    } catch (err) {
      return c.json({ error: err.message }, 400)
    }
  }

  const id = crypto.randomUUID()
  const now = Date.now()
  const stmt = c.env.DB.prepare(
    `INSERT INTO posts (id, title, content, user_id, attachment_url, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
  await stmt.bind(id, title, content, userId, attachmentUrl, now, now).run()

  const author = await fetchAuthor(c.env, userId)
  return c.json({
    id,
    title,
    content,
    user_id: userId,
    author,
    attachment_url: attachmentUrl,
    created_at: Math.floor(now / 1000),
  }, 201)
})

// 回复帖子（支持附件）
app.post('/api/posts/:id/replies', async (c) => {
  const postId = c.req.param('id')
  const userId = c.get('userId')
  const formData = await c.req.formData()
  const content = formData.get('content')?.toString() || ''
  const file = formData.get('file')

  if (!content) {
    return c.json({ error: 'Reply content is required' }, 400)
  }

  let attachmentUrl = null
  if (file) {
    try {
      const { buffer, fileName } = await validateUploadedFile(file, c.env)
      const uploadResult = await uploadFileToHF(buffer, fileName, userId, c.env)
      attachmentUrl = uploadResult.url
    } catch (err) {
      return c.json({ error: err.message }, 400)
    }
  }

  const id = crypto.randomUUID()
  const now = Date.now()
  const stmt = c.env.DB.prepare(
    `INSERT INTO replies (id, content, user_id, post_id, attachment_url, created_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
  await stmt.bind(id, content, userId, postId, attachmentUrl, now).run()

  // 更新帖子回复计数
  const updateStmt = c.env.DB.prepare(
    `UPDATE posts SET reply_count = reply_count + 1, last_reply_at = ? WHERE id = ?`
  )
  await updateStmt.bind(now, postId).run()

  // 回复数已变化：详情缓存失效
  await invalidatePostCache(postId, c)

  const author = await fetchAuthor(c.env, userId)
  return c.json({
    id,
    content,
    user_id: userId,
    post_id: postId,
    author,
    attachment_url: attachmentUrl,
    created_at: Math.floor(now / 1000),
  }, 201)
})

// ---------- 题目路由 ----------
// 创建题目（支持附件；题目与参考答案均为 markdown）
app.post('/api/questions', async (c) => {
  const userId = c.get('userId')
  const formData = await c.req.formData()
  const title = formData.get('title')?.toString() || ''
  const content = formData.get('content')?.toString() || ''
  const answer = formData.get('answer')?.toString() || ''
  const file = formData.get('file')

  if (!title || !content) {
    return c.json({ error: 'Title and content are required' }, 400)
  }

  let attachmentUrl = null
  if (file) {
    try {
      const { buffer, fileName } = await validateUploadedFile(file, c.env)
      const uploadResult = await uploadFileToHF(buffer, fileName, userId, c.env)
      attachmentUrl = uploadResult.url
    } catch (err) {
      return c.json({ error: err.message }, 400)
    }
  }

  const id = crypto.randomUUID()
  const now = Date.now()
  const stmt = c.env.DB.prepare(
    `INSERT INTO questions (id, title, content, answer, user_id, attachment_url, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  )
  await stmt.bind(id, title, content, answer, userId, attachmentUrl, now, now).run()

  const author = await fetchAuthor(c.env, userId)
  return c.json({
    id,
    title,
    content,
    answer,
    user_id: userId,
    author,
    attachment_url: attachmentUrl,
    created_at: Math.floor(now / 1000),
  }, 201)
})

// 题目列表（分页）
app.get('/api/questions', async (c) => {
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit

  const stmt = c.env.DB.prepare(
    `SELECT q.id, q.title, q.content, q.answer, q.user_id, q.attachment_url,
            q.created_at / 1000 AS created_at,
            u.username AS author_username, u.email AS author_email
     FROM questions q
     LEFT JOIN users u ON u.id = q.user_id
     ORDER BY q.created_at DESC LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(limit, offset).all()
  const totalStmt = c.env.DB.prepare('SELECT COUNT(*) as total FROM questions')
  const total = (await totalStmt.first()).total

  return c.json({
    data: await Promise.all((rows.results || []).map((row) => withAuthor(row))),
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})

// ---------- 通用文件上传 ----------
app.post('/api/upload', async (c) => {
  const userId = c.get('userId')

  // 1. 解析请求，获取文件
  const contentType = c.req.header('Content-Type') || ''
  let fileBuffer, fileName, mimeType

  if (contentType.includes('multipart/form-data')) {
    const formData = await c.req.formData()
    const file = formData.get('file')
    if (!file || !(file instanceof File)) {
      return c.json({ error: 'No file field found' }, 400)
    }
    fileBuffer = await file.arrayBuffer()
    fileName = file.name || 'upload.dat'
    mimeType = file.type || 'application/octet-stream'
  } else {
    fileBuffer = await c.req.arrayBuffer()
    const url = new URL(c.req.url)
    fileName = url.searchParams.get('filename') || 'upload.dat'
    mimeType = c.req.header('Content-Type') || 'application/octet-stream'
  }

  try {
    // 2. 校验文件
    const maxBytes = parseInt(c.env.MAX_FILE_BYTES || '10485760') // 默认10MB
    if (fileBuffer.byteLength > maxBytes) {
      throw new Error(`File too large (max ${maxBytes} bytes)`)
    }

    const ext = '.' + fileName.split('.').pop().toLowerCase()
    const allowedExts = (c.env.ALLOWED_EXTENSIONS || '')
      .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
    if (allowedExts.length && !allowedExts.includes(ext)) {
      throw new Error(`Extension not allowed. Allowed: ${allowedExts.join(', ')}`)
    }

    // 3. 上传到 Hugging Face (自动处理 LFS)
    const uploadResult = await uploadFileToHF(fileBuffer, fileName, userId, c.env)

    // 4. 保存文件元数据到 D1
    const fileId = await saveFileRecord(userId, {
      fileName: uploadResult.fileName,
      filePath: uploadResult.path,
      fileUrl: uploadResult.url,
      fileSize: uploadResult.fileSize,
      sha256: uploadResult.sha256,
      mimeType: uploadResult.mimeType,
    }, c.env)

    // 5. 返回成功响应
    return c.json({
      success: true,
      fileId,
      path: uploadResult.path,
      url: uploadResult.url,
      size: uploadResult.fileSize,
      fileName: uploadResult.fileName,
    }, 201)

  } catch (err) {
    console.error('Upload error:', err.message)
    return c.json({ error: err.message }, 400)
  }
})
// ---------- 全局错误处理 ----------
app.onError((err, c) => {
  console.error('Unhandled error:', err)
  return c.json({ error: 'Internal server error' }, 500)
})

// ---------- 导出 Worker ----------
export default app