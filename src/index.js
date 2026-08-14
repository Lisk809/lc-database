import { Hono } from 'hono'
import { jwt, sign, verify } from 'hono/jwt'
import { cors } from 'hono/cors'
//import { bcrypt } from 'bcryptjs'

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
// 计算 MD5（用于 Gravatar）
async function md5(message) {
  const msgUint8 = new TextEncoder().encode(message)
  const hashBuffer = await crypto.subtle.digest('MD5', msgUint8)
  const hashArray = Array.from(new Uint8Array(hashBuffer))
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
}

// 生成 Gravatar URL
async function getGravatarUrl(email, size = 200) {
  if (!email) return null
  const normalized = email.trim().toLowerCase()
  const hash = await md5(normalized)
  return `https://www.gravatar.com/avatar/${hash}?s=${size}&d=identicon`
}

// 上传文件到 Hugging Face
async function uploadFileToHF(fileBuffer, fileName, userId, env) {
  const hfToken = env.HF_TOKEN
  const repoId = env.HF_REPO_ID
  if (!hfToken || !repoId) {
    throw new Error('Hugging Face credentials not configured')
  }

  const timestamp = Date.now()
  const safeName = fileName.replace(/[^a-zA-Z0-9_.-]/g, '_')
  const filePath = `uploads/${userId}/${timestamp}_${safeName}`

  // 计算 SHA256 和 Base64
  const sha = await sha256(fileBuffer)
  const base64Content = arrayBufferToBase64(fileBuffer)
  const size = fileBuffer.byteLength

  // 构建 Commit API 请求体
  const commitPayload = {
    summary: `Upload ${safeName}`,
    description: `Uploaded by user ${userId}`,
    commits: [
      {
        path: filePath,
        title: `Add ${safeName}`,
        file: {
          content: base64Content,
          encoding: 'base64',
          size: size,
          sha256: sha,
        },
      },
    ],
  }

  const commitUrl = `https://huggingface.co/api/datasets/${repoId}/commit`
  const resp = await fetch(commitUrl, {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${hfToken}`,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(commitPayload),
  })

  if (!resp.ok) {
    const errText = await resp.text()
    throw new Error(`HF commit failed: ${resp.status} - ${errText}`)
  }

  // 返回文件 URL
  return {
    path: filePath,
    url: `https://huggingface.co/datasets/${repoId}/blob/main/${filePath}`,
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
  const { username, email, password } = await c.req.json()
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
  const userId = c.get('userId')
  const user = await c.env.DB.prepare(
    'SELECT id, username, email, avatar_url, bio, created_at FROM users WHERE id = ?'
  ).bind(userId).first()
  if (!user) {
    return c.json({ error: 'User not found' }, 404)
  }

  let avatar = user.avatar_url
  if (!avatar && user.email) {
    avatar = await getGravatarUrl(user.email)
  }

  return c.json({
    id: user.id,
    username: user.username,
    avatar: avatar || null,
    bio: user.bio || '',
    created_at: user.created_at,
  })
})

// 更新个人信息（bio / avatar_url）
app.patch('/api/me', async (c) => {
  const userId = c.get('userId')
  const { bio, avatar_url } = await c.req.json()
  let updates = []
  let values = []
  if (bio !== undefined) {
    updates.push('bio = ?')
    values.push(bio)
  }
  if (avatar_url !== undefined) {
    updates.push('avatar_url = ?')
    values.push(avatar_url)
  }
  if (updates.length === 0) {
    return c.json({ error: 'No fields to update' }, 400)
  }
  values.push(Date.now())
  values.push(userId)
  const stmt = c.env.DB.prepare(
    `UPDATE users SET ${updates.join(', ')}, updated_at = ? WHERE id = ?`
  )
  await stmt.bind(...values).run()
  return c.json({ message: 'Profile updated' })
})

// 我的帖子（分页）
app.get('/api/me/posts', async (c) => {
  const userId = c.get('userId')
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit

  const stmt = c.env.DB.prepare(
    `SELECT id, title, content, reply_count, attachment_url, created_at
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
    `SELECT id, title, content, options, answer, attachment_url, created_at
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

// ---------- 帖子路由 ----------
// 帖子详情（带缓存）
app.get('/api/posts/:id', async (c) => {
  const postId = c.req.param('id')
  if (!/^[0-9a-f-]{36}$/.test(postId)) {
    return c.json({ error: 'Invalid post ID format' }, 400)
  }

  const cacheKey = new Request(c.req.url, c.req.raw)
  const cache = caches.default

  // 1. Cache API
  let cached = await cache.match(cacheKey)
  if (cached) return cached

  // 2. KV
  const kv = c.env.POSTS_CACHE
  const kvKey = `post:${postId}`
  let kvData = await kv.get(kvKey, 'json')
  if (kvData) {
    const resp = c.json(kvData)
    c.executionCtx.waitUntil(cache.put(cacheKey, resp.clone()))
    return resp
  }

  // 3. D1
  const stmt = c.env.DB.prepare(
    'SELECT id, title, content, user_id, reply_count, attachment_url, created_at FROM posts WHERE id = ?'
  )
  const post = await stmt.bind(postId).first()
  if (!post) {
    return c.json({ error: 'Post not found' }, 404)
  }

  // 异步回填缓存
  c.executionCtx.waitUntil((async () => {
    await kv.put(kvKey, JSON.stringify(post), { expirationTtl: 3600 })
    const resp = c.json(post)
    await cache.put(cacheKey, resp.clone())
  })())

  return c.json(post)
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
    `SELECT id, content, user_id, attachment_url, created_at 
     FROM replies 
     WHERE post_id = ? AND status = 'active' 
     ORDER BY created_at DESC 
     LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(postId, limit, offset).all()
  const totalStmt = c.env.DB.prepare(
    'SELECT COUNT(*) as total FROM replies WHERE post_id = ? AND status = "active"'
  )
  const total = (await totalStmt.bind(postId).first()).total

  return c.json({
    data: rows.results || [],
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
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

  return c.json({
    id,
    title,
    content,
    user_id: userId,
    attachment_url: attachmentUrl,
    created_at: now,
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

  return c.json({
    id,
    content,
    user_id: userId,
    post_id: postId,
    attachment_url: attachmentUrl,
    created_at: now,
  }, 201)
})

// ---------- 题目路由 ----------
// 创建题目（支持附件）
app.post('/api/questions', async (c) => {
  const userId = c.get('userId')
  const formData = await c.req.formData()
  const title = formData.get('title')?.toString() || ''
  const content = formData.get('content')?.toString() || ''
  const options = formData.get('options')?.toString() || '[]'
  const answer = formData.get('answer')?.toString() || ''
  const file = formData.get('file')

  if (!title || !content || !options) {
    return c.json({ error: 'Title, content and options are required' }, 400)
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
    `INSERT INTO questions (id, title, content, options, answer, user_id, attachment_url, created_at, updated_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
  await stmt.bind(id, title, content, options, answer, userId, attachmentUrl, now, now).run()

  return c.json({
    id,
    title,
    content,
    options: JSON.parse(options),
    answer,
    user_id: userId,
    attachment_url: attachmentUrl,
    created_at: now,
  }, 201)
})

// 题目列表（分页）
app.get('/api/questions', async (c) => {
  const page = parseInt(c.req.query('page') || '1')
  const limit = Math.min(parseInt(c.req.query('limit') || '10'), 50)
  const offset = (page - 1) * limit

  const stmt = c.env.DB.prepare(
    `SELECT id, title, content, options, answer, user_id, attachment_url, created_at
     FROM questions ORDER BY created_at DESC LIMIT ? OFFSET ?`
  )
  const rows = await stmt.bind(limit, offset).all()
  const totalStmt = c.env.DB.prepare('SELECT COUNT(*) as total FROM questions')
  const total = (await totalStmt.first()).total

  return c.json({
    data: rows.results || [],
    pagination: { page, limit, total, pages: Math.ceil(total / limit) }
  })
})

// ---------- 通用文件上传 ----------
app.post('/api/upload', async (c) => {
  const userId = c.get('userId')
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
    const ext = '.' + fileName.split('.').pop().toLowerCase()
    const maxBytes = parseInt(c.env.MAX_FILE_BYTES || '10485760')
    if (fileBuffer.byteLength > maxBytes) {
      throw new Error(`File too large (max ${maxBytes} bytes)`)
    }
    const allowedExts = (c.env.ALLOWED_EXTENSIONS || '')
      .split(',').map(s => s.trim().toLowerCase()).filter(Boolean)
    if (allowedExts.length && !allowedExts.includes(ext)) {
      throw new Error(`Extension not allowed. Allowed: ${allowedExts.join(', ')}`)
    }
    if (!ALLOWED_MIME_TYPES.has(mimeType) && !allowedExts.includes(ext)) {
      throw new Error(`MIME type "${mimeType}" not allowed`)
    }

    const uploadResult = await uploadFileToHF(fileBuffer, fileName, userId, c.env)
    return c.json({
      success: true,
      path: uploadResult.path,
      url: uploadResult.url,
      size: fileBuffer.byteLength,
    })
  } catch (err) {
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