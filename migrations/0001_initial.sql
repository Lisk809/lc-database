-- 创建 posts 表（若已存在则跳过）
CREATE TABLE IF NOT EXISTS posts (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  user_id TEXT NOT NULL,
  reply_count INTEGER DEFAULT 0,
  attachment_url TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  last_reply_at INTEGER
);

-- 创建 replies 表
CREATE TABLE IF NOT EXISTS replies (
  id TEXT PRIMARY KEY,
  content TEXT NOT NULL,
  user_id TEXT NOT NULL,
  post_id TEXT NOT NULL,
  attachment_url TEXT,
  created_at INTEGER NOT NULL,
  status TEXT DEFAULT 'active'
);

-- 创建 questions 表
CREATE TABLE IF NOT EXISTS questions (
  id TEXT PRIMARY KEY,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  options TEXT,          -- JSON 数组
  answer TEXT,
  user_id TEXT NOT NULL,
  attachment_url TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- 创建索引以优化查询
CREATE INDEX IF NOT EXISTS idx_posts_user_id ON posts(user_id);
CREATE INDEX IF NOT EXISTS idx_replies_post_id ON replies(post_id);
CREATE INDEX IF NOT EXISTS idx_replies_created_at ON replies(created_at);
CREATE INDEX IF NOT EXISTS idx_questions_user_id ON questions(user_id);