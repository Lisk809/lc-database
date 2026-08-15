-- 提交与批改表（在线批改与学情分析系统）
-- 惯例：id 为 UUID 字符串、时间戳为毫秒整数、不建外键（与现有表一致）

-- 提交表：一名学生每题最多一条；重交 = upsert 覆盖内容并把状态打回 pending
CREATE TABLE IF NOT EXISTS submissions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  question_id     TEXT NOT NULL,
  content         TEXT,                             -- 文本答案（Markdown），可为 NULL（纯 PDF 提交）
  attachment_url  TEXT,                             -- PDF 答卷 URL（HuggingFace），不写入 files 表
  attachment_name TEXT,
  status          TEXT NOT NULL DEFAULT 'pending',  -- pending | graded
  created_at      INTEGER NOT NULL,                 -- 毫秒
  updated_at      INTEGER NOT NULL,
  UNIQUE (user_id, question_id)                     -- upsert 冲突目标
);

-- 批改表：覆盖式更新（每条提交只有一条最新批改）
CREATE TABLE IF NOT EXISTS grades (
  id            TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL UNIQUE,               -- UNIQUE 自带索引，无需再建
  grader_id     TEXT NOT NULL,
  score         INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  comment       TEXT,
  created_at    INTEGER NOT NULL,                   -- 毫秒
  updated_at    INTEGER NOT NULL
);

-- 查询索引
CREATE INDEX IF NOT EXISTS idx_submissions_user_id        ON submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_submissions_question_id    ON submissions(question_id);
CREATE INDEX IF NOT EXISTS idx_submissions_status_created ON submissions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_grades_grader_id           ON grades(grader_id);
CREATE INDEX IF NOT EXISTS idx_grades_created_at          ON grades(created_at);
