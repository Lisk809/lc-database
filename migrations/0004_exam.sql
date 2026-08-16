-- 0004_exam.sql: 联考模型迁移
-- 1) 新增 exams 表（联考事件实体，仅管理员创建）
-- 2) submissions/grades 从 question 维度重建为 exam 维度（旧数据为测试数据，直接丢弃）
-- 3) 撤销 0003 的 questions.status（题库回归纯开放集合）
-- 惯例：id 为 UUID 字符串、时间戳为毫秒整数、不建外键（与现有表一致）

-- 联考表：draft 仅管理员可见；published 全站可见、可提交答卷
CREATE TABLE IF NOT EXISTS exams (
  id           TEXT PRIMARY KEY,
  title        TEXT NOT NULL,
  description  TEXT,                              -- 说明（markdown，可选）
  paper_url    TEXT NOT NULL,                     -- 试卷 PDF URL（HuggingFace）
  paper_name   TEXT NOT NULL,
  sheet_url    TEXT NOT NULL,                     -- 答题卡 PDF URL（HuggingFace）
  sheet_name   TEXT NOT NULL,
  status       TEXT NOT NULL DEFAULT 'draft',     -- draft | published
  created_at   INTEGER NOT NULL,                  -- 毫秒
  updated_at   INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_exams_created_at     ON exams(created_at);
CREATE INDEX IF NOT EXISTS idx_exams_status_created ON exams(status, created_at);

-- 提交/批改表重建：exam 维度（一名学生每场联考最多一条）
DROP TABLE IF EXISTS submissions;   -- 旧表索引随表一并删除
DROP TABLE IF EXISTS grades;

CREATE TABLE submissions (
  id              TEXT PRIMARY KEY,
  user_id         TEXT NOT NULL,
  exam_id         TEXT NOT NULL,
  content         TEXT,                             -- 保留列（兼容队列/预览代码）；联考提交仅 PDF，恒为 NULL
  attachment_url  TEXT,
  attachment_name TEXT,
  status          TEXT NOT NULL DEFAULT 'pending',  -- pending | graded
  created_at      INTEGER NOT NULL,
  updated_at      INTEGER NOT NULL,
  UNIQUE (user_id, exam_id)
);

CREATE TABLE grades (
  id            TEXT PRIMARY KEY,
  submission_id TEXT NOT NULL UNIQUE,
  grader_id     TEXT NOT NULL,
  score         INTEGER NOT NULL CHECK (score BETWEEN 0 AND 100),
  comment       TEXT,
  created_at    INTEGER NOT NULL,
  updated_at    INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_submissions_user_id        ON submissions(user_id);
CREATE INDEX IF NOT EXISTS idx_submissions_exam_id        ON submissions(exam_id);
CREATE INDEX IF NOT EXISTS idx_submissions_status_created ON submissions(status, created_at);
CREATE INDEX IF NOT EXISTS idx_grades_grader_id           ON grades(grader_id);
CREATE INDEX IF NOT EXISTS idx_grades_created_at          ON grades(created_at);

-- 题库回归开放集合：撤销 0003 的 status 列
-- （D1 基于 SQLite >= 3.35，支持 DROP COLUMN；若报错则建新表-拷贝-换名重建）
ALTER TABLE questions DROP COLUMN status;
