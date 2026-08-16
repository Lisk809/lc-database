-- 题目发布状态：published 全站可见、可提交；draft 仅管理员可见、不可提交
-- 存量题目视为已发布（ALTER 默认值自动回填），新题目由创建接口显式写入 'draft'
ALTER TABLE questions ADD COLUMN status TEXT NOT NULL DEFAULT 'published';
