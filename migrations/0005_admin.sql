-- 0005_admin.sql: 管理员身份迁移到数据库
-- 管理员判定改为查 users.is_admin（1 = 管理员），不再使用 Secret 名单 ADMIN_USER_IDS。
-- 存量管理员上线后需手动执行一次（把 id 换成实际用户 ID）：
--   UPDATE users SET is_admin = 1 WHERE id IN ('...', '...');

ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;
