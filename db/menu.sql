START TRANSACTION;

DELETE FROM `menu`;

INSERT INTO `menu` (`title`,`path`,`icon`,`order`,`parent_id`,`active`,`created_at`,`updated_at`) VALUES
('文章列表','/admin/dashboard','bi bi-journal-text', 1, NULL, 1, NOW(), NOW()),
('新建文章','/admin/posts/new','bi bi-pencil-square', 2, NULL, 1, NOW(), NOW()),
('分类管理','/admin/categories','bi bi-folder', 3, NULL, 1, NOW(), NOW()),
('标签管理','/admin/tags','bi bi-tags', 4, NULL, 1, NOW(), NOW()),
('系列管理','/admin/series','bi bi-collection', 5, NULL, 1, NOW(), NOW()),
('评论管理','/admin/comments','bi bi-chat-left-text', 6, NULL, 1, NOW(), NOW()),
('浏览记录','/admin/views','bi bi-eye', 7, NULL, 1, NOW(), NOW()),
('审计日志','/admin/audit','bi bi-shield-lock', 8, NULL, 1, NOW(), NOW()),
('资源管理','/admin/attachments','bi bi-file-earmark-image', 9, NULL, 1, NOW(), NOW()),
('菜单管理','/admin/menus','bi bi-list', 10, NULL, 1, NOW(), NOW()),
('Redis 监控','/admin/redis','bi bi-database', 11, NULL, 1, NOW(), NOW());

COMMIT;

INSERT INTO `menu` (`title`,`path`,`icon`,`order`,`parent_id`,`active`,`created_at`,`updated_at`)
VALUES ('系统管理','', 'bi bi-gear', 100, NULL, 1, NOW(), NOW());

SET @pid := LAST_INSERT_ID();

UPDATE `menu` SET `parent_id`=@pid, `order`=101 WHERE `path`='/admin/attachments';
UPDATE `menu` SET `parent_id`=@pid, `order`=102 WHERE `path`='/admin/audit';
UPDATE `menu` SET `parent_id`=@pid, `order`=103 WHERE `path`='/admin/menus';
UPDATE `menu` SET `parent_id`=@pid, `order`=104 WHERE `path`='/admin/redis';
