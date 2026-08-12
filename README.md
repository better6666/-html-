# HTML网页转在线链接

这是一个静态前端页面，可直接部署到 GitHub Pages。

## 文件说明

- `index.html`：用户打开的上传/粘贴 HTML 页面，内置前端激活码校验。
- `激活码批量生成器.html`：本地使用的激活码生成页面。
- `可视化/`：页面截图。

## GitHub Pages 部署

1. 新建 GitHub 仓库。
2. 上传本目录中的 `index.html`、`激活码批量生成器.html`、`.nojekyll`、`.gitignore`、`README.md`、`可视化/`。
3. 进入仓库 `Settings` -> `Pages`。
4. `Build and deployment` 选择 `Deploy from a branch`。
5. `Branch` 选择 `main` 和 `/root`。
6. 保存后等待 GitHub 生成访问链接。

## 重要提醒

当前版本把激活码写在前端代码里，只适合临时演示或早期测试。公开部署后，懂浏览器的人可以在源代码里看到这些卡密。正式售卖建议接入后端数据库做卡密校验和核销。
