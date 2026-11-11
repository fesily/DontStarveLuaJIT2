---
name: gha-github-download-504-hardening
description: GitHub Actions 在下载 GitHub 资源时 504/超时（vcpkg port 源码、vcpkg-tool bootstrap、meson wrap clone）；含 gh 日志定位、缓存/重试修法、Windows Git Bash 的 GNU link 顶掉 MSVC link.exe 陷阱
---

# 适用

GitHub Actions（尤其 Windows runner）失败于 GitHub CDN 下载（504 / `The operation timed out` / `Download failed, halting portfile`），或需要在不复跑本地全流程的情况下定位失败步骤与真因。

# 1 先定位，不要猜

```bash
gh auth status                       # 本机已登录 fesily，scopes: repo, workflow
gh api repos/<o>/<r>/actions/runs/<run>/jobs?per_page=20 \
  --jq '.jobs[] | "\(.name) \(.status) \(.conclusion)", (.steps[] | select(.conclusion!="success" and .conclusion!="skipped") | "   \(.number) \(.name) \(.conclusion)")'
# 日志（job 结束后才可用；需要 repo scope，public API 无 auth 会 403）
gh run view --log --job <jobId> > /tmp/job.log
```

- 未认证 `api.github.com` 限流 **60/h**，批量轮询会瞬间耗尽（reset 前所有查询返回 403）；优先 `gh`。
- 300 s 级的失败常是**步骤内超时**，不是
