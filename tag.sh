#!/usr/bin/env bash
# 打 tag 前自动将 frontend 子模块更新到 origin/main，并提交子模块指针变更
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

info() { echo "[ArgusMind] $*"; }
err() { echo "[ArgusMind] 错误: $*" >&2; exit 1; }

TAG=""
MESSAGE=""
PUSH=0

usage() {
  cat <<'EOF'
用法: ./tag.sh [选项] <版本标签>

在打 tag 前自动将 frontend 子模块更新到 origin/main 最新提交；
若子模块指针有变化，会在主仓库提交一次 chore 提交，再创建标签。

选项:
  -m, --message <说明>  附带到 annotated tag 的说明（默认使用版本号）
  -p, --push            创建标签后推送当前分支与标签到 origin
  -h, --help            显示此帮助

示例:
  ./tag.sh v1.2.3
  ./tag.sh -m "release 1.2.3" v1.2.3
  ./tag.sh -p v1.2.3
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--message)
      [[ $# -ge 2 ]] || err "缺少 --message 参数"
      MESSAGE="$2"
      shift 2
      ;;
    -p|--push)
      PUSH=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    -v*)
      err "未知选项: $1（版本标签请作为位置参数，不要用 -v 前缀）"
      ;;
    -*)
      err "未知选项: $1"
      ;;
    *)
      [[ -z "$TAG" ]] || err "只能指定一个版本标签"
      TAG="$1"
      shift
      ;;
  esac
done

[[ -n "$TAG" ]] || { usage; exit 1; }
[[ "$TAG" =~ ^v[0-9] ]] || err "版本标签建议以 v 开头（如 v1.0.0），以匹配 CI 的 v* 触发规则"

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || err "当前目录不是 Git 仓库"

if git show-ref --tags --quiet "refs/tags/$TAG" 2>/dev/null; then
  err "标签已存在: $TAG"
fi

has_other_dirty_paths() {
  local line path
  while IFS= read -r line; do
    [[ -z "$line" ]] && continue
    path="${line:3}"
    [[ "$path" == "frontend" ]] && continue
    return 0
  done < <(git status --porcelain)
  return 1
}

if has_other_dirty_paths; then
  err "工作区存在未提交的更改（frontend 子模块指针除外），请先提交或暂存后再打 tag"
fi

chmod +x "$ROOT/scripts/update-frontend-submodule.sh"
"$ROOT/scripts/update-frontend-submodule.sh"

if ! git diff --quiet HEAD -- frontend 2>/dev/null || ! git diff --cached --quiet HEAD -- frontend 2>/dev/null; then
  info "提交 frontend 子模块指针更新..."
  git add frontend
  git commit -m "chore: bump frontend submodule to latest main"
else
  info "frontend 子模块指针已是最新 main，无需额外提交"
fi

MESSAGE="${MESSAGE:-$TAG}"
info "创建标签: $TAG"
git tag -a "$TAG" -m "$MESSAGE"

BRANCH="$(git branch --show-current 2>/dev/null || true)"
cat <<EOF

========================================
 标签已创建: $TAG
========================================
frontend 子模块: $(git -C frontend rev-parse --short HEAD)
EOF

if [[ "$PUSH" -eq 1 ]]; then
  if [[ -n "$BRANCH" ]]; then
    info "推送分支 $BRANCH ..."
    git push origin "$BRANCH"
  else
    info "推送当前 HEAD ..."
    git push origin HEAD
  fi
  info "推送标签 $TAG ..."
  git push origin "$TAG"
else
  cat <<EOF

下一步（手动推送）:
  git push origin ${BRANCH:-HEAD}
  git push origin $TAG
EOF
fi

cat <<'EOF'
========================================
EOF
