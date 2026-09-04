"""PoC-in-GitHub 本地知识库同步工具。

从 nomi-sec/PoC-in-GitHub 元数据仓库同步各 CVE 的公开 PoC 代码到本地，
按 年份/CVE-ID/仓库名 结构组织，并生成 metadata.json 与 README.md。

用法:
    python sync_pocs.py [--mirror] [--no-randomize-mirrors]
"""

import argparse
import json
import logging
import os
import random
import re
import shutil
import stat
import subprocess
import sys
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# --- 配置区（硬编码，仅适配 nomi-sec/PoC-in-GitHub 上游仓库） ---
META_REPO_URL = "https://github.com/nomi-sec/PoC-in-GitHub.git"
META_REPO_PATH = Path("./PoC-in-GitHub_meta")
LOCAL_POC_DIR = Path("./PoC_DB")
LOG_DIR = Path("./logs")
MAX_LOG_FILES = 3  # 日志最多保留份数

GIT_RETRIES = 3          # 对于每个镜像源，尝试 3 次
GIT_RETRY_DELAY = 7      # 重试间隔（秒）
MAX_WORKERS = 15         # 并发线程数

# 镜像源列表（仅 --mirror 启用时使用）
MIRROR_HOSTS = [
    "https://ghfast.top/",
    # "https://ghproxy.net/",
    # "https://wget.la/",
    "https://hk.gh-proxy.com/",
]

# CVE ID 严格格式（上游仓库文件名形如 CVE-YYYY-NNNN.json）
CVE_ID_PATTERN = re.compile(r'^CVE-(\d{4})-\d+$')

# 安全增强：禁用外部协议、凭据助手（同步第三方 PoC 时的必要防护）
# 注意：曾尝试加 `-c url."https://".insteadOf=` 来清空全局 insteadOf，但该写法语义是
# "把空前缀重写为 https://"，会让 git 给所有 URL 前面拼接 https:// 导致 URL 损坏
# （报错 fatal: protocol '"https' is not supported）。故不使用该项；
# 如担心全局 insteadOf 被恶意篡改，可在运行前手动 `git config --global --unset-regexp '^url\.'`。
GIT_SECURITY_OPTS = [
    '-c', 'protocol.ext.allow=never',
    '-c', 'protocol.file.allow=user',
    '-c', 'credential.helper=',
]

# --- 日志系统 ---

IS_TTY = sys.stdout.isatty()


def _setup_logging() -> Path:
    """配置 logging，同时输出到控制台和按时间戳命名的日志文件，并清理超量旧日志。"""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_file = LOG_DIR / f"sync_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"

    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(log_file, encoding='utf-8'),
            logging.StreamHandler(sys.stdout),
        ],
    )
    # 清理超量旧日志（按修改时间排序，保留最近 MAX_LOG_FILES 份）
    _cleanup_old_logs()
    return log_file


def _cleanup_old_logs() -> None:
    """删除超出 MAX_LOG_FILES 份数的最旧日志文件。"""
    logs = sorted(LOG_DIR.glob("sync_*.log"), key=lambda p: p.stat().st_mtime, reverse=True)
    for stale in logs[MAX_LOG_FILES:]:
        try:
            stale.unlink()
        except OSError as e:
            logging.warning(f"清理旧日志失败 {stale}: {e}")


def log_info(msg: str) -> None:
    logging.info(msg)


def log_warn(msg: str) -> None:
    logging.warning(msg)


def log_progress(i: int, total: int, name: str) -> None:
    """单行刷新进度。非 TTY 场景（如重定向）退化为普通日志，避免日志文件难读。"""
    msg = f"[*] 同步进度: {i}/{total} ({name})"
    if IS_TTY:
        print(f"\r{msg}\x1b[K", end='', flush=True)
    else:
        logging.info(msg)


# --- 核心功能函数 ---

def sanitize_filename(name: str) -> str:
    """净化文件名，移除 Windows 和 Linux 下不允许的字符及末尾的点和空格。"""
    name = name.strip(' .')
    return re.sub(r'[<>:"/\\|?*]', '', name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="PoC-in-GitHub 本地知识库同步工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        '--mirror', action='store_true',
        help='启用镜像加速（默认关闭，直连 GitHub 官方源）',
    )
    # 默认开启随机化：多 worker 并发时固定顺序会让首个镜像承担绝大多数流量，
    # 容易触发公共镜像的限速。随机化能在 worker 之间天然分散负载。
    # 如需固定顺序调试（例如排查某镜像故障），可用 --no-randomize-mirrors 关闭。
    parser.add_argument(
        '--randomize-mirrors', action=argparse.BooleanOptionalAction, default=True,
        help='随机化镜像源顺序做负载均衡（仅 --mirror 时生效；默认开启，可用 --no-randomize-mirrors 关闭）',
    )
    return parser.parse_args()


def _validate_url(url: str) -> bool:
    """仅允许 http(s) URL，防止 git ext/file 等协议绕过。"""
    return isinstance(url, str) and url.startswith(('https://', 'http://'))


def _build_urls_to_try(original_url: str, use_mirror: bool, randomize: bool) -> list[str]:
    """构建候选 URL 列表。始终把官方源放在最后兜底。"""
    urls_to_try = [original_url]
    if use_mirror:
        mirrors = MIRROR_HOSTS[:]
        if randomize:
            random.shuffle(mirrors)
        # 镜像 URL 形如 https://ghfast.top/https://github.com/owner/repo.git
        urls_to_try = [host + original_url for host in mirrors] + [original_url]
    return urls_to_try


def run_command(command: list[str], cwd: Path | str, repo_name: str,
                retries: int = GIT_RETRIES, delay: int = GIT_RETRY_DELAY) -> bool:
    """为单个 git 命令执行重试逻辑，自动注入安全参数。"""
    for attempt in range(retries):
        try:
            # 将安全参数插入到 'git' 命令之后
            try:
                git_index = command.index("git")
            except ValueError:
                log_warn(f"命令不包含 'git'：{command}")
                return False
            final_command = command[:git_index + 1] + GIT_SECURITY_OPTS + command[git_index + 1:]

            subprocess.run(
                final_command, cwd=cwd, check=True, capture_output=True, text=True,
                encoding='utf-8', errors='ignore',
            )
            return True
        except FileNotFoundError:
            log_warn(f"命令 '{command[0]}' 未找到。请确保 Git 已安装并在 PATH 中。")
            return False
        except subprocess.CalledProcessError as e:
            error_msg = (e.stderr or '').strip()
            if attempt < retries - 1:
                log_warn(f"仓库 {repo_name} 操作失败 (尝试 {attempt + 1}/{retries})。将在 {delay} 秒后重试... 错误: {error_msg}")
                time.sleep(delay)
            else:
                log_warn(f"仓库 {repo_name} 操作失败，已达最大重试次数 ({retries} 次)。最终错误: {error_msg}")
                return False
    return False


def _force_remove(func, path, exc_info):
    """rmtree 的 onerror 回调：清除只读属性后重试。Windows 下 .git/pack 常被占用。"""
    try:
        os.chmod(path, stat.S_IWRITE)
    except OSError:
        pass
    try:
        func(path)
    except OSError:
        # Windows 保留设备名（AUX/CON/PRN/NUL/COM*/LPT*）和含冒号的文件名
        # （如 'config/:0'）无法用 Win32 API 删除。尝试用 \\?\ 长路径前缀绕开
        # Win32 路径解析层，直接走 NT API。
        if os.name == 'nt':
            try:
                long_path = '\\\\?\\' + str(Path(path).resolve())
                func(long_path)
                return
            except OSError:
                pass
        raise


def safe_rmtree(path: Path, retries: int = 3, delay: int = 1) -> bool:
    """Windows 友好的目录删除：带重试、只读属性清除和长路径支持。"""
    for i in range(retries):
        try:
            shutil.rmtree(path, onerror=_force_remove)
            return True
        except OSError as e:
            if i < retries - 1:
                time.sleep(delay)
            else:
                log_warn(f"清理目录 {path} 失败（重试 {retries} 次）: {e}")
                return False
    return False  # 不可达：循环每个分支都 return，仅作为类型检查的兜底


def sync_meta_repo(use_mirror: bool, randomize: bool) -> None:
    """克隆或更新元数据仓库，使用镜像故障切换逻辑。"""
    log_info(f"--- 1. 同步元数据仓库: {META_REPO_URL} ---")
    repo_name = "meta-repository"
    original_url = META_REPO_URL
    urls_to_try = _build_urls_to_try(original_url, use_mirror, randomize)

    # 更新逻辑
    if META_REPO_PATH.is_dir() and META_REPO_PATH.joinpath(".git").is_dir():
        log_info("元数据仓库已存在，正在拉取更新...")
        update_successful = False
        try:
            for i, url in enumerate(urls_to_try):
                log_info(f"尝试更新元数据仓库 (源 {i + 1}/{len(urls_to_try)})...")
                if run_command(["git", "remote", "set-url", "origin", url], META_REPO_PATH, repo_name, retries=1):
                    if run_command(["git", "pull"], META_REPO_PATH, repo_name):
                        update_successful = True
                        break
        finally:
            # 无论结果如何，都恢复原始 URL
            if use_mirror:
                if not run_command(["git", "remote", "set-url", "origin", original_url], META_REPO_PATH, repo_name, retries=1):
                    log_warn("恢复元数据仓库 origin URL 失败，可能残留镜像地址。")
        if not update_successful:
            log_warn("警告: 更新元数据仓库失败。")
    # 克隆逻辑
    else:
        log_info("正在克隆元数据仓库...")
        clone_successful = False
        for i, url in enumerate(urls_to_try):
            log_info(f"尝试克隆元数据仓库 (源 {i + 1}/{len(urls_to_try)})...")
            if run_command(["git", "clone", url, str(META_REPO_PATH)], ".", repo_name):
                clone_successful = True
                break
        if clone_successful and use_mirror:
            run_command(["git", "remote", "set-url", "origin", original_url], META_REPO_PATH, repo_name, retries=1)
        elif not clone_successful:
            log_warn("错误: 克隆元数据仓库失败！")
            sys.exit(1)

    log_info("元数据仓库同步完成。\n")


def collect_poc_data_from_local() -> dict:
    """从本地元数据仓库扫描并收集所有 CVE 数据。

    Returns:
        dict: {cve_id: [entry, ...]}，entry 保持原始字段，**不做任何修改**。
              同一个 entry 字典对象可能被多个 CVE 共享（一个 PoC 关联多个 CVE），
              因此后续代码绝不能修改 entry。clone_url 等辅助字段应在 main() 中
              独立存放在任务元组里。
    """
    log_info("--- 2. 从本地扫描和收集 CVE 数据 ---")
    cve_data = defaultdict(list)
    total_json, valid_poc, decode_errors = 0, 0, 0
    for root, _, files in os.walk(META_REPO_PATH):
        # 跳过 .git 目录
        if '.git' in Path(root).parts:
            continue
        for file in files:
            if not file.endswith(".json"):
                continue
            total_json += 1
            file_path = Path(root) / file
            cve_id = file_path.stem

            # 严格校验上游格式：文件名必须形如 CVE-YYYY-NNNN
            match = CVE_ID_PATTERN.match(cve_id)
            if not match:
                # 上游格式可能已变更，立即终止提示用户
                raise ValueError(
                    f"无法解析 CVE ID: '{cve_id}'（文件: {file_path}）。"
                    f"上游仓库格式可能已变更，请联系维护者。"
                )

            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    entries = json.load(f)
                if isinstance(entries, list):
                    for entry in entries:
                        if not isinstance(entry, dict):
                            continue
                        html_url = entry.get("html_url")
                        if not html_url:
                            continue
                        # 不修改 entry！保持原始字段与上游一致。
                        cve_data[cve_id].append(entry)
                        valid_poc += 1
            except json.JSONDecodeError:
                decode_errors += 1
                continue
    log_info(f"扫描总结: 共检查 {total_json} 个 .json 文件, 加载了 {valid_poc} 个 PoC 条目 "
             f"({len(cve_data)} 个 CVE), JSON 解析失败 {decode_errors} 个。\n")
    return cve_data


def sync_poc_repository(repo_url: str, local_path: Path, use_mirror: bool, randomize: bool) -> tuple[str, bool]:
    """健壮地同步单个 PoC 仓库：尝试更新，失败则删除重来。

    Returns:
        (repo_url, success)
    """
    repo_name = local_path.name

    # URL scheme 安全校验
    if not _validate_url(repo_url):
        log_warn(f"仓库 {repo_name} 跳过：URL 非 http(s) 协议 ({repo_url})")
        return repo_url, False

    original_url = repo_url
    urls_to_try = _build_urls_to_try(original_url, use_mirror, randomize)

    # 阶段 1: 如果是有效仓库，尝试强制更新
    if local_path.is_dir() and local_path.joinpath(".git").is_dir():
        update_successful = False
        try:
            for i, url in enumerate(urls_to_try):
                if not run_command(["git", "remote", "set-url", "origin", url], local_path, repo_name, retries=1):
                    continue  # 设置远程地址失败，尝试下一个镜像
                # 顺序：fetch → reset 到 origin/HEAD（失败则回退到主分支）→ clean
                # 注意：origin/HEAD 在空仓库或某些上游配置下不存在，故需回退策略。
                # fetch 是网络操作，走默认 GIT_RETRIES 重试；其余均为本地操作，retries=1 即可。
                if not run_command(["git", "fetch", "--all", "--prune"], local_path, repo_name):
                    continue
                # 优先 origin/HEAD，回退到 origin/main、origin/master
                reset_ok = False
                for ref in ("origin/HEAD", "origin/main", "origin/master"):
                    if run_command(["git", "reset", "--hard", ref], local_path, repo_name, retries=1):
                        reset_ok = True
                        break
                if not reset_ok:
                    # 没有任何远程分支引用：可能是空仓库或损坏的 .git。
                    # 空仓库：fetch 已成功，视为更新完成（重新 clone 也是同样结果）。
                    # 损坏 .git：阶段 2 会"删了重来"。
                    if not run_command(["git", "rev-parse", "HEAD"], local_path, repo_name, retries=1):
                        # 连 HEAD 都解析不出，说明 .git 损坏，跳到阶段 2
                        continue
                    reset_ok = True
                if reset_ok and run_command(["git", "clean", "-fdx"], local_path, repo_name, retries=1):
                    update_successful = True
                    break  # 更新成功，跳出循环
        finally:
            # 无论结果如何，都恢复原始 URL
            if use_mirror:
                if not run_command(["git", "remote", "set-url", "origin", original_url], local_path, repo_name, retries=1):
                    log_warn(f"仓库 {repo_name} 恢复 origin URL 失败，可能残留镜像地址。")

        if update_successful:
            return repo_url, True

        log_warn(f"仓库 {repo_name} 强制更新失败，将执行删除后重新克隆策略。")

    # 阶段 2: 如果不是有效仓库，或更新失败，则执行"删了重来"策略
    if local_path.exists():
        if not safe_rmtree(local_path):
            # 清理失败时无法继续克隆
            return repo_url, False
        # Windows 下 safe_rmtree 偶发地"报告成功但目录仍存在"（文件锁延迟、并发占用等），
        # 这里二次校验：如果目录还在，再删一次；仍不行就放弃，避免 git clone 报
        # "destination path already exists" 后还白白重试。
        if local_path.exists():
            if not safe_rmtree(local_path, retries=5, delay=2) or local_path.exists():
                log_warn(f"仓库 {repo_name} 跳过：目录残留无法清理 ({local_path})")
                return repo_url, False

    clone_successful = False
    for i, url in enumerate(urls_to_try):
        # clone 前先确保目录不存在（前一次失败的 clone 可能留下 .git 残留）
        if local_path.exists():
            safe_rmtree(local_path)
        if run_command(["git", "clone", "--depth", "1", url, str(local_path)], ".", repo_name):
            clone_successful = True
            break
        # clone 失败后若目录被部分创建，下次循环开头会再清理一次（双保险）

    if clone_successful and use_mirror:
        run_command(["git", "remote", "set-url", "origin", original_url], local_path, repo_name, retries=1)
    elif not clone_successful:
        log_warn(f"仓库 {repo_name} 克隆失败：已尝试所有镜像源及官方源。")

    return repo_url, clone_successful


def generate_summary_files(cve_id: str, entries: list, cve_dir: Path) -> None:
    """为单个 CVE 生成 metadata.json 和 README.md。

    entries 保持原始上游字段（在 collect 阶段未被修改），直接序列化即可。
    """
    cve_dir.mkdir(parents=True, exist_ok=True)

    # 直接序列化 entries，保持与上游格式一致（entry 在 collect 阶段已保持原始纯净）
    with open(cve_dir / "metadata.json", 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)

    main_desc = "No description available."
    if entries:
        first_entry = entries[0]
        # 上游 JSON 中 description 字段可能为 null（例如 CVE-1999-0016），
        # 故用 `or main_desc` 兜底，避免对 None 调用 .replace 而崩溃。
        main_desc = (first_entry.get('description') or main_desc).replace('\n', ' ').strip()

    readme_content = f"# {cve_id}\n\n**漏洞描述:** {main_desc}\n\n---\n\n## 相关 PoC 仓库 ({len(entries)} 个)\n\n"
    for i, entry in enumerate(entries, 1):
        # 上游字段可能为 null（如 pushed_at、description），统一做 None 安全处理
        html_url = entry.get('html_url') or '#'
        display_url = html_url.removesuffix('.git')
        pushed_at = entry.get('pushed_at') or 'N/A'
        last_update = pushed_at.split('T')[0] if 'T' in pushed_at else pushed_at
        readme_content += (
            f"### {i}. [{entry.get('full_name') or 'N/A'}]({display_url})\n\n"
            f"- **仓库描述:** {entry.get('description') or '作者未提供仓库描述。'}\n"
            f"- **Stars:** ⭐ {entry.get('stargazers_count', 0)}\n"
            f"- **Forks:** 🍴 {entry.get('forks_count', 0)}\n"
            f"- **最后更新:** {last_update}\n\n"
        )
    with open(cve_dir / "README.md", 'w', encoding='utf-8') as f:
        f.write(readme_content)


def main() -> None:
    """脚本主入口。"""
    args = parse_args()
    _setup_logging()

    log_info("--- PoC-in-GitHub 本地知识库同步工具 ---")
    if args.mirror:
        log_info(f"镜像加速功能: 已启用 ({len(MIRROR_HOSTS)} 个镜像源, "
                 f"{'随机顺序' if args.randomize_mirrors else '固定顺序'})")
    else:
        log_info("镜像加速功能: 已禁用（直连 GitHub 官方源）")
        # --randomize-mirrors 默认为 True，只有在用户显式传入且未开 --mirror 时才提醒
        if args.randomize_mirrors and '--randomize-mirrors' in sys.argv:
            log_warn("--randomize-mirrors 在未启用 --mirror 时无效果，将被忽略。")
    log_info("安全增强: 已启用 (禁用外部协议、凭据助手和全局 URL 重写)")

    sync_meta_repo(args.mirror, args.randomize_mirrors)
    all_cve_data = collect_poc_data_from_local()

    if not all_cve_data:
        log_warn("未收集到任何有效的 CVE 数据，任务提前结束。")
        return

    log_info("--- 3. 收集所有需要同步的仓库任务 ---")
    tasks = []
    for cve_id, entries in all_cve_data.items():
        try:
            year = cve_id.split('-')[1]
            cve_dir = LOCAL_POC_DIR / year / cve_id
            generate_summary_files(cve_id, entries, cve_dir)
            for entry in entries:
                full_name = entry.get("full_name")
                # 单个坏 entry 只跳过自己，不影响同 CVE 下其他 PoC
                if not full_name or '/' not in full_name:
                    log_warn(f"跳过无 full_name 或格式异常的条目（CVE: {cve_id}）")
                    continue
                repo_owner, repo_name = full_name.split('/', 1)
                safe_repo_name = sanitize_filename(f"{repo_owner}_{repo_name}")
                repo_path = cve_dir / "repositories" / safe_repo_name
                # 在 main 中独立计算 clone_url，不修改 entry（entry 可能被多个 CVE 共享）
                html_url = entry.get("html_url")
                if not html_url:
                    continue
                clone_url = html_url if html_url.endswith('.git') else html_url + '.git'
                tasks.append((clone_url, repo_path))
        except (IndexError, KeyError, TypeError) as e:
            log_warn(f"处理 CVE {cve_id} 时出错，已跳过: {e}")
            continue
    log_info(f"共收集到 {len(tasks)} 个仓库同步任务。\n")

    log_info(f"--- 4. 使用 {MAX_WORKERS} 个线程并发同步仓库 ---")
    total = len(tasks)
    success, failed = 0, 0
    if tasks:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_task = {executor.submit(sync_poc_repository, url, path,
                                              args.mirror, args.randomize_mirrors): url
                              for url, path in tasks}
            for i, future in enumerate(as_completed(future_to_task), 1):
                url = future_to_task[future]
                try:
                    _, ok = future.result()
                    if ok:
                        success += 1
                    else:
                        failed += 1
                        log_warn(f"失败: {url}")
                except Exception as e:
                    failed += 1
                    log_warn(f"任务异常 ({url}): {e}")
                # 进度显示（TTY 模式下覆盖刷新，非 TTY 走 logging）
                log_progress(i, total, Path(url).name)

    if IS_TTY:
        print()  # 进度行结束后换行
    log_info(f"同步完成: 成功 {success}/{total}, 失败 {failed}/{total}")
    log_info("--- ✅ 所有任务完成 ---")


if __name__ == "__main__":
    main()
