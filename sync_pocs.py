# sync_pocs_v6.py

import os
import json
import subprocess
import time
import shutil
import re
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置区 ---
META_REPO_URL = "https://github.com/nomi-sec/PoC-in-GitHub.git"
META_REPO_PATH = Path("./PoC-in-GitHub_meta")
LOCAL_POC_DIR = Path("./PoC_DB")
GIT_RETRIES = 3 # 对于每个仓库操作，尝试3次
GIT_RETRY_DELAY = 10 # 重试间隔（秒）
MAX_WORKERS = 10 # 并发线程数

# --- 核心功能函数 ---

def sanitize_filename(name: str) -> str:
    """净化文件名，移除Windows和Linux下不允许的字符及末尾的点和空格。"""
    # 移除末尾的点和空格
    name = name.strip(' .')
    # 移除非法字符，替换为空字符串
    return re.sub(r'[<>:"/\\|?*]', '', name)

def run_command_with_retry(command: list[str], cwd: Path | str, repo_name: str, retries: int = GIT_RETRIES, delay: int = GIT_RETRY_DELAY) -> bool:
    """带重试机制和更清晰日志的命令执行函数。"""
    for attempt in range(retries):
        try:
            subprocess.run(
                command, cwd=cwd, check=True, capture_output=True, text=True,
                encoding='utf-8', errors='ignore'
            )
            return True
        except FileNotFoundError:
            print(f"\n[!] 命令 '{command[0]}' 未找到。请确保 Git 已安装并在 PATH 中。")
            return False
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip()
            if attempt < retries - 1:
                print(f"\n[!] 仓库 {repo_name} 操作失败 (尝试 {attempt + 1}/{retries})。将在 {delay} 秒后重试... 错误: {error_msg}")
                time.sleep(delay)
            else:
                print(f"\n[!] 仓库 {repo_name} 操作失败，已达最大重试次数 ({retries}次)。最终错误: {error_msg}")
                return False
    return False

def sync_meta_repo():
    """克隆或更新元数据仓库。"""
    print(f"--- 1. 同步元数据仓库: {META_REPO_URL} ---")
    if META_REPO_PATH.is_dir() and META_REPO_PATH.joinpath(".git").is_dir():
        print("[*] 元数据仓库已存在，正在拉取更新...")
        run_command_with_retry(["git", "pull"], META_REPO_PATH, "meta-repository")
    else:
        print("[*] 正在克隆元数据仓库...")
        run_command_with_retry(["git", "clone", META_REPO_URL, str(META_REPO_PATH)], ".", "meta-repository")
    print("[*] 元数据仓库同步完成。\n")

def collect_poc_data_from_local() -> dict:
    """从本地元数据仓库扫描并收集所有 CVE 数据。"""
    print("--- 2. 从本地扫描和收集 CVE 数据 ---")
    cve_data = defaultdict(list)
    total_json, valid_poc = 0, 0
    for root, _, files in os.walk(META_REPO_PATH):
        for file in files:
            if not file.endswith(".json"): continue
            total_json += 1
            file_path = Path(root) / file
            cve_id = file_path.stem
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    entries = json.load(f)
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict) and entry.get("html_url"):
                            entry['cve_id'] = cve_id
                            cve_data[cve_id].append(entry)
                            valid_poc += 1
            except json.JSONDecodeError: continue
    print(f"[*] 扫描总结: 共检查 {total_json} 个.json文件, 加载了 {valid_poc} 个PoC条目 ({len(cve_data)}个CVE)。\n")
    return cve_data

def sync_poc_repository(repo_url: str, local_path: Path) -> str:
    """健壮地同步单个PoC仓库：尝试更新，失败则删除重来。"""
    repo_name = local_path.name
    
    # 阶段1: 如果是有效仓库，尝试强制更新
    if local_path.is_dir() and local_path.joinpath(".git").is_dir():
        update_commands = [
            ["git", "fetch", "--all", "--prune"],
            ["git", "reset", "--hard", "origin/HEAD"],
            ["git", "clean", "-fdx"]
        ]
        update_successful = all(
            run_command_with_retry(cmd, local_path, repo_name, retries=1) for cmd in update_commands
        )
        if update_successful:
            return repo_url # 更新成功，任务完成

        print(f"\n[!] 仓库 {repo_name} 强制更新失败，将执行删除后重新克隆策略。")
    
    # 阶段2: 如果不是有效仓库，或更新失败，则执行“删了重来”策略
    if local_path.exists():
        try:
            shutil.rmtree(local_path)
        except OSError as e:
            print(f"\n[!] 清理目录 {local_path} 失败: {e}。跳过此仓库。")
            return repo_url

    # 执行浅克隆
    clone_command = ["git", "clone", "--depth", "1", repo_url, str(local_path)]
    run_command_with_retry(clone_command, ".", repo_name)
        
    return repo_url

def generate_summary_files(cve_id: str, entries: list, cve_dir: Path):
    """为单个CVE生成元数据和描述文件。"""
    # ... (此函数无需修改)
    cve_dir.mkdir(parents=True, exist_ok=True)
    with open(cve_dir / "metadata.json", 'w', encoding='utf-8') as f:
        json.dump(entries, f, indent=4, ensure_ascii=False)
    
    main_desc = "No description available."
    if entries:
        first_entry = entries[0]
        main_desc = (first_entry.get('summary') or first_entry.get('repo_description') 
                     or first_entry.get('description', main_desc)).replace('\n', ' ').strip()

    readme_content = f"# {cve_id}\n\n**漏洞描述:** {main_desc}\n\n---\n\n## 相关 PoC 仓库 ({len(entries)} 个)\n\n"
    for i, entry in enumerate(entries, 1):
        readme_content += (
            f"### {i}. [{entry.get('full_name', 'N/A')}]({entry.get('html_url', '#')})\n\n"
            f"- **仓库描述:** {entry.get('description') or '作者未提供仓库描述。'}\n"
            f"- **Stars:** ⭐ {entry.get('stargazers_count', 0)}\n"
            f"- **Forks:** 🍴 {entry.get('forks_count', 0)}\n"
            f"- **最后更新:** {entry.get('pushed_at', 'N/A').split('T')[0]}\n\n"
        )
    with open(cve_dir / "README.md", 'w', encoding='utf-8') as f:
        f.write(readme_content)

def main():
    """脚本主入口。"""
    print("--- PoC-in-GitHub 本地知识库同步工具 (V6 - 健壮版) ---")
    
    sync_meta_repo()
    all_cve_data = collect_poc_data_from_local()

    if not all_cve_data:
        print("[!] 未收集到任何有效的 CVE 数据，任务提前结束。")
        return

    print("--- 3. 收集所有需要同步的仓库任务 ---")
    tasks = []
    for cve_id, entries in all_cve_data.items():
        try:
            year = cve_id.split('-')[1]
            cve_dir = LOCAL_POC_DIR / year / cve_id
            generate_summary_files(cve_id, entries, cve_dir)
            
            for entry in entries:
                repo_owner, repo_name = entry.get("full_name").split('/')
                # **净化文件名**
                safe_repo_name = sanitize_filename(f"{repo_owner}_{repo_name}")
                repo_path = cve_dir / "repositories" / safe_repo_name
                tasks.append((entry.get("html_url"), repo_path))
        except (AttributeError, IndexError, KeyError, TypeError):
            continue
    print(f"[*] 共收集到 {len(tasks)} 个仓库同步任务。\n")

    print(f"--- 4. 使用 {MAX_WORKERS} 个线程并发同步仓库 ---")
    if tasks:
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_task = {executor.submit(sync_poc_repository, url, path): url for url, path in tasks}
            for i, future in enumerate(as_completed(future_to_task), 1):
                url = future.result()
                # 使用 \r 和 ANSI escape code \x1b[K 来确保行被完全清除
                print(f"\r[*] 同步进度: {i}/{len(tasks)} ({url})\x1b[K", end='')
    
    print(f"\n[*] 所有仓库同步完成。\n")
    print("--- ✅ 所有任务完成 ---")

if __name__ == "__main__":
    main()