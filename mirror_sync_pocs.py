# sync_pocs_v9.py

import os
import json
import subprocess
import time
import shutil
import re
import random
from pathlib import Path
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

# --- 配置区 ---
META_REPO_URL = "https://github.com/nomi-sec/PoC-in-GitHub.git"
META_REPO_PATH = Path("./PoC-in-GitHub_meta")
LOCAL_POC_DIR = Path("./PoC_DB")
GIT_RETRIES = 2 # 对于每个镜像源，尝试2次
GIT_RETRY_DELAY = 8 # 重试间隔（秒）
MAX_WORKERS = 15 # 并发线程数

# --- 镜像加速配置 ---
USE_MIRROR = True # 是否启用镜像加速
# 常用的GitHub镜像源列表（可根据需要添加或修改）
MIRROR_HOSTS = [
    "https://ghfast.top/",
    #"https://ghproxy.net/",
    #"https://wget.la/",
    "https://hk.gh-proxy.com/"
]
RANDOMIZE_MIRRORS = True # 是否随机化镜像源顺序，即简单的负载均衡

# --- 安全配置 ---
GIT_SECURITY_OPTS = ['-c', 'protocol.ext.allow=never', '-c', 'credential.helper=']

# --- 核心功能函数 ---

def sanitize_filename(name: str) -> str:
    """净化文件名，移除Windows和Linux下不允许的字符及末尾的点和空格。"""
    name = name.strip(' .')
    return re.sub(r'[<>:"/\\|?*]', '', name)

def run_command(command: list[str], cwd: Path | str, repo_name: str, retries: int = GIT_RETRIES, delay: int = GIT_RETRY_DELAY) -> bool:
    """为单个命令执行重试逻辑。"""
    for attempt in range(retries):
        try:
            # 将安全参数插入到 'git' 命令之后
            git_index = command.index("git")
            final_command = command[:git_index+1] + GIT_SECURITY_OPTS + command[git_index+1:]
            
            subprocess.run(
                final_command, cwd=cwd, check=True, capture_output=True, text=True,
                encoding='utf-8', errors='ignore'
            )
            return True
        except (FileNotFoundError, ValueError):
            print(f"\n[!] 'git' 命令处理错误。请确保 Git 已安装。")
            return False
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr.strip()
            if attempt < retries - 1:
                print(f"\n[!] 仓库 {repo_name} 操作失败 (尝试 {attempt + 1}/{retries})。将在 {delay} 秒后重试... 错误: {error_msg}")
                time.sleep(delay)
            else:
                # 在上层函数中报告最终错误
                return False
    return False

def sync_meta_repo():
    """克隆或更新元数据仓库，使用正确的故障切换逻辑。"""
    print(f"--- 1. 同步元数据仓库: {META_REPO_URL} ---")
    repo_name = "meta-repository"
    original_url = META_REPO_URL
    urls_to_try = [original_url]
    if USE_MIRROR:
        mirrors = MIRROR_HOSTS[:]
        if RANDOMIZE_MIRRORS: random.shuffle(mirrors)
        urls_to_try = [host + original_url for host in mirrors] + [original_url]

    # 更新逻辑
    if META_REPO_PATH.is_dir() and META_REPO_PATH.joinpath(".git").is_dir():
        print(f"[*] 元数据仓库已存在，正在拉取更新...")
        update_successful = False
        try:
            for i, url in enumerate(urls_to_try):
                print(f"\r[*] 尝试更新元数据仓库 (源 {i+1}/{len(urls_to_try)})...", end="")
                if run_command(["git", "remote", "set-url", "origin", url], META_REPO_PATH, repo_name, retries=1):
                    if run_command(["git", "pull"], META_REPO_PATH, repo_name):
                        update_successful = True
                        break
        finally:
            if USE_MIRROR:
                run_command(["git", "remote", "set-url", "origin", original_url], META_REPO_PATH, repo_name, retries=1)
        if not update_successful:
             print(f"\n[!] 警告: 更新元数据仓库失败。")
    # 克隆逻辑
    else:
        print(f"[*] 正在克隆元数据仓库...")
        clone_successful = False
        for i, url in enumerate(urls_to_try):
             print(f"\r[*] 尝试克隆元数据仓库 (源 {i+1}/{len(urls_to_try)})...", end="")
             if run_command(["git", "clone", url, str(META_REPO_PATH)], ".", repo_name):
                 clone_successful = True
                 break
        if clone_successful and USE_MIRROR:
            run_command(["git", "remote", "set-url", "origin", original_url], META_REPO_PATH, repo_name, retries=1)
        elif not clone_successful:
             print(f"\n[!] 错误: 克隆元数据仓库失败！")
             exit(1)

    print(f"\n[*] 元数据仓库同步完成。\n")


def collect_poc_data_from_local() -> dict:
    # ... (此函数无需修改)
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
                with open(file_path, 'r', encoding='utf-8') as f: entries = json.load(f)
                if isinstance(entries, list):
                    for entry in entries:
                        if isinstance(entry, dict) and entry.get("html_url"):
                            if not entry['html_url'].endswith('.git'): entry['html_url'] += '.git'
                            entry['cve_id'] = cve_id
                            cve_data[cve_id].append(entry)
                            valid_poc += 1
            except json.JSONDecodeError: continue
    print(f"[*] 扫描总结: 共检查 {total_json} 个.json文件, 加载了 {valid_poc} 个PoC条目 ({len(cve_data)}个CVE)。\n")
    return cve_data

def sync_poc_repository(repo_url: str, local_path: Path) -> str:
    """健壮地同步单个PoC仓库，使用正确的镜像切换和强制更新。"""
    repo_name = local_path.name
    original_url = repo_url
    urls_to_try = [original_url]
    if USE_MIRROR:
        mirrors = MIRROR_HOSTS[:]
        if RANDOMIZE_MIRRORS: random.shuffle(mirrors)
        urls_to_try = [host + original_url for host in mirrors] + [original_url]

    # 阶段1: 如果是有效仓库，尝试强制更新
    if local_path.is_dir() and local_path.joinpath(".git").is_dir():
        update_successful = False
        try:
            for i, url in enumerate(urls_to_try):
                if not run_command(["git", "remote", "set-url", "origin", url], local_path, repo_name, retries=1):
                    continue # 设置远程地址失败，尝试下一个镜像
                
                update_commands = [
                    ["git", "fetch", "--all", "--prune"],
                    ["git", "reset", "--hard", "origin/HEAD"],
                    ["git", "clean", "-fdx"]
                ]
                if all(run_command(cmd, local_path, repo_name, retries=1) for cmd in update_commands):
                    update_successful = True
                    break # 更新成功，跳出循环
        finally:
            if USE_MIRROR: # 无论结果如何，都恢复原始URL
                run_command(["git", "remote", "set-url", "origin", original_url], local_path, repo_name, retries=1)
        
        if update_successful:
            return repo_url

        print(f"\n[!] 仓库 {repo_name} 强制更新失败，将执行删除后重新克隆策略。")
    
    # 阶段2: 如果不是有效仓库，或更新失败，则执行“删了重来”策略
    if local_path.exists():
        try:
            shutil.rmtree(local_path)
        except OSError as e:
            print(f"\n[!] 清理目录 {local_path} 失败: {e}。跳过此仓库。")
            return repo_url

    clone_successful = False
    for i, url in enumerate(urls_to_try):
        if run_command(["git", "clone", "--depth", "1", url, str(local_path)], ".", repo_name):
            clone_successful = True
            break
            
    if clone_successful and USE_MIRROR:
        run_command(["git", "remote", "set-url", "origin", original_url], local_path, repo_name, retries=1)
    elif not clone_successful:
        print(f"\n[!] 仓库 {repo_name} 克隆失败：已尝试所有镜像源及官方源。")
            
    return repo_url


def generate_summary_files(cve_id: str, entries: list, cve_dir: Path):
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
        display_url = entry.get('html_url', '#').removesuffix('.git')
        readme_content += (
            f"### {i}. [{entry.get('full_name', 'N/A')}]({display_url})\n\n"
            f"- **仓库描述:** {entry.get('description') or '作者未提供仓库描述。'}\n"
            f"- **Stars:** ⭐ {entry.get('stargazers_count', 0)}\n"
            f"- **Forks:** 🍴 {entry.get('forks_count', 0)}\n"
            f"- **最后更新:** {entry.get('pushed_at', 'N/A').split('T')[0]}\n\n"
        )
    with open(cve_dir / "README.md", 'w', encoding='utf-8') as f:
        f.write(readme_content)

def main():
    """脚本主入口。"""
    print(f"--- PoC-in-GitHub 本地知识库同步工具 (V9 - 终极健壮版) ---")
    if USE_MIRROR:
        print(f"[*] 镜像加速功能: 已启用 ({len(MIRROR_HOSTS)}个镜像源, {'随机顺序' if RANDOMIZE_MIRRORS else '固定顺序'})")
    else:
        print(f"[*] 镜像加速功能: 已禁用")
    print(f"[*] 安全增强: 已启用 (禁用外部协议和凭据助手)")
    
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
                url = future.result().removesuffix('.git')
                print(f"\r[*] 同步进度: {i}/{len(tasks)} ({Path(url).name})\x1b[K", end='')
    
    print(f"\n[*] 所有仓库同步完成。\n")
    print("--- ✅ 所有任务完成 ---")

if __name__ == "__main__":
    main()