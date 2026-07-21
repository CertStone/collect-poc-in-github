# PoC-in-GitHub 本地知识库同步工具

## 1. 项目简介

本项目是一个自动化工具，旨在从 [PoC-in-GitHub](https://github.com/nomi-sec/PoC-in-GitHub) 中同步和整理与各类 CVE (Common Vulnerabilities and Exposures) 相关的公开 PoC (Proof-of-Concept) 代码，并构建一个结构化的本地知识库。推荐配合如 Anytxt、VS Code 等文本搜索软件使用。

## 2. 核心功能

- **自动化同步**: 一键执行，自动从元数据仓库 (`nomi-sec/PoC-in-GitHub`) 获取最新的 PoC 列表，并下载到本地。
- **结构化存储**: 所有 PoC 仓库按照 `年份/CVE-ID/仓库名` 的结构进行组织，清晰明了，易于检索。
- **元数据生成**: 为每个 CVE 自动生成 `README.md`（易读）和 `metadata.json`（易于程序处理）文件，包含漏洞描述、相关 PoC 仓库列表、Stars、Forks 等信息。
- **镜像加速与容错（可选）**: 对于中国大陆地区的网络情况，支持多个 GitHub 镜像源，支持随机切换和失败重试，有效应对网络限制和不稳定的情况（通过 `--mirror` 参数启用）。
- **并发下载**: 利用多线程并发克隆仓库，显著提升同步速度。
- **稳健的更新机制**: 采用"先更新，失败则删除重来"的策略，确保本地仓库与远程保持一致，并修复损坏的 Git 仓库。
- **失败汇总**: 运行结束时统计并输出成功/失败计数，便于关注出错的仓库。

## 3. 先决条件

在运行此工具之前，请确保您的系统已安装以下软件：

- **Python 3.10+**: 脚本运行环境。
- **Git**: 用于克隆和更新 GitHub 仓库。

## 4. 使用方法

项目仅包含一个脚本 `sync_pocs.py`，通过命令行参数控制是否启用镜像加速。

**执行同步（默认直连 GitHub 官方源）:**

```bash
python sync_pocs.py
```

**启用镜像加速（推荐中国大陆用户）:**

```bash
python sync_pocs.py --mirror
```

启用 `--mirror` 后，镜像源顺序**默认随机化**以在多线程并发时分散负载、避免触发单一镜像的限速。如需固定顺序（例如排查某镜像故障时），可显式关闭：

```bash
python sync_pocs.py --mirror --no-randomize-mirrors
```

注：即使开启了使用镜像源，GitHub官方源也会作为回退源存在。

**命令行参数一览:**

| 参数 | 说明 |
|------|------|
| `--mirror` | 启用镜像加速（默认关闭，直连 GitHub 官方源）。 |
| `--randomize-mirrors` / `--no-randomize-mirrors` | 是否随机化镜像源顺序做负载均衡（仅 `--mirror` 时生效；**默认开启**，可用 `--no-randomize-mirrors` 关闭）。 |

**自定义配置:**

您可以直接编辑 `sync_pocs.py` 文件顶部的配置区，以满足您的需求：

- `MIRROR_HOSTS`: 添加或修改 GitHub 镜像地址。
- `MAX_WORKERS`: 调整并发下载的线程数，根据您的网络和机器性能设置。
- `GIT_RETRIES` / `GIT_RETRY_DELAY`: 调整 git 命令的重试次数与间隔。

## 5. 目录结构

同步完成后，项目将生成以下目录结构：

```
.
├── PoC_DB/                      # 本地 PoC 数据库
│   ├── 2023/
│   │   └── CVE-2023-XXXX/
│   │       ├── repositories/      # 存放所有相关的 PoC 仓库
│   │       │   └── author_poc-repo/
│   │       ├── metadata.json      # CVE 相关的元数据（与上游格式一致）
│   │       └── README.md          # CVE 描述和 PoC 列表
│   └── ...
├── PoC-in-GitHub_meta/          # PoC 元数据仓库的本地克隆（按年份组织）
│   ├── 1999/
│   │   └── CVE-1999-XXXX.json
│   └── ...
├── logs/                        # 同步日志（自动保留最近 3 份）
│   └── sync_YYYYMMDD_HHMMSS.log
├── sync_pocs.py                 # 同步脚本
└── README.md                    # 本说明文档
```

## 6. 日志

每次运行会在 `logs/` 目录下生成一份按时间戳命名的日志文件（如 `sync_20240101_120000.log`），同时输出到控制台。日志目录最多保留最近 **3 份**，超出会自动清理最旧的文件。`logs/` 已加入 `.gitignore`。

## 7. ⚠️ 安全提示

**PoC 代码可能包含恶意内容！运行前请检查！**

本项目同步的所有代码均来自互联网上的公开仓库，其安全性未经审核。在本地运行或调试任何 PoC 之前，请务必在隔离环境（如虚拟机、Docker 容器）中进行，并仔细审查代码，以防对您的系统造成损害。

脚本已默认启用 Git 安全增强配置：
- 禁用 `ext::` 外部协议（防止 `protocol.ext.allow` 滥用）。
- 禁用 `file://` 协议自动加载（`protocol.file.allow=user`）。
- 禁用凭据助手（`credential.helper=`），避免意外发送本地凭据。
- 仅允许 `http(s)` URL，非 `http(s)` 协议会跳过。

**请勿在生产环境或任何重要设备上直接运行未经验证的 PoC 代码。**

## 8. 其他声明

特别感谢 Gemini-2.5-Pro 和 GLM-5.2 对代码编写的支持。

项目采用 MIT 许可证开源。
