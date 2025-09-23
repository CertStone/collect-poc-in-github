# PoC-in-GitHub 本地知识库同步工具

## 1. 项目简介

本项目是一个自动化工具，旨在从 [PoC-in-Github](https://github.com/nomi-sec/PoC-in-GitHub) 中同步和整理与各类 CVE (Common Vulnerabilities and Exposures) 相关的公开 PoC (Proof-of-Concept) 代码，并构建一个结构化的本地知识库。推荐配合如 Anytxt、VS Code等文本搜索软件使用。

## 2. 核心功能

- **自动化同步**: 一键执行，自动从元数据仓库 (`nomi-sec/PoC-in-GitHub`) 获取最新的 PoC 列表，并下载到本地。
- **结构化存储**: 所有 PoC 仓库按照 `年份/CVE-ID/仓库名` 的结构进行组织，清晰明了，易于检索。
- **元数据生成**: 为每个 CVE 自动生成 `README.md`(易读) 和 `metadata.json` (易于程序处理)文件，包含漏洞描述、相关 PoC 仓库列表、Stars、Forks 等信息。
- **镜像加速与容错**: 对于中国大陆地区的网络情况，支持多个 GitHub 镜像源，支持随机切换和失败重试，有效应对网络限制和不稳定的情况 (`mirror_sync_pocs.py`)。
- **并发下载**: 利用多线程并发克隆仓库，显著提升同步速度。
- **稳健的更新机制**: 采用“先更新，失败则删除重来”的策略，确保本地仓库与远程保持一致，并修复损坏的 Git 仓库。

## 3. 先决条件

在运行此工具之前，请确保您的系统已安装以下软件：

- **Python 3**: 脚本运行环境。
- **Git**: 用于克隆和更新 GitHub 仓库。

## 4. 使用方法

项目包含两个脚本：

1.  `sync_pocs.py`: 基础版本，直接从 GitHub 官方源同步数据。
2.  `mirror_sync_pocs.py`: **推荐使用**的增强版，支持镜像加速、随机化和更强的容错机制。

**执行同步:**

打开终端，直接运行推荐的脚本即可：

```bash
python mirror_sync_pocs.py
```

**自定义配置:**

您可以直接编辑 `mirror_sync_pocs.py` 文件顶部的配置区，以满足您的需求：

- `MIRROR_HOSTS`: 添加或修改 GitHub 镜像地址。
- `MAX_WORKERS`: 调整并发下载的线程数，根据您的网络和机器性能设置。
- `USE_MIRROR`: 是否启用镜像加速功能。

## 5. 目录结构

同步完成后，项目将生成以下目录结构：

```
.
├── PoC_DB/                      # 本地 PoC 数据库
│   ├── 2023/
│   │   └── CVE-2023-XXXX/
│   │       ├── repositories/      # 存放所有相关的 PoC 仓库
│   │       │   └── author_poc-repo/
│   │       ├── metadata.json      # CVE 相关的元数据
│   │       └── README.md          # CVE 描述和 PoC 列表
│   └── ...
├── PoC-in-GitHub_meta/          # PoC 元数据仓库的本地克隆
├── mirror_sync_pocs.py          # 增强版同步脚本 (推荐)
├── sync_pocs.py                 # 基础版同步脚本
└── README.md                    # 本说明文档
```

## 6. ⚠️ 安全提示

**PoC 代码可能包含恶意内容！**

本项目同步的所有代码均来自互联网上的公开仓库，其安全性未经审核。在本地运行或调试任何 PoC 之前，请务必在隔离环境（如虚拟机、Docker 容器）中进行，并仔细审查代码，以防对您的系统造成损害。

**请勿在生产环境或任何重要设备上直接运行未经验证的 PoC 代码。**

## 7. 其他声明

特别感谢 Gemini-2.5-Pro 对代码编写的支持。

项目采用MIT许可证开源。
