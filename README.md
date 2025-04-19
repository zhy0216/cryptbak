# CryptBak

基于Zig的增量加密备份工具。该工具可以加密源文件夹中的文件并备份到目标文件夹，支持增量备份功能，只对新增或修改的文件进行加密处理。

build with windsurf.

## 功能特点

- 文件夹加密和解密
- 支持增量备份（只处理变化的文件）
- 高效的差异化处理
- 密码保护

## 安装

首先需要安装Zig编程语言：

- macOS (使用 Homebrew): `brew install zig`
- 或者从 [Zig官网](https://ziglang.org/download/) 下载最新版本

然后编译项目：

```bash
git clone https://github.com/zhy0216/cryptbak.git
cd cryptbak
zig build
```

编译后的可执行文件将位于 `./zig-out/bin/cryptbak`。

## 使用方法

### 加密备份

```bash
./cryptbak source_folder output_folder -p password
```

### 解密还原

```bash
./cryptbak source_folder output_folder -d -p password
```

## 工作原理

1. **加密模式**：
   - 扫描源文件夹中的所有文件
   - 计算每个文件的哈希值
   - 与上次备份的元数据进行比较（如果存在）
   - 只加密新增或修改过的文件
   - 从备份中删除源文件夹中已不存在的文件
   - 更新元数据

2. **解密模式**：
   - 读取加密文件夹中的元数据
   - 解密所有文件到目标文件夹

3. **元数据**：
   - 存储在输出文件夹的`.cryptbak.meta`文件中
   - 包含每个文件的路径、修改时间、大小和哈希值
   - 元数据本身也会被加密

## 安全说明

- 使用ChaCha20IETF流加密算法
- 密钥从密码派生，使用PBKDF2算法
- 每个文件使用唯一的随机nonce进行加密
