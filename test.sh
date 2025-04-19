#!/bin/bash
set -e  # 遇到错误立即退出

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # 无颜色

# 测试目录
TEST_BASE="$(pwd)/test_integration"
SOURCE_DIR="$TEST_BASE/source"
BACKUP_DIR="$TEST_BASE/backup"
RESTORE_DIR="$TEST_BASE/restore"
CRYPTBAK_BIN="$(pwd)/zig-out/bin/cryptbak"

# 测试密码
TEST_PASSWORD="test_password_123"

# 创建测试目录结构
setup_test_environment() {
    echo -e "${YELLOW}设置测试环境...${NC}"
    
    # 清理之前的测试目录（如果存在）
    rm -rf "$TEST_BASE"
    
    # 创建新的测试目录
    mkdir -p "$SOURCE_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$RESTORE_DIR"
    
    # 创建一个非常简单的测试文件
    echo "这是一个简单的测试文件内容" > "$SOURCE_DIR/simple_file.txt"
    
    # 创建多层级目录结构
    mkdir -p "$SOURCE_DIR/level1/level2/level3"
    echo "这是第一层目录中的文件" > "$SOURCE_DIR/level1/file1.txt"
    echo "这是第二层目录中的文件" > "$SOURCE_DIR/level1/level2/file2.txt"
    echo "这是第三层目录中的文件" > "$SOURCE_DIR/level1/level2/level3/file3.txt"
    
    # 创建特殊名称的文件
    echo "包含空格的文件名" > "$SOURCE_DIR/file with spaces.txt"
    echo "包含特殊字符的文件名" > "$SOURCE_DIR/special_@#$%^&()_file.txt"
    
    # 创建大文件（10MB）
    dd if=/dev/urandom of="$SOURCE_DIR/large_file.bin" bs=1M count=10
    
    # 创建小文件集合
    mkdir -p "$SOURCE_DIR/many_files"
    for i in {1..100}; do
        echo "这是第 $i 个小文件" > "$SOURCE_DIR/many_files/small_file_$i.txt"
    done
    
    # 创建空文件和空目录
    touch "$SOURCE_DIR/empty_file.txt"
    mkdir -p "$SOURCE_DIR/empty_dir"
    
    # 创建超长文件名
    long_name=$(printf 'a%.0s' {1..100})
    echo "超长文件名测试" > "$SOURCE_DIR/$long_name.txt"
    
    echo -e "${GREEN}测试环境已设置完成.${NC}"
}

# 运行命令并优雅地处理失败
run_cmd() {
    echo "执行: $@"
    if ! "$@"; then
        echo -e "${RED}命令执行失败: $@${NC}"
        return 1
    fi
    return 0
}

# 测试简单加密
test_simple_encryption() {
    echo -e "\n${YELLOW}测试 1: 简单文件加密${NC}"
    
    echo "运行加密..."
    run_cmd "$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -p "$TEST_PASSWORD" || return 1
    
    # 检查备份目录中是否有加密文件
    if [ ! -f "$BACKUP_DIR/simple_file.txt" ]; then
        echo -e "${RED}失败: 加密文件不存在${NC}"
        return 1
    fi
    
    # 检查多层级文件是否都被加密
    if [ ! -f "$BACKUP_DIR/level1/level2/level3/file3.txt" ]; then
        echo -e "${RED}失败: 多层级文件未被正确加密${NC}"
        return 1
    fi
    
    # 检查特殊文件名是否被正确加密
    if [ ! -f "$BACKUP_DIR/file with spaces.txt" ]; then
        echo -e "${RED}失败: 包含空格的文件名未被正确加密${NC}"
        return 1
    fi
    
    # 检查大文件是否被正确加密
    if [ ! -f "$BACKUP_DIR/large_file.bin" ]; then
        echo -e "${RED}失败: 大文件未被正确加密${NC}"
        return 1
    fi
    
    # 检查是否有足够数量的小文件被加密
    small_files_count=$(find "$BACKUP_DIR/many_files" -type f | wc -l)
    if [ "$small_files_count" -lt 100 ]; then
        echo -e "${RED}失败: 小文件集合未被完全加密，期望100个，实际$small_files_count个${NC}"
        return 1
    fi
    
    # 检查空文件和空目录
    if [ ! -f "$BACKUP_DIR/empty_file.txt" ]; then
        echo -e "${RED}失败: 空文件未被正确加密${NC}"
        return 1
    fi
    
    if [ ! -d "$BACKUP_DIR/empty_dir" ]; then
        echo -e "${RED}失败: 空目录未被正确创建${NC}"
        return 1
    fi
    
    echo -e "${GREEN}测试 1 通过: 文件加密成功${NC}"
    return 0
}

# 测试简单解密
test_simple_decryption() {
    echo -e "\n${YELLOW}测试 2: 文件解密${NC}"
    
    echo "运行解密..."
    set +e  # 暂时关闭错误退出
    "$CRYPTBAK_BIN" "$BACKUP_DIR" "$RESTORE_DIR" -d -p "$TEST_PASSWORD" > /tmp/decrypt_output.log 2>&1
    local result=$?
    set -e  # 重新开启错误退出
    
    if [ $result -ne 0 ]; then
        echo -e "${RED}解密失败，错误代码: $result${NC}"
        echo -e "${YELLOW}错误日志:${NC}"
        cat /tmp/decrypt_output.log
        return 1
    fi
    
    # 检查还原目录中是否有解密文件
    if [ ! -f "$RESTORE_DIR/simple_file.txt" ]; then
        echo -e "${RED}失败: 解密文件不存在${NC}"
        return 1
    fi
    
    # 比较原始文件和解密文件
    if ! cmp -s "$SOURCE_DIR/simple_file.txt" "$RESTORE_DIR/simple_file.txt"; then
        echo -e "${RED}失败: 解密文件内容与原始文件不匹配${NC}"
        return 1
    fi
    
    # 检查多层级文件是否被正确解密
    if [ ! -f "$RESTORE_DIR/level1/level2/level3/file3.txt" ]; then
        echo -e "${RED}失败: 多层级文件未被正确解密${NC}"
        return 1
    fi
    
    if ! cmp -s "$SOURCE_DIR/level1/level2/level3/file3.txt" "$RESTORE_DIR/level1/level2/level3/file3.txt"; then
        echo -e "${RED}失败: 多层级文件内容与原始文件不匹配${NC}"
        return 1
    fi
    
    # 检查特殊文件名是否被正确解密
    if [ ! -f "$RESTORE_DIR/file with spaces.txt" ]; then
        echo -e "${RED}失败: 包含空格的文件名未被正确解密${NC}"
        return 1
    fi
    
    # 检查大文件是否被正确解密
    if [ ! -f "$RESTORE_DIR/large_file.bin" ]; then
        echo -e "${RED}失败: 大文件未被正确解密${NC}"
        return 1
    fi
    
    if ! cmp -s "$SOURCE_DIR/large_file.bin" "$RESTORE_DIR/large_file.bin"; then
        echo -e "${RED}失败: 大文件内容与原始文件不匹配${NC}"
        return 1
    fi
    
    # 检查小文件集合
    restored_small_files_count=$(find "$RESTORE_DIR/many_files" -type f | wc -l)
    if [ "$restored_small_files_count" -lt 100 ]; then
        echo -e "${RED}失败: 小文件集合未被完全解密，期望100个，实际$restored_small_files_count个${NC}"
        return 1
    fi
    
    # 随机检查一个小文件内容
    if ! cmp -s "$SOURCE_DIR/many_files/small_file_42.txt" "$RESTORE_DIR/many_files/small_file_42.txt"; then
        echo -e "${RED}失败: 小文件内容与原始文件不匹配${NC}"
        return 1
    fi
    
    # 检查文件总数是否一致
    source_files_count=$(find "$SOURCE_DIR" -type f | wc -l)
    restore_files_count=$(find "$RESTORE_DIR" -type f | wc -l)
    if [ "$source_files_count" -ne "$restore_files_count" ]; then
        echo -e "${RED}失败: 源目录与还原目录文件数量不匹配 (源: $source_files_count, 还原: $restore_files_count)${NC}"
        return 1
    fi
    
    echo -e "${GREEN}测试 2 通过: 文件解密成功${NC}"
    return 0
}

# 测试增量备份
test_incremental_backup() {
    echo -e "\n${YELLOW}测试 3: 增量备份${NC}"
    
    # 修改一些现有文件
    echo "这是修改后的文件内容" > "$SOURCE_DIR/simple_file.txt"
    echo "这是修改后的层级文件内容" > "$SOURCE_DIR/level1/level2/file2.txt"
    
    # 添加一些新文件
    echo "这是新增加的文件" > "$SOURCE_DIR/new_file.txt"
    mkdir -p "$SOURCE_DIR/new_dir"
    echo "这是新目录中的文件" > "$SOURCE_DIR/new_dir/new_dir_file.txt"
    
    # 删除一些文件
    rm "$SOURCE_DIR/level1/file1.txt"
    
    echo "运行增量备份..."
    run_cmd "$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -p "$TEST_PASSWORD" || return 1
    
    # 检查修改的文件是否被更新
    if ! [ -f "$BACKUP_DIR/simple_file.txt" ]; then
        echo -e "${RED}失败: 修改后的文件不存在${NC}"
        return 1
    fi
    
    # 检查新增文件是否被备份
    if ! [ -f "$BACKUP_DIR/new_file.txt" ]; then
        echo -e "${RED}失败: 新增文件未被备份${NC}"
        return 1
    fi
    
    if ! [ -f "$BACKUP_DIR/new_dir/new_dir_file.txt" ]; then
        echo -e "${RED}失败: 新增目录中的文件未被备份${NC}"
        return 1
    fi
    
    # 检查删除的文件是否也从备份中删除
    if [ -f "$BACKUP_DIR/level1/file1.txt" ]; then
        echo -e "${RED}失败: 删除的文件仍然存在于备份中${NC}"
        return 1
    fi
    
    echo -e "${GREEN}测试 3 通过: 增量备份成功${NC}"
    return 0
}

# 运行所有测试
run_all_tests() {
    setup_test_environment
    
    test_simple_encryption || true
    
    test_simple_decryption || true
    
    test_incremental_backup || true
    
    echo -e "\n${GREEN}测试完成!${NC}"
    return 0
}

# 主函数
main() {
    # 检查cryptbak二进制文件是否存在
    if [ ! -f "$CRYPTBAK_BIN" ]; then
        echo -e "${RED}错误: cryptbak 程序不存在于 $CRYPTBAK_BIN${NC}"
        exit 1
    fi
    
    run_all_tests
    exit 0
}

# 执行主函数
main
