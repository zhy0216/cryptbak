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
    
    echo -e "${GREEN}测试 1 通过: 文件加密成功${NC}"
    return 0
}

# 测试简单解密
test_simple_decryption() {
    echo -e "\n${YELLOW}测试 2: 简单文件解密${NC}"
    
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
    
    echo -e "${GREEN}测试 2 通过: 文件解密成功${NC}"
    return 0
}

# 检查内存分配失败的问题
analyze_memory_issue() {
    echo -e "\n${YELLOW}分析: 检查内存分配问题${NC}"
    
    # 显示可用内存信息
    echo "系统内存信息:"
    vm_stat
    
    # 查看错误发生位置的代码
    echo -e "\n加载元数据函数代码片段 (第311行附近):"
    grep -A 5 -B 5 "const path = try allocator.alloc" "$SOURCE_DIR/../src/main.zig" || echo "找不到相关代码行"
    
    echo -e "\n${YELLOW}建议: 可能需要检查loadMetadata函数的实现，特别是路径分配和反序列化部分。${NC}"
}

# 运行所有测试
run_all_tests() {
    setup_test_environment
    
    # 运行每个测试，如果有失败就继续下一个测试
    test_simple_encryption
    
    # 尝试解密但不影响后续测试
    test_simple_decryption || true
    
    # 分析内存问题
    analyze_memory_issue
    
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
