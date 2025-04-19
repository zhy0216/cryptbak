#!/bin/bash
set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # 无颜色

CRYPTBAK_BIN="$(pwd)/zig-out/bin/cryptbak"
TEST_DIR="$(pwd)/debug_test"
SOURCE_DIR="$TEST_DIR/source"
BACKUP_DIR="$TEST_DIR/backup"
RESTORE_DIR="$TEST_DIR/restore"
PASSWORD="debug_password"

# 确保测试目录存在
mkdir -p "$SOURCE_DIR" "$BACKUP_DIR" "$RESTORE_DIR"

# 创建一个非常小的测试文件
echo "debug test content" > "$SOURCE_DIR/tiny.txt"

echo -e "${YELLOW}1. 尝试加密文件${NC}"
"$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -p "$PASSWORD"

echo -e "\n${YELLOW}2. 检查元数据文件${NC}"
ls -la "$BACKUP_DIR/"
METADATA_FILE="$BACKUP_DIR/.cryptbak.meta"
if [ -f "$METADATA_FILE" ]; then
    echo "元数据文件存在，大小: $(du -h "$METADATA_FILE" | cut -f1)"
    
    echo -e "\n${YELLOW}3. 检查元数据文件内容（二进制格式）${NC}"
    # 显示元数据文件的二进制内容
    hexdump -C "$METADATA_FILE" | head -20
else
    echo "元数据文件不存在"
fi

echo -e "\n${YELLOW}4. 尝试使用二进制调试工具运行程序${NC}"
# 设置环境变量，增加调试信息
export ZIG_DEBUG=1

# 尝试使用更多内存运行解密过程
echo "尝试解密，打开详细日志..."
"$CRYPTBAK_BIN" "$BACKUP_DIR" "$RESTORE_DIR" -d -p "$PASSWORD" || {
    echo -e "${RED}解密失败，错误代码: $?${NC}"
}

echo -e "\n${YELLOW}5. 建议修复方案${NC}"
echo "1. 检查loadMetadata函数中path_len的计算和验证"
echo "2. 添加边界检查，确保path_len不会过大"
echo "3. 考虑使用不同的内存分配策略"
echo "4. 限制元数据文件中path_len的最大值"

echo -e "\n${YELLOW}6. 修改建议${NC}"
cat << 'EOF'
在main.zig第311行左右，建议修改类似如下：

```zig
// 添加最大路径长度限制
const MAX_PATH_LEN = 1024;

// 读取path长度
var path_len_bytes: [8]u8 = undefined;
_ = try reader.read(&path_len_bytes);
const path_len = std.mem.readInt(u64, &path_len_bytes, .little);

// 添加安全检查
if (path_len == 0 || path_len > MAX_PATH_LEN) {
    return error.InvalidMetadataFile;
}

// 分配内存
const path = try allocator.alloc(u8, path_len);
```

这样可以防止由于非法的path_len值导致的内存分配问题。
EOF

echo -e "\n${GREEN}调试脚本完成${NC}"
