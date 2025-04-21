#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

# Paths
CRYPTBAK_BIN="./zig-out/bin/cryptbak"
TEST_DIR="./test_integration"
SOURCE_DIR="$TEST_DIR/source"
BACKUP_DIR="$TEST_DIR/backup"
RESTORE_DIR="$TEST_DIR/restore"
TEST_PASSWORD="test_password_123"

# Create the test directory if it doesn't exist
mkdir -p "$TEST_DIR"

# Available tests
AVAILABLE_TESTS=("unit" "encrypt" "decrypt" "incremental" "watch")

# Function to print usage information
print_usage() {
    echo -e "${YELLOW}Usage:${NC} $0 [test_name]"
    echo -e "Available tests:"
    echo -e "  unit        - Run unit tests"
    echo -e "  encrypt     - Test file encryption"
    echo -e "  decrypt     - Test file decryption"
    echo -e "  incremental - Test incremental backup"
    echo -e "  watch       - Test watch mode"
    echo -e "  all         - Run all tests (default)"
    echo -e "  help        - Show this help message"
}

# Check if the binary exists
check_binary() {
    if [ ! -f "$CRYPTBAK_BIN" ]; then
        echo -e "${RED}Error: $CRYPTBAK_BIN not found. Please build the project first.${NC}"
        exit 1
    fi
}

# Test directories
TEST_BASE="$(pwd)/test_integration"
SOURCE_DIR="$TEST_BASE/source"
BACKUP_DIR="$TEST_BASE/backup"
RESTORE_DIR="$TEST_BASE/restore"
CRYPTBAK_BIN="$(pwd)/zig-out/bin/cryptbak"

# Test password
TEST_PASSWORD="test_password_123"

# Create test directory structure
setup_test_environment() {
    echo -e "${YELLOW}Setting up test environment...${NC}"

    # Clean up previous test directories (if they exist)
    rm -rf "$TEST_BASE"

    # Create new test directories
    mkdir -p "$SOURCE_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$RESTORE_DIR"

    # Create a very simple test file
    echo "This is a simple test file content" > "$SOURCE_DIR/simple_file.txt"

    # Create multi-level directory structure
    mkdir -p "$SOURCE_DIR/level1/level2/level3"
    echo "This is a file in the first level directory" > "$SOURCE_DIR/level1/file1.txt"
    echo "This is a file in the second level directory" > "$SOURCE_DIR/level1/level2/file2.txt"
    echo "This is a file in the third level directory" > "$SOURCE_DIR/level1/level2/level3/file3.txt"

    # Create files with special names
    echo "File name with spaces" > "$SOURCE_DIR/file with spaces.txt"
    echo "File name with special characters" > "$SOURCE_DIR/special_@#$%^&()_file.txt"

    # Create a large file (10MB)
    dd if=/dev/urandom of="$SOURCE_DIR/large_file.bin" bs=1M count=10

    # Create a collection of small files
    mkdir -p "$SOURCE_DIR/many_files"
    for i in {1..100}; do
        echo "This is small file number $i" > "$SOURCE_DIR/many_files/small_file_$i.txt"
    done

    # Create empty file and empty directory
    touch "$SOURCE_DIR/empty_file.txt"
    mkdir -p "$SOURCE_DIR/empty_dir"

    # Create file with very long name
    long_name=$(printf 'a%.0s' {1..100})
    echo "Long filename test" > "$SOURCE_DIR/$long_name.txt"

    echo -e "${GREEN}Test environment setup complete.${NC}"
}

# Run command and handle failure gracefully
run_cmd() {
    echo "Executing: $@"
    if ! "$@"; then
        echo -e "${RED}Command execution failed: $@${NC}"
        return 1
    fi
    return 0
}

# Test simple encryption
test_file_encryption() {
    echo -e "\n${YELLOW}Test 1: Simple File Encryption${NC}"

    echo "Running encryption..."
    run_cmd "$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -p "$TEST_PASSWORD" || return 1

    # Check if content subdirectory exists in backup directory
    if [ ! -d "$BACKUP_DIR/content" ]; then
        echo -e "${RED}Failed: content subdirectory does not exist${NC}"
        return 1
    fi

    # Check if files exist in content directory (doesn't need to be exactly equal due to content-based deduplication)
    local source_files_count=$(find "$SOURCE_DIR" -type f | wc -l)
    local content_files_count=$(find "$BACKUP_DIR/content" -type f | wc -l)

    if [ "$content_files_count" -eq 0 ]; then
        echo -e "${RED}Failed: no files in content directory${NC}"
        return 1
    fi

    echo -e "${YELLOW}Source directory file count: $source_files_count, content directory file count: $content_files_count${NC}"
    echo -e "${YELLOW}Note: Due to content-based deduplication, content directory may have fewer files than source directory${NC}"

    # Check if metadata file exists
    if [ ! -f "$BACKUP_DIR/.cryptbak.meta" ]; then
        echo -e "${RED}Failed: metadata file does not exist${NC}"
        return 1
    fi

    echo -e "${GREEN}Test 1 passed: File encryption successful${NC}"
    return 0
}

# Test simple decryption
test_file_decryption() {
    echo -e "\n${YELLOW}Test 2: File Decryption${NC}"

    echo "Running decryption..."
    set +e  # Temporarily disable error exit
    "$CRYPTBAK_BIN" "$BACKUP_DIR" "$RESTORE_DIR" -d -p "$TEST_PASSWORD" > /tmp/decrypt_output.log 2>&1
    local result=$?
    set -e  # Re-enable error exit

    if [ $result -ne 0 ]; then
        echo -e "${RED}Decryption failed, error code: $result${NC}"
        echo -e "${YELLOW}Error log:${NC}"
        cat /tmp/decrypt_output.log
        return 1
    fi

    # Check if decrypted files exist in restore directory
    if [ ! -f "$RESTORE_DIR/simple_file.txt" ]; then
        echo -e "${RED}Failed: decrypted file does not exist${NC}"
        return 1
    fi

    # Compare original and decrypted files
    if ! cmp -s "$SOURCE_DIR/simple_file.txt" "$RESTORE_DIR/simple_file.txt"; then
        echo -e "${RED}Failed: decrypted file content does not match original${NC}"
        return 1
    fi

    # Check if multi-level files were correctly decrypted
    if [ ! -f "$RESTORE_DIR/level1/level2/level3/file3.txt" ]; then
        echo -e "${RED}Failed: multi-level file not correctly decrypted${NC}"
        return 1
    fi

    if ! cmp -s "$SOURCE_DIR/level1/level2/level3/file3.txt" "$RESTORE_DIR/level1/level2/level3/file3.txt"; then
        echo -e "${RED}Failed: multi-level file content does not match original${NC}"
        return 1
    fi

    # Check if files with special names were correctly decrypted
    if [ ! -f "$RESTORE_DIR/file with spaces.txt" ]; then
        echo -e "${RED}Failed: file with spaces in name not correctly decrypted${NC}"
        return 1
    fi

    # Check if large file was correctly decrypted
    if [ ! -f "$RESTORE_DIR/large_file.bin" ]; then
        echo -e "${RED}Failed: large file not correctly decrypted${NC}"
        return 1
    fi

    if ! cmp -s "$SOURCE_DIR/large_file.bin" "$RESTORE_DIR/large_file.bin"; then
        echo -e "${RED}Failed: large file content does not match original${NC}"
        return 1
    fi

    # Check small file collection
    restored_small_files_count=$(find "$RESTORE_DIR/many_files" -type f | wc -l)
    if [ "$restored_small_files_count" -lt 100 ]; then
        echo -e "${RED}Failed: small file collection not fully decrypted, expected 100, got $restored_small_files_count${NC}"
        return 1
    fi

    # Randomly check one small file content
    if ! cmp -s "$SOURCE_DIR/many_files/small_file_42.txt" "$RESTORE_DIR/many_files/small_file_42.txt"; then
        echo -e "${RED}Failed: small file content does not match original${NC}"
        return 1
    fi

    # Check if total file count matches
    source_files_count=$(find "$SOURCE_DIR" -type f | wc -l)
    restore_files_count=$(find "$RESTORE_DIR" -type f | wc -l)
    if [ "$source_files_count" -ne "$restore_files_count" ]; then
        echo -e "${RED}Failed: source and restore directory file counts don't match (source: $source_files_count, restore: $restore_files_count)${NC}"
        return 1
    fi

    echo -e "${GREEN}Test 2 passed: File decryption successful${NC}"
    return 0
}

# Test incremental backup
test_incremental_backup() {
    echo -e "\n${YELLOW}Test 3: Incremental Backup${NC}"

    # Modify some existing files
    echo "This is modified file content" > "$SOURCE_DIR/simple_file.txt"
    echo "This is modified hierarchical file content" > "$SOURCE_DIR/level1/level2/file2.txt"

    # Add some new files
    echo "This is a newly added file" > "$SOURCE_DIR/new_file.txt"
    mkdir -p "$SOURCE_DIR/new_dir"
    echo "This is a file in the new directory" > "$SOURCE_DIR/new_dir/new_dir_file.txt"

    # Delete some files
    rm "$SOURCE_DIR/level1/file1.txt"

    echo "Running incremental backup..."
    run_cmd "$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -p "$TEST_PASSWORD" || return 1

    # Check if new files were backed up (doesn't need to check equal counts due to content-based deduplication)
    local source_files_count=$(find "$SOURCE_DIR" -type f | wc -l)
    local content_files_count=$(find "$BACKUP_DIR/content" -type f | wc -l)

    if [ "$content_files_count" -eq 0 ]; then
        echo -e "${RED}Failed: after incremental backup, no files in content directory${NC}"
        return 1
    fi

    echo -e "${YELLOW}After incremental backup - Source directory file count: $source_files_count, content directory file count: $content_files_count${NC}"
    echo -e "${YELLOW}Note: Due to content-based deduplication, content directory may have fewer files than source directory${NC}"

    # Decryption test to ensure modified files are correctly decrypted
    rm -rf "$RESTORE_DIR"
    mkdir -p "$RESTORE_DIR"

    "$CRYPTBAK_BIN" "$BACKUP_DIR" "$RESTORE_DIR" -d -p "$TEST_PASSWORD" > /tmp/decrypt_output.log 2>&1
    local result=$?

    if [ $result -ne 0 ]; then
        echo -e "${RED}Decryption after incremental backup failed, error code: $result${NC}"
        cat /tmp/decrypt_output.log
        return 1
    fi

    # Check if modified files were correctly restored
    if ! grep -q "This is modified file content" "$RESTORE_DIR/simple_file.txt"; then
        echo -e "${RED}Failed: modified file content not correctly restored${NC}"
        return 1
    fi

    # Check if newly added files were correctly restored
    if [ ! -f "$RESTORE_DIR/new_file.txt" ]; then
        echo -e "${RED}Failed: newly added file not correctly restored${NC}"
        return 1
    fi

    # Check if deleted files were also removed from backup
    if [ -f "$RESTORE_DIR/level1/file1.txt" ]; then
        echo -e "${RED}Failed: deleted file still exists in restore directory${NC}"
        return 1
    fi

    echo -e "${GREEN}Test 3 passed: Incremental backup successful${NC}"
    return 0
}

test_watch_mode() {
    echo -e "\n${YELLOW}Test 4: Watch Mode${NC}"
    
    # Clean up and recreate test directories
    echo "Setting up clean test environment for watch mode test..."
    rm -rf "$SOURCE_DIR" "$BACKUP_DIR" "$RESTORE_DIR"
    mkdir -p "$SOURCE_DIR"
    mkdir -p "$BACKUP_DIR"
    mkdir -p "$RESTORE_DIR"
    
    # Create an initial file for the initial backup
    echo "Creating initial file..."
    echo "Initial test file content" > "$SOURCE_DIR/initial_file.txt"
    
    # First run a normal backup to establish baseline
    echo "Running initial backup..."
    "$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -p "$TEST_PASSWORD" > /tmp/initial_backup.log 2>&1
    
    # Get initial content count
    local initial_content_files_count=0
    if [ -d "$BACKUP_DIR/content" ]; then
        initial_content_files_count=$(find "$BACKUP_DIR/content" -type f | wc -l)
    fi
    echo "Initial content files count: $initial_content_files_count"
    
    # Now start watch mode
    echo "Starting cryptbak in watch mode..."
    "$CRYPTBAK_BIN" "$SOURCE_DIR" "$BACKUP_DIR" -t -p "$TEST_PASSWORD" --mt 1 > /tmp/watch_output.log 2>&1 &
    WATCH_PID=$!
    
    # Wait for watch mode to initialize
    echo "Waiting for watch mode to initialize (3 seconds)..."
    sleep 3
    
    # Create new files with unique timestamps
    echo "Creating new test files..."
    local timestamp=$(date +%s)
    echo "This is test file 1" > "$SOURCE_DIR/test_file_1_$timestamp.txt"
    sleep 1
    echo "This is test file 2" > "$SOURCE_DIR/test_file_2_$timestamp.txt"
    
    # Wait longer for watch mode to detect changes
    echo "Waiting for backup to occur (8 seconds)..."
    sleep 8
    
    # Terminate the watch process
    echo "Terminating watch mode process..."
    kill $WATCH_PID
    sleep 1
    
    # Check if content directory has new files
    local final_content_files_count=0
    if [ -d "$BACKUP_DIR/content" ]; then
        final_content_files_count=$(find "$BACKUP_DIR/content" -type f | wc -l)
    fi
    
    echo "Content files count - Initial: $initial_content_files_count, Final: $final_content_files_count, Difference: $((final_content_files_count - initial_content_files_count))"
    
    # Display watch output for debugging
    echo "Watch mode log output:"
    cat /tmp/watch_output.log
    
    if [ $final_content_files_count -le $initial_content_files_count ]; then
        echo -e "${RED}Failed: No new content files added during watch mode${NC}"
        return 1
    fi
    
    # Check if watch mode logged any errors
    if grep -q "Error" /tmp/watch_output.log; then
        echo -e "${RED}Failed: Watch mode logged errors${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Test 4 passed: Watch mode successfully detected and backed up file changes${NC}"
    return 0
}

# Run Zig unit tests
run_unit_tests() {
    echo -e "\n${YELLOW}Running Zig unit tests...${NC}"

    # Test all modules
    if ! zig test src/metadata.zig; then
        echo -e "${RED}metadata.zig unit tests failed${NC}"
        return 1
    fi

    if ! zig test src/crypto_utils.zig; then
        echo -e "${RED}crypto_utils.zig unit tests failed${NC}"
        return 1
    fi

    if ! zig test src/fs_utils.zig; then
        echo -e "${RED}fs_utils.zig unit tests failed${NC}"
        return 1
    fi

    if ! zig test src/config.zig; then
        echo -e "${RED}config.zig unit tests failed${NC}"
        return 1
    fi

   if ! zig test src/fs_watcher.zig; then
        echo -e "${RED}fs_watcher.zig unit tests failed${NC}"
        return 1
    fi

    if ! zig test src/backup.zig; then
        echo -e "${RED}backup.zig unit tests failed${NC}"
        return 1
    fi

    if ! zig test src/backup_test.zig; then
        echo -e "${RED}backup_test.zig unit tests failed${NC}"
        return 1
    fi

    echo -e "${GREEN}All unit tests passed!${NC}"
    return 0
}

# Main function
main() {
    # Check for help flag
    if [ "$1" == "help" ] || [ "$1" == "--help" ] || [ "$1" == "-h" ]; then
        print_usage
        exit 0
    fi

    check_binary

    # Default is to run all tests
    local test_to_run="all"
    
    # If an argument is provided, validate it
    if [ $# -gt 0 ]; then
        test_to_run="$1"
        # Check if the specified test is valid
        local valid_test=false
        for t in "${AVAILABLE_TESTS[@]}" "all"; do
            if [ "$test_to_run" == "$t" ]; then
                valid_test=true
                break
            fi
        done
        
        if [ "$valid_test" == "false" ]; then
            echo -e "${RED}Error: Invalid test name '$test_to_run'${NC}"
            print_usage
            exit 1
        fi
    fi
    
    # Run the selected test(s)
    echo -e "${YELLOW}Running tests: $test_to_run${NC}"
    
    # First run unit tests unless specifically running a different test
    if [ "$test_to_run" == "all" ] || [ "$test_to_run" == "unit" ]; then
        if ! run_unit_tests; then
            echo -e "${RED}Unit tests failed, aborting further tests${NC}"
            exit 1
        fi
    fi
    
    # Run the specific integration test or all of them
    if [ "$test_to_run" == "all" ] || [ "$test_to_run" == "encrypt" ]; then
        if ! test_file_encryption; then
            echo -e "${RED}File encryption test failed, aborting tests${NC}"
            exit 1
        fi
    fi
    
    if [ "$test_to_run" == "all" ] || [ "$test_to_run" == "decrypt" ]; then
        if ! test_file_decryption; then
            echo -e "${RED}File decryption test failed, aborting tests${NC}"
            exit 1
        fi
    fi
    
    if [ "$test_to_run" == "all" ] || [ "$test_to_run" == "incremental" ]; then
        if ! test_incremental_backup; then
            echo -e "${RED}Incremental backup test failed, aborting tests${NC}"
            exit 1
        fi
    fi
    
    if [ "$test_to_run" == "all" ] || [ "$test_to_run" == "watch" ]; then
        if ! test_watch_mode; then
            echo -e "${RED}Watch mode test failed, aborting tests${NC}"
            exit 1
        fi
    fi
    
    echo -e "${GREEN}All selected tests passed successfully!${NC}"
    exit 0
}

# Run the main function
main "$@"
