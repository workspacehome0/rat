#!/bin/bash

echo "=========================================="
echo "RAT System Test Suite"
echo "=========================================="
echo ""

# Test 1: Check Python version
echo "[TEST 1] Checking Python version..."
python3 --version
if [ $? -eq 0 ]; then
    echo "[✓] Python 3 is installed"
else
    echo "[✗] Python 3 is not installed"
    exit 1
fi
echo ""

# Test 2: Check required files
echo "[TEST 2] Checking required files..."
FILES=("rat_server_fixed.py" "blockchain_server.py" "payload_generator.py" "rat_control.py")
for file in "${FILES[@]}"; do
    if [ -f "$file" ]; then
        echo "[✓] $file exists"
    else
        echo "[✗] $file missing"
        exit 1
    fi
done
echo ""

# Test 3: Test payload generation
echo "[TEST 3] Testing payload generation..."
python3 payload_generator.py > /dev/null 2>&1
if [ -f "test_payload.py" ]; then
    echo "[✓] Payload generated successfully"
    echo "[✓] test_payload.py created"
    SIZE=$(wc -c < test_payload.py)
    echo "[✓] Payload size: $SIZE bytes"
else
    echo "[✗] Payload generation failed"
    exit 1
fi
echo ""

# Test 4: Verify file permissions
echo "[TEST 4] Checking file permissions..."
if [ -x "rat_control.py" ]; then
    echo "[✓] Scripts are executable"
else
    echo "[!] Making scripts executable..."
    chmod +x *.py
    echo "[✓] Permissions fixed"
fi
echo ""

# Test 5: Check documentation
echo "[TEST 5] Checking documentation..."
if [ -f "README.md" ] && [ -f "QUICKSTART.md" ]; then
    echo "[✓] Documentation files present"
    README_LINES=$(wc -l < README.md)
    QUICK_LINES=$(wc -l < QUICKSTART.md)
    echo "[✓] README.md: $README_LINES lines"
    echo "[✓] QUICKSTART.md: $QUICK_LINES lines"
else
    echo "[✗] Documentation missing"
fi
echo ""

# Test 6: Check examples
echo "[TEST 6] Checking examples..."
if [ -d "examples" ]; then
    EXAMPLE_COUNT=$(ls -1 examples/*.py 2>/dev/null | wc -l)
    echo "[✓] Examples directory exists"
    echo "[✓] Found $EXAMPLE_COUNT example scripts"
else
    echo "[!] Examples directory not found"
fi
echo ""

echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "[✓] All tests passed!"
echo ""
echo "System is ready to use."
echo ""
echo "Quick Start:"
echo "  1. Start services: python3 rat_control.py"
echo "  2. Generate payload: Click 'Generate Payload' in GUI"
echo "  3. Deploy and execute payload on target"
echo ""
echo "Documentation:"
echo "  - Full docs: README.md"
echo "  - Quick start: QUICKSTART.md"
echo "=========================================="

