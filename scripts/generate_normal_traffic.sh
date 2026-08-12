#!/bin/bash
# generate_normal_traffic.sh — Tạo traffic bình thường nền trên VM NIDS
# Chạy SONG SONG với tấn công để tạo dữ liệu normal cho retrain
#
# Cách dùng:
#   chmod +x scripts/generate_normal_traffic.sh
#   ./scripts/generate_normal_traffic.sh          # chạy 10 phút (mặc định)
#   ./scripts/generate_normal_traffic.sh 300      # chạy 5 phút
#   ./scripts/generate_normal_traffic.sh 900      # chạy 15 phút
#
# Traffic sinh ra: HTTP browse, DNS lookup, ping, apt check — giống hoạt động
# bình thường của server/user trên mạng. KHÔNG đến từ IP Kali nên sẽ được
# gán nhãn Normal khi retrain.

DURATION=${1:-600}  # mặc định 10 phút
END_TIME=$((SECONDS + DURATION))
COUNT=0

echo "=== NORMAL TRAFFIC GENERATOR ==="
echo "    Thời gian: ${DURATION}s"
echo "    Bắt đầu: $(date)"
echo "    Ctrl+C để dừng sớm"
echo ""

while [ $SECONDS -lt $END_TIME ]; do
    # HTTP requests đến các trang phổ biến (hoặc local web server)
    curl -s -o /dev/null -w "" http://example.com/ 2>/dev/null &
    curl -s -o /dev/null -w "" http://httpbin.org/get 2>/dev/null &

    # DNS lookups
    dig google.com @8.8.8.8 +short > /dev/null 2>&1 &
    dig facebook.com +short > /dev/null 2>&1 &
    nslookup microsoft.com > /dev/null 2>&1 &

    # Ping (ICMP)
    ping -c 1 -W 1 8.8.8.8 > /dev/null 2>&1 &
    ping -c 1 -W 1 1.1.1.1 > /dev/null 2>&1 &

    # Simulate apt/update check (HTTP traffic)
    curl -s -o /dev/null http://archive.ubuntu.com/ubuntu/dists/jammy/Release 2>/dev/null &

    COUNT=$((COUNT + 1))

    # Random delay 1-5 giây (giống traffic thật — không đều)
    sleep $((RANDOM % 5 + 1))

    # Log tiến độ mỗi 20 vòng
    if [ $((COUNT % 20)) -eq 0 ]; then
        ELAPSED=$((SECONDS))
        REMAINING=$((END_TIME - SECONDS))
        echo "  [${COUNT} rounds] elapsed=${ELAPSED}s remaining=${REMAINING}s"
    fi
done

echo ""
echo "=== KẾT THÚC ==="
echo "    Tổng: ${COUNT} rounds"
echo "    Kết thúc: $(date)"
echo "    Traffic normal đã được CICFlowMeter ghi lại."
