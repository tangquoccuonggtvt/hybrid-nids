"""Trích xuất feature cho NIDS từ NFStreamer flow.

Lưu ý quan trọng:
- UNSW-NB15 có một số feature thống kê theo ngữ cảnh (`ct_*`) không thể lấy trực tiếp
  từ một flow đơn lẻ. File này dùng sliding window để ước lượng chúng từ các flow gần
  nhau trong cùng PCAP/luồng giám sát.
- Một số feature như `ct_state_ttl` và `tcprtt` vẫn chỉ là xấp xỉ nếu NFStreamer không
  cung cấp TCP state/TTL/RTT thật. Code ghi rõ fallback thay vì gán nhầm đơn vị như bản cũ.
"""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from datetime import datetime, timezone
from time import time
from typing import Any, Deque

from feature_schema import FEATURE_COLUMNS

EPS = 1e-9


def _num(value: Any, default: float = 0.0) -> float:
    """Ép một giá trị về float an toàn."""
    try:
        if value is None:
            return default
        value_float = float(value)
        if value_float != value_float:  # NaN check không cần import math.
            return default
        return value_float
    except (TypeError, ValueError):
        return default


def _int(value: Any, default: int = 0) -> int:
    """Ép một giá trị về int không âm an toàn."""
    return max(0, int(round(_num(value, default))))


def _get(flow: Any, name: str, default: Any = 0) -> Any:
    """Lấy thuộc tính từ NFStreamer flow, có fallback nếu version khác nhau."""
    return getattr(flow, name, default)


def _duration_seconds(flow: Any) -> float:
    """Lấy duration theo giây từ NFStreamer flow."""
    duration_ms = _num(_get(flow, "bidirectional_duration_ms", 0.0))
    return max(duration_ms / 1000.0, EPS)


def _first_seen_seconds(flow: Any) -> float:
    """Lấy timestamp bắt đầu flow theo giây; fallback sang thời gian hiện tại."""
    first_seen_ms = _num(_get(flow, "bidirectional_first_seen_ms", 0.0))
    if first_seen_ms > 0:
        return first_seen_ms / 1000.0
    return time()


def _mean_packet_size(byte_count: int, packet_count: int) -> int:
    """Tính byte trung bình mỗi packet theo một chiều."""
    if packet_count <= 0:
        return 0
    return int(round(byte_count / packet_count))


def _packet_rate(total_packets: int, duration_s: float) -> float:
    """Tính rate gần với UNSW: (tổng packet - 1) / duration."""
    if total_packets <= 1:
        return 0.0
    return float((total_packets - 1) / max(duration_s, EPS))


def _direction_load_bits_per_second(byte_count: int, packet_count: int, duration_s: float) -> float:
    """Tính sload/dload theo bit/giây có hiệu chỉnh số khoảng giữa các packet.

    Trong UNSW, load xấp xỉ `bytes * 8 / duration * ((packets - 1) / packets)`.
    Code cũ chia theo mili-giây nên lệch khoảng 1000 lần và làm model nhận sai phân phối.
    """
    if byte_count <= 0 or packet_count <= 1:
        return 0.0
    correction = (packet_count - 1) / packet_count
    return float(byte_count * 8.0 / max(duration_s, EPS) * correction)


def _tcp_rtt_seconds(flow: Any) -> float:
    """Ước lượng RTT TCP nếu NFStreamer có timestamp hai chiều đầu tiên.

    Nếu không có thông tin cần thiết, trả về 0.0 thay vì lấy min PIAT và gọi nhầm là RTT.
    """
    src_first_ms = _num(_get(flow, "src2dst_first_seen_ms", 0.0))
    dst_first_ms = _num(_get(flow, "dst2src_first_seen_ms", 0.0))
    if src_first_ms > 0 and dst_first_ms > 0 and dst_first_ms >= src_first_ms:
        return float((dst_first_ms - src_first_ms) / 1000.0)
    return 0.0


def _state_ttl_proxy(flow: Any, spkts: int, dpkts: int) -> int:
    """Xấp xỉ ct_state_ttl khi không có đầy đủ state/TTL từ PCAP.

    UNSW `ct_state_ttl` không thể tái tạo chính xác bằng NFStreamer cơ bản. Proxy này
    vẫn tốt hơn bản cũ vì không dùng nhầm số packet nguồn làm state/TTL.
    """
    protocol = _int(_get(flow, "protocol", 0))
    bidirectional_tcp_flags = _int(_get(flow, "bidirectional_tcp_flags", 0))
    src2dst_tcp_flags = _int(_get(flow, "src2dst_tcp_flags", 0))
    dst2src_tcp_flags = _int(_get(flow, "dst2src_tcp_flags", 0))

    if protocol not in {6, 17, 1}:  # TCP/UDP/ICMP thường gặp; protocol khác để 0.
        return 0
    if spkts > 0 and dpkts == 0:
        # Một chiều, thường gặp scan hoặc traffic không có phản hồi.
        return 2
    if protocol == 6:
        rst_flag = 0x04
        syn_flag = 0x02
        ack_flag = 0x10
        if bidirectional_tcp_flags & rst_flag:
            return 3
        if (src2dst_tcp_flags & syn_flag) and not (dst2src_tcp_flags & ack_flag):
            return 2
        return 1
    return 1 if dpkts > 0 else 2


@dataclass(frozen=True)
class FlowContext:
    """Thông tin tối thiểu để tính các feature ct_* trong sliding window."""

    timestamp_s: float
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    service: str


class FlowContextWindow:
    """Sliding window ước lượng các feature thống kê ngữ cảnh `ct_*`."""

    def __init__(self, window_seconds: float = 100.0, max_items: int = 200_000) -> None:
        self.window_seconds = float(window_seconds)
        self.max_items = int(max_items)
        self._items: Deque[FlowContext] = deque()
        self._srv_src: Counter[tuple[str, str]] = Counter()
        self._dst: Counter[str] = Counter()
        self._src_dport: Counter[tuple[str, int]] = Counter()
        self._dst_sport: Counter[tuple[str, int]] = Counter()
        self._dst_src: Counter[tuple[str, str]] = Counter()

    @staticmethod
    def _decrement(counter: Counter[Any], key: Any) -> None:
        counter[key] -= 1
        if counter[key] <= 0:
            del counter[key]

    def _add(self, ctx: FlowContext) -> None:
        self._items.append(ctx)
        self._srv_src[(ctx.src_ip, ctx.service)] += 1
        self._dst[ctx.dst_ip] += 1
        self._src_dport[(ctx.src_ip, ctx.dst_port)] += 1
        self._dst_sport[(ctx.dst_ip, ctx.src_port)] += 1
        self._dst_src[(ctx.src_ip, ctx.dst_ip)] += 1

    def _remove_left(self) -> None:
        old = self._items.popleft()
        self._decrement(self._srv_src, (old.src_ip, old.service))
        self._decrement(self._dst, old.dst_ip)
        self._decrement(self._src_dport, (old.src_ip, old.dst_port))
        self._decrement(self._dst_sport, (old.dst_ip, old.src_port))
        self._decrement(self._dst_src, (old.src_ip, old.dst_ip))

    def _evict_old(self, now_s: float) -> None:
        min_ts = now_s - self.window_seconds
        while self._items and (self._items[0].timestamp_s < min_ts or len(self._items) > self.max_items):
            self._remove_left()

    def counts_for(self, ctx: FlowContext) -> dict[str, int]:
        """Đếm các kết nối liên quan trong window, tính cả flow hiện tại."""
        self._evict_old(ctx.timestamp_s)
        counts = {
            "ct_srv_src": 1 + self._srv_src[(ctx.src_ip, ctx.service)],
            "ct_dst_ltm": 1 + self._dst[ctx.dst_ip],
            "ct_src_dport_ltm": 1 + self._src_dport[(ctx.src_ip, ctx.dst_port)],
            "ct_dst_sport_ltm": 1 + self._dst_sport[(ctx.dst_ip, ctx.src_port)],
            "ct_dst_src_ltm": 1 + self._dst_src[(ctx.src_ip, ctx.dst_ip)],
        }
        self._add(ctx)
        return counts


def make_flow_context(flow: Any) -> FlowContext:
    """Tạo FlowContext từ một NFStreamer flow."""
    src_ip = str(_get(flow, "src_ip", ""))
    dst_ip = str(_get(flow, "dst_ip", ""))
    src_port = _int(_get(flow, "src_port", 0))
    dst_port = _int(_get(flow, "dst_port", 0))
    protocol = str(_get(flow, "protocol", ""))
    app_name = str(_get(flow, "application_name", "") or "").strip()
    service = app_name if app_name else f"{protocol}:{dst_port}"
    return FlowContext(
        timestamp_s=_first_seen_seconds(flow),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        service=service,
    )


def extract_features_from_flow(flow: Any, context_window: FlowContextWindow | None = None) -> dict[str, float | int]:
    """Trích 22 feature hiện có của nhánh PCAP/NFStreamer từ một flow."""
    duration_s = _duration_seconds(flow)
    spkts = _int(_get(flow, "src2dst_packets", 0))
    dpkts = _int(_get(flow, "dst2src_packets", 0))
    sbytes = _int(_get(flow, "src2dst_bytes", 0))
    dbytes = _int(_get(flow, "dst2src_bytes", 0))
    total_packets = spkts + dpkts

    ctx = make_flow_context(flow)
    if context_window is None:
        # Fallback chỉ dùng cho unit test/khám phá. Detector production nên truyền window.
        context_counts = {
            "ct_srv_src": 1,
            "ct_dst_ltm": 1,
            "ct_src_dport_ltm": 1,
            "ct_dst_sport_ltm": 1,
            "ct_dst_src_ltm": 1,
        }
    else:
        context_counts = context_window.counts_for(ctx)

    features: dict[str, float | int] = {
        "dur": float(duration_s),
        "spkts": spkts,
        "dpkts": dpkts,
        "sbytes": sbytes,
        "dbytes": dbytes,
        "rate": _packet_rate(total_packets, duration_s),
        "sload": _direction_load_bits_per_second(sbytes, spkts, duration_s),
        "dload": _direction_load_bits_per_second(dbytes, dpkts, duration_s),
        "sjit": float(_num(_get(flow, "src2dst_stddev_piat_ms", 0.0))),
        "djit": float(_num(_get(flow, "dst2src_stddev_piat_ms", 0.0))),
        "smean": _mean_packet_size(sbytes, spkts),
        "dmean": _mean_packet_size(dbytes, dpkts),
        "sinpkt": float(_num(_get(flow, "src2dst_mean_piat_ms", 0.0))),
        "dinpkt": float(_num(_get(flow, "dst2src_mean_piat_ms", 0.0))),
        "tcprtt": _tcp_rtt_seconds(flow),
        "is_sm_ips_ports": int(ctx.src_ip == ctx.dst_ip and ctx.src_port == ctx.dst_port),
        "ct_state_ttl": _state_ttl_proxy(flow, spkts, dpkts),
        **context_counts,
    }

    # Bảo đảm extractor tạo đủ và chỉ đúng feature model cần.
    missing = sorted(set(FEATURE_COLUMNS) - set(features))
    if missing:
        raise RuntimeError(f"Lỗi lập trình: extractor thiếu feature {missing}")
    return {col: features[col] for col in FEATURE_COLUMNS}


def extract_metadata_from_flow(flow: Any) -> dict[str, str | int]:
    """Lấy metadata để ghi log/cảnh báo, tách khỏi feature đưa vào model."""
    first_seen_ms = _num(_get(flow, "bidirectional_first_seen_ms", 0.0))
    last_seen_ms = _num(_get(flow, "bidirectional_last_seen_ms", first_seen_ms))

    def _iso_utc(epoch_ms: float) -> str:
        if epoch_ms <= 0:
            return ""
        return datetime.fromtimestamp(epoch_ms / 1000.0, timezone.utc).isoformat()

    return {
        "start_utc": _iso_utc(first_seen_ms),
        "end_utc": _iso_utc(last_seen_ms),
        "src_ip": str(_get(flow, "src_ip", "")),
        "src_port": _int(_get(flow, "src_port", 0)),
        "dst_ip": str(_get(flow, "dst_ip", "")),
        "dst_port": _int(_get(flow, "dst_port", 0)),
        "protocol": str(_get(flow, "protocol", "")),
        "application_name": str(_get(flow, "application_name", "") or ""),
    }
