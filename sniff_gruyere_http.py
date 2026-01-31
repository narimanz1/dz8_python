#!/usr/bin/env python3
"""
Scapy HTTP Sniffer для Google Gruyere.
Перехватывает HTTP-трафик на loopback-интерфейсе,
парсит пары запрос -> ответ и сохраняет в pairs.jsonl + traffic.pcap.

Запуск: sudo ./venv/bin/python sniff_gruyere_http.py [--port 8008] [--iface lo0]
"""

import argparse
import json
import signal
import sys
import time
from collections import defaultdict
from pathlib import Path

from scapy.all import (
    IP, TCP, Raw,
    sniff, wrpcap,
    conf,
)

# --------------- настройки ---------------
PROJECT_DIR = Path(__file__).resolve().parent
PAIRS_FILE = PROJECT_DIR / "evidence" / "pairs.jsonl"
PCAP_FILE = PROJECT_DIR / "evidence" / "traffic.pcap"

# --------------- глобальное состояние ---------------
captured_packets = []
pending_requests = {}        # client_port -> request dict
completed_pairs = []         # list of {request, response}
running = True


def safe_decode(raw_bytes: bytes) -> str:
    """Безопасное декодирование байтов в строку."""
    for enc in ("utf-8", "latin-1"):
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, AttributeError):
            continue
    return raw_bytes.hex()


def parse_http_message(payload: str):
    """
    Разбирает сырую HTTP-строку на start_line, headers (dict), body.
    Возвращает dict или None, если это не HTTP.
    """
    if not payload:
        return None

    parts = payload.split("\r\n\r\n", 1)
    head = parts[0]
    body = parts[1] if len(parts) > 1 else ""

    lines = head.split("\r\n")
    if not lines:
        return None

    start_line = lines[0]

    # Проверяем, что это HTTP
    is_request = any(start_line.startswith(m) for m in
                     ("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH "))
    is_response = start_line.startswith("HTTP/")

    if not is_request and not is_response:
        return None

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            key, _, val = line.partition(":")
            headers[key.strip()] = val.strip()

    return {
        "start_line": start_line,
        "headers": headers,
        "body": body[:4000],  # ограничиваем размер тела
        "type": "request" if is_request else "response",
    }


def process_packet(pkt):
    """Callback для sniff — обрабатывает каждый пакет."""
    global running
    if not running:
        return

    captured_packets.append(pkt)

    if not pkt.haslayer(Raw) or not pkt.haslayer(TCP) or not pkt.haslayer(IP):
        return

    raw = safe_decode(bytes(pkt[Raw].load))
    msg = parse_http_message(raw)
    if msg is None:
        return

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    sport = pkt[TCP].sport
    dport = pkt[TCP].dport
    ts = float(pkt.time)

    if msg["type"] == "request":
        # Ключ = клиентский порт (sport для запроса)
        client_port = sport
        pending_requests[client_port] = {
            "timestamp": ts,
            "src": f"{src_ip}:{sport}",
            "dst": f"{dst_ip}:{dport}",
            "start_line": msg["start_line"],
            "headers": msg["headers"],
            "body": msg["body"],
        }
        print(f"  [REQ] {msg['start_line']}  (client_port={client_port})")

    elif msg["type"] == "response":
        # Ключ = dport ответа = client_port запроса
        client_port = dport
        resp_info = {
            "timestamp": ts,
            "src": f"{src_ip}:{sport}",
            "dst": f"{dst_ip}:{dport}",
            "start_line": msg["start_line"],
            "headers": msg["headers"],
            "body": msg["body"],
        }

        if client_port in pending_requests:
            pair = {
                "request": pending_requests.pop(client_port),
                "response": resp_info,
            }
            completed_pairs.append(pair)
            print(f"  [RSP] {msg['start_line']}  -> paired with request")
        else:
            print(f"  [RSP] {msg['start_line']}  (no matching request)")


def save_results():
    """Сохраняет пары и pcap."""
    PAIRS_FILE.parent.mkdir(parents=True, exist_ok=True)

    # pairs.jsonl
    with open(PAIRS_FILE, "w", encoding="utf-8") as f:
        for pair in completed_pairs:
            f.write(json.dumps(pair, ensure_ascii=False, default=str) + "\n")
    print(f"\n[*] Сохранено пар request/response: {len(completed_pairs)} -> {PAIRS_FILE}")

    # pcap
    if captured_packets:
        wrpcap(str(PCAP_FILE), captured_packets)
        print(f"[*] Сохранено пакетов в pcap: {len(captured_packets)} -> {PCAP_FILE}")
    else:
        print("[!] Пакетов не перехвачено, pcap не создан.")


def signal_handler(sig, frame):
    global running
    print("\n[!] Остановка сниффера (Ctrl+C)...")
    running = False


def main():
    parser = argparse.ArgumentParser(description="Scapy HTTP sniffer для Gruyere")
    parser.add_argument("--iface", default="lo0",
                        help="Сетевой интерфейс (по умолчанию lo0)")
    parser.add_argument("--host", default="127.0.0.1",
                        help="Хост Gruyere (по умолчанию 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8008,
                        help="Порт Gruyere (по умолчанию 8008)")
    parser.add_argument("--timeout", type=int, default=0,
                        help="Таймаут в секундах (0 = бесконечно, стоп по Ctrl+C)")
    args = parser.parse_args()

    bpf = f"tcp port {args.port} and host {args.host}"
    print(f"[*] Scapy HTTP Sniffer для Google Gruyere")
    print(f"[*] Интерфейс : {args.iface}")
    print(f"[*] BPF фильтр: {bpf}")
    print(f"[*] Нажмите Ctrl+C для остановки\n")

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    timeout = args.timeout if args.timeout > 0 else None

    try:
        sniff(
            iface=args.iface,
            filter=bpf,
            prn=process_packet,
            store=False,
            timeout=timeout,
            stop_filter=lambda _: not running,
        )
    except PermissionError:
        print("[!] Ошибка: нужны права sudo для перехвата на интерфейсе.")
        print(f"    Запустите: sudo ./venv/bin/python {__file__}")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Ошибка sniff: {e}")

    save_results()
    print("[*] Готово.")


if __name__ == "__main__":
    main()
