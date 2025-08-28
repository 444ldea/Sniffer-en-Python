#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import signal
import sys
import time
import threading
from collections import Counter, deque, defaultdict

try:
    from scapy.all import (
        sniff, ARP, Ether, IP, TCP, UDP, ICMP, DNS, DNSQR, DNSRR, conf
    )
except Exception as e:
    print("Error importando Scapy. ¿Instalaste scapy? pip install scapy")
    raise

# ----------------------------
# Configuración y argumentos
# ----------------------------

def build_args():
    p = argparse.ArgumentParser(
        description="Sniffer en tiempo real con detección básica (ARP spoofing, SYN flood, port scan)."
    )
    p.add_argument("-i", "--iface", help="Interfaz (ej: eth0, wlan0). Por defecto: la que elija Scapy.")
    p.add_argument("-f", "--bpf", default="arp or ip",
                   help='Filtro BPF (por defecto: "arp or ip"). Ej: "tcp or udp or arp"')
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Mostrar cada paquete capturado.")
    p.add_argument("--stats-interval", type=float, default=2.0,
                   help="Cada cuántos segundos imprimir estadísticas (default: 2s).")
    # Umbrales de detección (ajustables)
    p.add_argument("--arp-max-macs-per-ip", type=int, default=2,
                   help="Si un mismo IP aparece con >N MACs, alerta de ARP spoof (default: 2).")
    p.add_argument("--syn-window", type=float, default=5.0,
                   help="Ventana (seg) para medir SYN flood (default: 5s).")
    p.add_argument("--syn-threshold", type=int, default=150,
                   help="SYNs a un mismo destino en la ventana para alertar (default: 150).")
    p.add_argument("--scan-window", type=float, default=5.0,
                   help="Ventana (seg) para medir escaneo de puertos por IP origen (default: 5s).")
    p.add_argument("--scan-unique-dports", type=int, default=20,
                   help="Puertos destino únicos por origen en la ventana para alertar (default: 20).")
    return p.parse_args()

args = build_args()
stop_event = threading.Event()
lock = threading.Lock()

# ----------------------------
# Contadores y estado
# ----------------------------

proto_counts = Counter()
packet_count = 0

# ARP Spoofing
ip_to_macs = defaultdict(set)    # ip -> {macs}
last_arp_alert = {}              # ip -> timestamp último alerta para rate-limit
ARP_ALERT_COOLDOWN = 30.0        # segundos

# SYN flood (por destino)
syn_by_dst = defaultdict(deque)  # dst_ip -> deque[timestamps]
last_syn_alert = {}              # dst_ip -> t

# Port scan (por origen)
flows_by_src = defaultdict(deque)      # src_ip -> deque[(t, dst_ip, dport)]
last_scan_alert = {}                   # src_ip -> t
ALERT_COOLDOWN = 30.0

# ----------------------------
# Utilidades
# ----------------------------

def now():
    return time.time()

def cooldown_ok(last_map: dict, key, cooldown: float) -> bool:
    t = now()
    last = last_map.get(key, 0)
    if (t - last) >= cooldown:
        last_map[key] = t
        return True
    return False

def within_window(dq: deque, window: float):
    t = now()
    while dq and (t - dq[0]) > window:
        dq.popleft()

def within_window_triples(dq: deque, window: float):
    # Para deques de tuplas (t, ...)
    t = now()
    while dq and (t - dq[0][0]) > window:
        dq.popleft()

def tcp_flags_str(pkt):
    try:
        fl = pkt[TCP].flags
        return str(fl)
    except Exception:
        return "?"

# ----------------------------
# Detecciones
# ----------------------------

def detect_arp_spoof(pkt):
    """Alerta si un mismo IP aparece con múltiples MACs (posible ARP spoof)."""
    if ARP in pkt and pkt[ARP].op == 2:  # is-at (respuesta ARP)
        src_ip = pkt[ARP].psrc
        src_mac = pkt[ARP].hwsrc

        with lock:
            ip_to_macs[src_ip].add(src_mac)
            macs = ip_to_macs[src_ip]

            # Heurística: demasiadas MACs distintas para un IP (envenenamiento ARP)
            if len(macs) > args.arp_max_macs_per_ip:
                if cooldown_ok(last_arp_alert, src_ip, ARP_ALERT_COOLDOWN):
                    print(f"[ALERTA][ARP-SPOOF] IP {src_ip} asociado a múltiples MACs: {', '.join(macs)}")

        # Alerta suave para ARP "gratuito" (GARP): reply anunciándose sin request.
        # Útil pero no siempre malicioso (DHCP, failover). Solo informativo:
        if pkt[ARP].psrc != pkt[ARP].pdst:
            # Evitar spam: 1 cada 30s por IP
            if cooldown_ok(last_arp_alert, f"GARP:{src_ip}", ARP_ALERT_COOLDOWN):
                print(f"[INFO][ARP] GARP detectado: {src_ip} -> {src_mac} (pdst={pkt[ARP].pdst})")

def detect_syn_flood(pkt):
    """Cuenta SYNs por destino dentro de una ventana para detectar flood."""
    if TCP in pkt:
        flags = pkt[TCP].flags
        is_syn = flags & 0x02 != 0
        is_ack = flags & 0x10 != 0
        if is_syn and not is_ack:
            try:
                dst = pkt[IP].dst
            except Exception:
                return
            t = now()
            with lock:
                dq = syn_by_dst[dst]
                dq.append(t)
                within_window(dq, args.syn_window)
                if len(dq) >= args.syn_threshold:
                    if cooldown_ok(last_syn_alert, dst, ALERT_COOLDOWN):
                        print(f"[ALERTA][SYN-FLOOD] Muchas SYN a {dst} "
                              f"({len(dq)} en {args.syn_window:.0f}s)")

def detect_port_scan(pkt):
    """Heurística: un origen que toca muchos puertos de destino en ventana corta."""
    if TCP in pkt:
        try:
            src = pkt[IP].src
            dst = pkt[IP].dst
            dport = pkt[TCP].dport
        except Exception:
            return
        t = now()
        with lock:
            dq = flows_by_src[src]
            dq.append((t, dst, int(dport)))
            within_window_triples(dq, args.scan_window)
            # Contar puertos destino únicos en la ventana
            unique_ports = {p for (_, _, p) in dq}
            if len(unique_ports) >= args.scan_unique_dports:
                if cooldown_ok(last_scan_alert, src, ALERT_COOLDOWN):
                    print(f"[ALERTA][PORT-SCAN] Posible escaneo desde {src}: "
                          f"{len(unique_ports)} puertos distintos en {args.scan_window:.0f}s")

# ----------------------------
# Handler de paquetes
# ----------------------------

def packet_handler(pkt):
    global packet_count
    # Actualizar contadores
    with lock:
        packet_count += 1
        if ARP in pkt:
            proto_counts["ARP"] += 1
        elif IP in pkt:
            proto_counts["IP"] += 1
            if TCP in pkt:
                proto_counts["TCP"] += 1
            elif UDP in pkt:
                proto_counts["UDP"] += 1
            elif ICMP in pkt:
                proto_counts["ICMP"] += 1
        else:
            proto_counts["OTROS"] += 1

        # Algunas heurísticas por puertos (para visual rápido)
        try:
            if UDP in pkt and pkt.haslayer(DNS):
                proto_counts["DNS"] += 1
            if TCP in pkt and (pkt[TCP].dport == 80 or pkt[TCP].sport == 80):
                proto_counts["HTTP"] += 1
            if TCP in pkt and (pkt[TCP].dport == 443 or pkt[TCP].sport == 443):
                proto_counts["TLS/HTTPS"] += 1
        except Exception:
            pass

    # Detecciones
    detect_arp_spoof(pkt)
    detect_syn_flood(pkt)
    detect_port_scan(pkt)

    # Verbose por paquete
    if args.verbose:
        try:
            summary = pkt.summary()
        except Exception:
            summary = "<paquete>"
        print(summary)

# ----------------------------
# Estadísticas periódicas
# ----------------------------

class StatsPrinter(threading.Thread):
    def __init__(self, interval=2.0):
        super().__init__(daemon=True)
        self.interval = interval
        self.last_packets = 0
        self.last_time = now()

    def run(self):
        while not stop_event.is_set():
            time.sleep(self.interval)
            with lock:
                total = packet_count
                elapsed = max(1e-6, now() - self.last_time)
                pps = (total - self.last_packets) / elapsed
                self.last_packets = total
                self.last_time = now()

                # Construir línea de stats
                top = ", ".join(f"{k}:{v}" for k, v in proto_counts.most_common(6))
                print(f"[STATS] pkts:{total} | ~{pps:.1f} pkt/s | {top}")

# ----------------------------
# Señales y parada limpia
# ----------------------------

def handle_sigint(sig, frame):
    print("\nCerrando… (Ctrl+C)")
    stop_event.set()

signal.signal(signal.SIGINT, handle_sigint)

# ----------------------------
# Main
# ----------------------------

def main():
    print("=== Sniffer/IDS básico con Scapy ===")
    print(f"Interfaz: {args.iface or '(auto)'}  |  Filtro BPF: {args.bpf}")
    print("Controles: Ctrl+C para salir.")
    # Pequeña mejora: evita warnings de IPv6 si no hay
    conf.verb = 0

    stats_thread = StatsPrinter(interval=args.stats_interval)
    stats_thread.start()

    try:
        sniff(
            iface=args.iface,
            filter=args.bpf,
            prn=packet_handler,
            store=False,        # no almacenar en memoria
            stop_filter=lambda p: stop_event.is_set()
        )
    except PermissionError:
        print("Permiso denegado. Ejecuta con sudo/Administrador.")
    except Exception as e:
        print(f"Error en sniff: {e}")

    # Resumen final
    with lock:
        print("\n=== Resumen ===")
        total = packet_count
        print(f"Paquetes totales: {total}")
        for k, v in proto_counts.most_common():
            print(f"  {k}: {v}")
        # Estado ARP visto
        if ip_to_macs:
            print("\nTabla IP -> MACs observadas (para revisar incoherencias):")
            for ip, macs in ip_to_macs.items():
                mark = "  <-- sospechoso" if len(macs) > args.arp_max_macs_per_ip else ""
                print(f"  {ip:15} -> {', '.join(macs)}{mark}")

if __name__ == "__main__":
    main()
