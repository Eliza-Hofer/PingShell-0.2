from scapy.all import sniff, IP, ICMP
from collections import deque, Counter
import time
import threading
import itertools

# Stores (timestamp, source IP) for recent pings
ping_log = deque(maxlen=128)

# Time between pings 
MAX_TIME_GAP = 3.0

def packet_handler(pkt):
    if ICMP in pkt and pkt[ICMP].type == 8:  # Echo
        timestamp = time.time()
        src_ip = pkt[IP].src
        ping_log.append((timestamp, src_ip))

def find_ip_pairs(ping_log):
    """Find IPs that frequently alternate pings, ignoring noise"""
    if len(ping_log) < 6:
        return []

    # Count frequency of alternations
    alt_counts = Counter()
    ip_set = set(ip for _, ip in ping_log)

    for ip1, ip2 in itertools.combinations(ip_set, 2):
        filtered = [(t, ip) for t, ip in ping_log if ip == ip1 or ip == ip2]
        ips = [ip for _, ip in filtered]

        count = 0
        for i in range(len(ips) - 3):
            seq = ips[i:i+4]
            if seq[0] == seq[2] and seq[1] == seq[3] and seq[0] != seq[1]:
                count += 1
        if count > 0:
            alt_counts[(ip1, ip2)] = count

    return alt_counts.most_common(2)  # top pairs

def analyze_binary_stream(ip1, ip2):
    """Turn filtered ping pattern into binary string"""
    bits = ''
    prev_time = None
    relevant_pings = [(t, ip) for t, ip in ping_log if ip in {ip1, ip2}]

    for t, ip in relevant_pings:
        bit = '1' if ip == ip1 else '0'
        if prev_time is not None and t - prev_time > MAX_TIME_GAP:
            bits += ' '  
        bits += bit
        prev_time = t

    print(f"[!] Stream between {ip1} (1) and {ip2} (0): {bits}")
    chunks = bits.split()
    for chunk in chunks:
        if len(chunk) >= 8:
            try:
                decoded = ''.join(chr(int(chunk[i:i+8], 2)) for i in range(0, len(chunk), 8))
                print(f"    → Decoded: {decoded}")
            except Exception:
                continue

def monitor_loop():
    while True:
        time.sleep(5)
        if not ping_log:
            continue

        # Identify sus pairs
        top_pairs = find_ip_pairs(ping_log)
        for (ip1, ip2), _ in top_pairs:
            analyze_binary_stream(ip1, ip2)

def main():
    print("Listening for ICMP Echo Requests...")
    threading.Thread(target=monitor_loop, daemon=True).start()
    sniff(filter="icmp", prn=packet_handler, store=0)

if __name__ == "__main__":
    main()


