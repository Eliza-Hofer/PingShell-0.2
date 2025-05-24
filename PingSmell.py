from scapy.all import sniff, IP, ICMP
from collections import deque, Counter
import time
import threading
import itertools

# Stores (timestamp, source IP) for recent pings
ping_log = deque(maxlen=128)

# Time between pings 
MAX_TIME_GAP = 3.0

def flip_bits(bits):
    """Flip each bit in the binary string."""
    return ''.join('1' if b == '0' else '0' for b in bits)

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

def binary_to_text(binary_str):
    print(f"[DEBUG] Starting binary_to_text with input: {binary_str}")
    # Ensure the binary string length is a multiple of 8
    if len(binary_str) % 8 != 0:
        print(f"[!] Warning: Incomplete byte detected! Binary length: {len(binary_str)}")
        binary_str = binary_str[:-(len(binary_str) % 8)]  # Trim off incomplete bits
    try:
        # Split the binary string into 8-bit chunks
        chunks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
        print(f"[DEBUG] Binary chunks: {chunks}")
        # Convert each chunk to the corresponding character
        text = "".join(chr(int(chunk, 2)) for chunk in chunks)
        print(f"[DEBUG] Converted text: {repr(text)}")
        return text
    except ValueError as e:
        print(f"[!] Error in binary conversion: {e}")
        return None

def analyze_binary_stream(ip1, ip2):
    """Turn filtered ping pattern into binary string and analyze variants"""
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
            print(f"    → Original bits: {chunk}")
            decoded = binary_to_text(chunk)
            if decoded:
                print(f"    → Decoded: {decoded}")

            # Flip bits
            flipped = flip_bits(chunk)
            print(f"    → Flipped bits: {flipped}")
            flipped_decoded = binary_to_text(flipped)
            if flipped_decoded:
                print(f"    → Flipped Decoded: {flipped_decoded}")

            # Reverse bits
            reversed_chunk = chunk[::-1]
            print(f"    → Reversed bits: {reversed_chunk}")
            reversed_decoded = binary_to_text(reversed_chunk)
            if reversed_decoded:
                print(f"    → Reversed Decoded: {reversed_decoded}")

            # Flip and reverse
            flipped_reversed = flip_bits(reversed_chunk)
            print(f"    → Flipped & Reversed bits: {flipped_reversed}")
            flipped_reversed_decoded = binary_to_text(flipped_reversed)
            if flipped_reversed_decoded:
                print(f"    → Flipped & Reversed Decoded: {flipped_reversed_decoded}")

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

