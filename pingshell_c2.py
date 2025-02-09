import subprocess
import paramiko
import time

# Define your IP addresses and credentials
credentials = {
    "420.69.96.421": {"username": "username", "password": "password"},
    "420.69.96.422": {"username": "username", "password": "password"},
    "420.69.96.423": {"username": "username", "password": "password"}
}

def read_binary_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            binary_str = file.read().replace(" ", "")
            print(f"[DEBUG] Read binary string from file: {binary_str}")
            return binary_str
    except FileNotFoundError:
        print(f"[ERROR] File not found: {file_path}")
        return None

def send_ping(ip_address):
    print(f"[DEBUG] Attempting to connect to {ip_address} via SSH")
    if ip_address in credentials:
        username = credentials[ip_address]["username"]
        password = credentials[ip_address]["password"]
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
            ssh_client.connect(ip_address, username=username, password=password)
            print(f"[SUCCESS] Connected to {ip_address}")
            
            with open('address_register.txt', 'r') as file:
                addresses = file.read().splitlines()
                for address in addresses:
                    print(f"[DEBUG] Sending ping command to {address}")
                    stdin, stdout, stderr = ssh_client.exec_command(f"ping -c 1 {address}")
                    ping_output = stdout.read().decode()
                    error_output = stderr.read().decode()
                    print(f"[OUTPUT] Ping result for {address}: {ping_output}")
                    if error_output:
                        print(f"[ERROR] Ping command error: {error_output}")
        except paramiko.AuthenticationException:
            print(f"[ERROR] Authentication failed for {ip_address}")
        except paramiko.SSHException as e:
            print(f"[ERROR] SSH error for {ip_address}: {e}")
        except Exception as e:
            print(f"[ERROR] Error connecting to {ip_address}: {e}")
        finally:
            ssh_client.close()
            print(f"[DEBUG] Closed SSH connection to {ip_address}")
    else:
        print(f"[ERROR] No credentials found for IP address: {ip_address}")

def string_to_binary(input_string):
    binary = ''.join(format(ord(char), '08b') for char in input_string)
    print(f"[DEBUG] Converted string to binary: {binary}")
    return binary

def write_binary_to_file(binary_string, file_path):
    try:
        with open(file_path, 'w') as file:
            file.write(binary_string)
            print(f"[DEBUG] Written binary string to {file_path}")
    except IOError as e:
        print(f"[ERROR] Error writing to file {file_path}: {e}")

def main():
    user_input = input("Send command: ")
    print(f"[DEBUG] User input: {user_input}")
    
    binary_string = string_to_binary(user_input)
    file_path = "binary_string.txt"
    write_binary_to_file(binary_string, file_path)
    
    binary_str = read_binary_from_file(file_path)
    print(binary_str)

    if binary_str:
        for char in binary_str:
            if char == "1":
                send_ping("420.69.96.421")
                time.sleep(1)
            elif char == "0":
                send_ping("420.69.96.422")
                time.sleep(1)
    
    send_ping("420.69.96.423")

if __name__ == "__main__":
    main()


