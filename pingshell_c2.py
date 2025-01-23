import subprocess
import paramiko

# Define your IP addresses and credentials
credentials = {
    "420.69.96.021": {"username": "username", "password": "password"},
    "420.69.96.022": {"username": "username", "password": "password"},
    "420.69.96.023": {"username": "username", "password": "password"}
}

def read_binary_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            binary_str = file.read().replace(" ", "")
            return binary_str
    except FileNotFoundError:
        print(f"File not found: {file_path}")
        return None

def send_ping(ip_address):
    try:
        if ip_address in credentials:
            username = credentials[ip_address]["username"]
            password = credentials[ip_address]["password"]
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                ssh_client.connect(ip_address, username=username, password=password)
                with open('address_register.txt', 'r') as file:
                    addresses = file.read().splitlines()
                    for address in addresses:
                        stdin, stdout, stderr = ssh_client.exec_command(f"ping -c 1 {address}")
                        ping_output = stdout.read().decode()
                        print(f"Ping result for {address}:\n{ping_output}")
            except paramiko.AuthenticationException:
                print(f"Authentication failed for {ip_address}")
            except paramiko.SSHException as e:
                print(f"SSH error for {ip_address}: {e}")
            except Exception as e:
                print(f"Error connecting to {ip_address}: {e}")
            finally:
                ssh_client.close()
        else:
            print(f"No credentials found for IP address: {ip_address}")
    except KeyError:
        print(f"No credentials found for IP address: {ip_address}")


def string_to_binary(input_string):
    return ' '.join(format(ord(char), '08b') for char in input_string)

def write_binary_to_file(binary_string, file_path):
    try:
        with open(file_path, 'w') as file:
            file.write(binary_string)
    except IOError as e:
        print(f"Error writing to file {file_path}: {e}")

def main():
    user_input = input("Send command: ")
    
    binary_string = string_to_binary(user_input)
    
    file_path = "binary_string.txt"
    
    write_binary_to_file(binary_string, file_path)
    
    binary_str = read_binary_from_file(file_path)

    if binary_str:
        for char in binary_str:
            if char == "1":
                send_ping("420.69.96.021")
            elif char == "0":
                send_ping("420.69.96.022")
    
    send_ping("420.69.96.023")

if __name__ == "__main__":
    main()

