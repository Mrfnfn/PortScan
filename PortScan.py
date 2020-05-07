import socket
import threading
import time
import os
import getopt
import sys
from banner.banner import banner_3
socket.setdefaulttimeout(3)#全局延迟

ports = ['20','22','80','445','3389']

def socket_scan(ip,PORT,estart,eend):
    try:
        
        s = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        r = s.connect_ex((ip,PORT))#连接地址
        if(r==0):#访问成功显示信息
            text=f'''\033[1;32m[+] {ip}:{PORT} [PORT OPEN]\033[0m'''
            print(text)
            try:
                cmd  = os.getcwd()
                file_name = (str(ip))
                t = time.strftime('%Y-%m-%d %H:%M:%S')
                with open(f"./logs/{format(file_name)}.log","a+") as file:
                    file.seek(1)
                    file.write('Time:')
                    file.write(str(t))
                    file.write('\t')
                    file.write(str(ip))
                    file.write(':')
                    file.write(str(PORT))
                    file.write('[OPEN]')
                    file.write('\n')
                    file.close()
                    #fileopen(str(ip)+".log")
            except:
                print('OPEN ERROR')
            

        s.close()#断开连接
        
    except:
        print('PORT Scan abnormal!  [201]')


def IP_thread(join,estart,eend):
    
    try:
        t = time.time() 
        for i in range(estart,eend+1):
            threading._start_new_thread(socket_scan,(join,int(i),int(estart),int(eend)))
            
            time.sleep(0.003)

    except KeyboardInterrupt:
        print('process terminated by user![202]'.title())
    except:
        print('thread startup failure![203]'.title())


if __name__ == '__main__':
    #调用进程
    try:
        print(banner_3)
        try:
            json = sys.argv[1]
            estart = sys.argv[2]
            eend = sys.argv[3]

            ip_list=[]
            addrs = socket.getaddrinfo(json,None)
            for i in addrs:
                if i[4][0] not in ip_list:
                    ip_list.append(i[4][0])
            if len(ip_list) == 1:
                print(f'\033[1;33m[+]正在扫描地址:{json}\n[+]CDN检测:目标不存在CDN\033[0m')
                for ips in ip_list:
                    print(f'\033[1;33m[+]IP:{ips}\033[0m')
            else:
                print(f'\033[1;33m[+]正在扫描地址:{json}\033[0m\n\033[1;31m[-]CDN检测:目标存在CDN\033[0m')
                for ips in ip_list:
                    print(f'\033[1;33m[+]IP:{ips}\033[0m')

            IP_thread(json,int(estart),int(eend))
        except:
            print('python PortScan.py IP Startport Endport')
            print('python PortScan.py 192.168.1.1 0 60000')
        


    except KeyboardInterrupt:
        print('process terminated by user![204]'.title())

    
