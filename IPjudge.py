import re
from numpy.core.defchararray import endswith
from typing import Pattern


def is_addr_range(uip): #合法的ip地址范围表达式
    x = uip.find('/')
    if x == -1:
        return False
    ip = uip[:int(x)]
    num = uip[int(x) + 1:]
    if not num.isdigit() or judge(ip) == -1: #判断是否合法
        return False
    if judge(ip) == 1:
        if int(num) > 32:
            return False
        ip2 = ip.split('.')
        ip2 = list(map(int, ip2))
        ip2 = [str(format(i, '08b')) for i in ip2]
        str1 = ''.join(ip2)
        str2 = ''
        flag = True
        if int(num) == 32:
            flag = False
        for i in range(int(num), 32):
            if str1[i] != '0':
                flag = False
        if not flag: #处理类似192.168.0.1/24的情况
            str3 = ''
            for i in range(len(ip2) - 1):
                str3 += ip2[i] + '.'
            str3 += ip2[len(ip2) - 1]
            print(str3)
            return True
        else:
            str3 = ''
            for i in range(int(num), 32):#最大和最小地址二进制
                if i == 31:
                    str3 += '1'
                    str2 += '0'
                    break
                str2 += '1'
                str3 += '0'
            str4 = str1[:int(num)] + str2
            str5 = str1[:int(num)] + str3
            binmax = re.findall(r'.{8}', str4)
            binmin = re.findall(r'.{8}', str5)
            ip3, ip4 = [], []
            for i in range(4):#最大和最小地址的十进制
                num1, num2 = 0, 0
                for j in range(8):
                    if binmax[i][j] == '1':
                        num1 += 2 ** (7 - j)
                    if binmin[i][j] == '1':
                        num2 += 2 ** (7 - j)
                ip3.append(str(num1))
                ip4.append(str(num2))
            str4, str5, str6, str7 = '', '', '', ''
            for i in range(3):
                str4 += binmax[i] + '.'
                str5 += binmin[i] + '.'
                str6 += ip3[i] + '.'
                str7 += ip4[i] + '.'
            str4 += binmax[3]
            str5 += binmin[3]
            str6 += ip3[3]
            str7 += ip4[3]
            count = 2 ** (32 - int(num)) - 2
            print("The total number of addresses is:" + str(count))
            print(str5 + " - " + str4)
            print(str7 + " - " + str6)
            return True
    elif judge(ip) == 2:
        if int(num) > 128:
            return False
        ip2 = ipv6_to_all(ip)
        ip2 = ip2.split(':')
        iptmp = []
        for i in range(8):
            iptmp.append(int(ip2[i],16))
        ip2 = [str(format(i, '016b')) for i in iptmp]
        str1 = ''.join(ip2)
        str2 = ''
        flag = True
        if int(num) == 128:
            flag = False
        for i in range(int(num), 128):
            if str1[i] != '0':
                flag = False
        if not flag:
            str3 = ''
            for i in range(len(ip2) - 1):
                str3 += ip2[i] + '.'
            str3 += ip2[len(ip2) - 1]
            print(str3)
            print(ipv6_to_all(ip))
            return True
        else:
            str3 = ''
            for i in range(int(num), 128):
                if i == 127:
                    str3 += '1'
                    str2 += '0'
                    break
                str2 += '1'
                str3 += '0'
            str4 = str1[:int(num)] + str2
            str5 = str1[:int(num)] + str3
            binmax = re.findall(r'.{16}', str4)
            binmin = re.findall(r'.{16}', str5)
            ip3, ip4 = [], []
            for i in range(8):
                num1, num2 = 0, 0
                for j in range(16):
                    if binmax[i][j] == '1':
                        num1 += 2 ** (15 - j)
                    if binmin[i][j] == '1':
                        num2 += 2 ** (15 - j)
                num2 = hex(num2)
                num1 = hex(num1)
                ip3.append(str(num1)[2:])
                ip4.append(str(num2)[2:])
            str4, str5, str6, str7 = '', '', '', ''
            for i in range(7):
                str4 += binmax[i] + ':'
                str5 += binmin[i] + ':'
                str6 += ip3[i] + ':'
                str7 += ip4[i] + ':'
            str4 += binmax[7]
            str5 += binmin[7]
            str6 += ip3[7]
            str7 += ip4[7]
            count = 2 ** (128 - int(num)) - 2
            print("The total number of addresses is:" + str(count))
            print(str5 + " - " + str4)
            print(str7 + " - " + str6)
            return True
    else:
        return False


def judge(uip): #判断是否为合法ip
    ipv4 = re.compile('^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$') #判断ipv4的正则表达式
    ipv61 = re.compile('^([0-9a-fA-F]{1,4}:){7}([0-9a-fA-F]{1,4})$') #判断形如1:1:1:1:1:1:1:1的ipv6正则表达式
    ipv62 = re.compile('^([0-9a-fA-F]{1,4}:){1,6}(:[0-9a-fA-F]{1,4}){1,6}$') #判断形如1::1的ipv6的正则表达式
    ipv63 = re.compile('^([0-9a-fA-F]{1,4}:){1,7}:$') #判断形如1::的ipv6的正则表达式
    ipv64 = re.compile('^(:(:[0-9a-fA-F]{1,4}){1,7})$') #判断形如::1的ipv6的正则表达式
    if ipv4.match(uip):
        return 1
    elif ipv61.match(uip) or ipv62.match(uip) or ipv63.match(uip) or ipv64.match(uip):
        return 2
    else:
        return -1


def ipv4_to_bin(uip): #ipv4转为二进制
    arr1 = uip.split('.')
    arr2 = list(map(int, arr1))
    arr3 = [str(format(i, '08b')) for i in arr2]
    str1 = ''
    for i in range(len(arr3) - 1):
        str1 += arr3[i] + '.'
    str1 += arr3[len(arr3) - 1]
    print(str1)


def ipv6_to_all(uip):#对于零缩法的ipv6地址进行扩展
    arr1 = uip.split(':')
    arr1 = [i for i in arr1 if i != '']
    mVaild = 8 - len(arr1)
    if mVaild != 0:
        if uip.endswith('::'):
            str1 = ''
            for i in range(mVaild):
                str1 += ':0'
            uip = uip.replace('::', str1)
        elif uip.find('::') == 0:
            str1 = ''
            for i in range(mVaild):
                str1 += '0:'
            uip = uip.replace('::', str1)
        else:
            str1 = ':'
            for i in range(mVaild):
                str1 += '0:'
            uip = uip.replace('::', str1)
    return uip


def ipv6_to_bin(uip):#ipv6地址转为二进制表达
    uip = ipv6_to_all(uip)
    arr1 = uip.split(':')
    arr2 = []
    for i in  range(8):
        arr2.append(int(arr1[i],16))
    arr3 = [str(format(i, '016b')) for i in arr2]
    str1 = ''
    for i in range(len(arr3) - 1):
        str1 += arr3[i] + ':'
    str1 += arr3[len(arr3) - 1]
    print(str1)

    # arr2 = list(map(int, arr1))


def IPjudge(uip):
    islegal = judge(uip)
    if islegal == 1:
        ipv4_to_bin(uip)
        print("Your Ip is legal,IPv4!")
    elif islegal == 2:
        ipv6_to_bin(uip)
        print("Your Ip is legal,IPv6!")
    if islegal == -1:
        if not is_addr_range(uip):
            print("Your Ip is illegal!")


if __name__ == "__main__":
    while True:
        uip = input("please input IP:")
        IPjudge(uip)
