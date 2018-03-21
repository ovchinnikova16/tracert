import argparse
import subprocess
import re
import socket
from urllib.request import urlopen


def get_ip_info(ip):
    try:
        url = urlopen('http://www.iana.org/whois?q=' + ip).read().decode()
        whois_type = find_substr(r'[Ww]hois:(.+)', url)
        sock = socket.socket()
        sock.connect((whois_type, 43))
        ip = (ip +'\n').encode()
        sock.send(ip)
        reply = get_reply(sock)
        return reply
    except Exception:
        return ''


def get_reply(sock):
    reply = b''
    while True:
        part = sock.recv(1024)
        if part:
            reply += part
        else:
            break
    return reply.decode()


def find_as(ip_info):
    return find_substr(r"[Oo]rigin[A]?[S]?:(.+)", ip_info)

def find_country(ip_info):
    return find_substr(r'[Cc]ountry:(.+)', ip_info)


def find_substr(regexp, string):
    try:
        substr = re.search(regexp, string).group(1).strip()
        return substr
    except Exception:
        return ''


def get_domain():
    parser = argparse.ArgumentParser()
    parser.add_argument('domain', help="domain or ip for tracert")
    return parser.parse_args().domain


def main():
    domain = get_domain()
    process = subprocess.Popen('tracert ' + domain, stdout=subprocess.PIPE)
    data = process.communicate()
    reply = data[0].decode('cp866').split('\n')
    reply = reply[2:]
    for line in reply:
        ip_strings = re.search(r"(\d{1,3}\.){3}\d{1,3}", line)
        if ip_strings:
            ip = ip_strings.group(0)
            ip_info = get_ip_info(ip)

            print('IP {0:20}  AS {1:15} Country {2}'
                  .format(ip, find_as(ip_info), find_country(ip_info)))


if __name__ == '__main__':
    main()
 #протоколы кроме icmp
 #два разных пути
