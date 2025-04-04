import re
import socket
from common_ports import ports_and_services as PS

# get_open_ports("209.216.230.240", [440, 445])
# get_open_ports("www.stackoverflow.com", [79, 82])

def urlToIP(url):
    try:
        hosts = socket.gethostbyname(url)
        return hosts
    except socket.herror:
        return url

def ipToURL(ip):
    try:
        hosts = socket.gethostbyaddr(ip)
        for host in hosts:
            if host != [] and host != ip:
                return host
    except socket.herror:
        return ip

def targetIsIP(target):
    try:
        socket.inet_pton(socket.AF_INET, target)
        return True
    except:
        return False

def targetIsURL(target):
    try:
        socket.gethostbyname(target)
        return True
    except:
        return False
    
def targetIsIPFormat(target):
    return bool(re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", target))
    
def initScanner():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    return s

def get_open_ports(target, port_range, verbose = False):
    # target: can be a URL or IP address
    # port_range :a list of two numbers indicating the first and last numbers of the range of ports to check.

# get url and ip from target
    target_url = target_ip = target
    open_ports = []
    open_ports_verbose = [
        f"Open ports for {target_url} ({target_ip}):",
        "PORT     SERVICE",
    ]

    if(targetIsIPFormat(target)):
        if(targetIsIP(target)):
            target_ip = target
            target_url = ipToURL(target)
        else:
            return "Error: Invalid IP address"
    else:
        if(targetIsURL(target)):
            target_url = target
            target_ip = urlToIP(target)
        else:
            return "Error: Invalid hostname"

    for port in range(port_range[0], port_range[1] + 1):
        print(f"Target: {target} Scanning port {port}...")
        s = initScanner()
        connection = s.connect_ex((target, port))
        if connection == 0:
            open_ports.append(port)
            open_ports_verbose.append(f"{port:<4}     {PS[port]}")
        s.close()

    if(verbose):
        if target_ip == target_url:
            open_ports_verbose[0] = f"Open ports for {target}"
        else:
            open_ports_verbose[0] = f"Open ports for {target_url} ({target_ip})"

        return("\n".join(open_ports_verbose))
    else:
        return(open_ports)