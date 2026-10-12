import socket

def check_rtsp_vulnerability(target, port):
    try:
        # Create a socket object
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        
        # Connect to the target
        sock.connect((target, port))
        
        # Send an RTSP OPTIONS request
        request = b"OPTIONS / RTSP/1.0\r\nCSeq: 1\r\nUser-Agent: VLC/3.0.14 LibVLC/3.0.14\r\nAccept: */*\r\n\r\n"
        sock.sendall(request)
        
        # Receive the response
        response = sock.recv(4096)
        
        # Check for the presence of the CVE-2020-8815 indicator
        if b"Invalid session" in response:
            print("Vulnerability CVE-2020-8815 detected")
        else:
            print("No known vulnerabilities detected")
        
        # Close the socket
        sock.close()
    except socket.timeout:
        print("Connection timed out")
    except Exception as e:
        print(f"An error occurred: {e}")

# Check the target
check_rtsp_vulnerability('127.0.0.1', 5000)