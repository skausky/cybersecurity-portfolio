import socket
import sys

# CONFIGURATION — edit these before running
IP = "192.0.2.1"   # target IP (RFC 5737 documentation placeholder — replace with actual target)
PORT = 554
USER = "admin"     # username to test (many cameras default to "admin")
PASS = "admin"     # password to test (replace with actual or leave for default-cred check)
TIMEOUT = 2

# A list of the most common RTSP paths for generic/Tuya/Hikvision/Dahua cameras
COMMON_PATHS = [
    "/", "/0", "/1", "/2", "/3", "/4",
    "/live/ch0", "/live/ch1", "/live/ch2",
    "/stream1", "/stream2", "/stream3",
    "/h264/ch1/main/av_stream", "/h264/ch1/sub/av_stream",
    "/cam/realmonitor?channel=1&subtype=0", "/cam/realmonitor?channel=1&subtype=1",
    "/videoMain", "/videoSub",
    "/axis-media/media.amp",
    "/ucast/11",
    "/media/video1", "/media/video2",
    "/ch0_0.h264", "/ch0_1.h264",
    "/11", "/12", "/13",
    "/Streaming/Channels/101", "/Streaming/Channels/102"
]

def check_rtsp(path):
    """Attempts to open a TCP connection and send an RTSP OPTIONS request."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(TIMEOUT)
        sock.connect((IP, PORT))
        
        # RTSP Handshake (OPTIONS request)
        request = f"OPTIONS rtsp://{IP}:{PORT}{path} RTSP/1.0\r\nCSeq: 1\r\n\r\n"
        sock.send(request.encode())
        
        response = sock.recv(1024).decode()
        sock.close()
        
        # If we get a 200 OK or 401 Unauthorized, the path exists!
        # 401 means "I see you, but you need a password," which confirms the stream is there.
        if "200 OK" in response or "401 Unauthorized" in response:
            return True, response.split('\r\n')[0]
            
    except Exception as e:
        pass
    
    return False, None

print(f"--- Scanning {IP} for RTSP Streams ---")
found_streams = []

for path in COMMON_PATHS:
    status, msg = check_rtsp(path)
    if status:
        full_url = f"rtsp://{USER}:{PASS}@{IP}:{PORT}{path}"
        print(f"[FOUND] {path} -> {msg}")
        found_streams.append(full_url)

print("\n--- Summary of Valid Streams ---")
if found_streams:
    for url in found_streams:
        print(url)
else:
    print("No common streams found. Try using Nmap or ONVIF Device Manager.")
