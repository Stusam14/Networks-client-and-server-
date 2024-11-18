import random
import socket
import json
import struct
import sys
import io
import hashlib

class Message:
    def __init__(self, sock, addr, request):
        self.sock = sock
        self.addr = addr
        self.request = request
        self._recv_buffer = b""
        self._send_buffer = b""
        self._request_queued = False
        self._jsonheader_len = None
        self.jsonheader = None
        self.response = None

    def _read(self):
        try:
            # Should be ready to read
            data = None
            # From the TCP Connection
            if self.sock.type == socket.SOCK_STREAM:
                data = self.sock.recv(4096)
            # For UDP Connections
            elif self.sock.type == socket.SOCK_DGRAM:
                data, peerAddress = self.sock.recvfrom(4096)

        except BlockingIOError:
            # Resource temporarily unavailable (errno EWOULDBLOCK)
            pass
        else:
            if data:
                self._recv_buffer += data
            else:
                raise RuntimeError("Peer closed.")

    def _write(self):
        if self._send_buffer:
            # print(f"Sending {self._send_buffer!r} to {self.addr}")
            try:
                # Should be ready to write
                sent = 0
                if self.sock.type == socket.SOCK_STREAM:
                    sent = self.sock.send(self._send_buffer)
                elif self.sock.type == socket.SOCK_DGRAM:
                    sent = self.sock.sendto(self._send_buffer, self.addr)

            except BlockingIOError:
                # Resource temporarily unavailable (errno EWOULDBLOCK)
                pass
            else:
                self._send_buffer = self._send_buffer[sent:]

    def _json_encode(self, obj, encoding):
        return json.dumps(obj, ensure_ascii=False).encode(encoding)

    def _json_decode(self, json_bytes, encoding):
        tiow = io.TextIOWrapper(
            io.BytesIO(json_bytes), encoding=encoding, newline=""
        )
        obj = json.load(tiow)
        tiow.close()
        return obj

    def _create_message(
            self, *, content_bytes, content_type, content_encoding
    ):
        jsonheader = {
            "byteorder": sys.byteorder,
            "content-type": content_type,
            "content-encoding": content_encoding,
            "content-length": len(content_bytes),
        }
        jsonheader_bytes = self._json_encode(jsonheader, "utf-8")
        message_hdr = struct.pack(">H", len(jsonheader_bytes))
        message = message_hdr + jsonheader_bytes + content_bytes
        return message

    def send(self):
        # successful login or register
        if not self._request_queued:
            self.queue_request()

        self._write()

        if self._request_queued:
            if not self._send_buffer:
                # We're done writing.
                pass  # No need to set any event here

    def receive(self):
        self._read()

        if self._jsonheader_len is None:
            self.process_protoheader()

        if self._jsonheader_len is not None:
            if self.jsonheader is None:
                self.process_jsonheader()

        if self.jsonheader:
            if self.response is None:
                self.process_response()

    def close(self):
        print(f"Closing connection to {self.addr}")
        try:
            self.sock.close()
        except OSError as e:
            print(f"Error: socket.close() exception for {self.addr}: {e!r}")
        finally:
            # Delete reference to socket object for garbage collection
            self.sock = None

    def queue_request(self):
        content = self.request["content"]
        content_type = self.request["type"]
        content_encoding = self.request["encoding"]
        if content_type == "text/json":
            req = {
                "content_bytes": self._json_encode(content, content_encoding),
                "content_type": content_type,
                "content_encoding": content_encoding,
            }
        else:
            req = {
                "content_bytes": content,
                "content_type": content_type,
                "content_encoding": content_encoding,
            }
        message = self._create_message(**req)
        self._send_buffer += message
        self._request_queued = True

    def process_protoheader(self):
        hdrlen = 2
        if len(self._recv_buffer) >= hdrlen:
            self._jsonheader_len = struct.unpack(
                ">H", self._recv_buffer[:hdrlen]
            )[0]
            self._recv_buffer = self._recv_buffer[hdrlen:]

    def process_jsonheader(self):
        hdrlen = self._jsonheader_len
        if len(self._recv_buffer) >= hdrlen:
            self.jsonheader = self._json_decode(
                self._recv_buffer[:hdrlen], "utf-8"
            )
            self._recv_buffer = self._recv_buffer[hdrlen:]
            for reqhdr in (
                    "byteorder",
                    "content-length",
                    "content-type",
                    "content-encoding",
            ):
                if reqhdr not in self.jsonheader:
                    raise ValueError(f"Missing required header '{reqhdr}'.")

    def process_response(self):
        content_len = self.jsonheader["content-length"]
        if not len(self._recv_buffer) >= content_len:
            return
        data = self._recv_buffer[:content_len]
        self._recv_buffer = self._recv_buffer[content_len:]
        if self.jsonheader["content-type"] == "text/json":
            encoding = self.jsonheader["content-encoding"]
            self.response = self._json_decode(data, encoding)
            # print(f"Received response {self.response!r} from {self.addr}")
        else:
            # Binary or unknown content-type
            self.response = data
            print(
                f"Received {self.jsonheader['content-type']} "
                f"response from {self.addr}"
            )


def register_request():
    username = input("Username: ")
    password_1 = input("Enter Password: ").strip()
    password_2 = input("Confirm Password: ").strip()

    while password_1 != password_2:
        print("Make both passwords matches")
        password_1 = input("Enter Password: ")
        password_2 = input("Confirm Password: ")

    value = {
        "username": username,
        "password": hashlib.sha3_256(password_1.encode()).hexdigest()
    }
    request = create_request("register", value)
    return request


def handle_request(sock, addr, req) -> Message:
    msg = Message(sock, addr, req)
    msg.send()
    msg.receive()
    return msg


def login_request():
    username = input("Username: ")
    pass_word = input("Password: ")
    value = {
        "username": username,
        "password": hashlib.sha3_256(pass_word.encode()).hexdigest()
    }

    request = create_request("login", value)
    return request


def chat_request(peers_list):
    recipient_username = input("Enter Recipient Name from the list: ").strip()

    while recipient_username not in peers_list:
        recipient_username = input("Opps Recipient not in the list, try again: ")

    value = {
        "recipient_username": recipient_username
    }

    return create_request("chat", value)


def list_peers(sock, addr, username):
    request = create_request("list", username)
    msg = handle_request(sock, addr, request)
    print(msg.response["connected_clients"])
    return msg.response["connected_clients"]


def user_login(sock, addr):
    peers = []  # Initialize peers list
    username = ''

    while True:
        message = handle_request(sock, addr, login_request())
        response = message.response.get('login')

        if response == "Successful Login":
            print("________Welcome_______")
            username = message.response['username']
            peers = list_peers(sock, addr, username)
            return peers, username  # Return peers and username upon successful login
        elif response == "Failed, username not found":
            have_account = input("Have an account (Y/N): ").strip().upper()
            if have_account == 'Y':
                continue  # Retry login
            elif have_account == 'N':
                user_registration(sock, addr)
                # After registration, attempt login again
                continue
            else:
                print("Invalid input. Please enter 'Y' or 'N'.")
        elif response == "Incorrect password, try again":
            print("Incorrect password. Please try again.")
        else:
            print("Unexpected response from the server. Please try again.")

    return peers, username  # Return peers and username (even if login fails)


def user_registration(sock, addr):
    message = handle_request(sock, addr, register_request())
    res = message.response['register']

    peers = []
    username = ''
    if res == 'OK':
        print("________Welcome_______")
        print("Connected Peers: ")
        username = message.response['username']
        list_peers(sock, addr, username)

    elif res == 'Username already exists':
        print("User already has account under this username, please login")
        handle_request(sock, addr, login_request())

    return peers, username


def handle_peer_communication(msg, server_port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as peerSocket:
        hostname = '127.0.0.1'
        if msg == "be a client":
            print("UDP Client Peer")
            while True:
                send = input(">:")
                peerSocket.sendto(send.encode(), (hostname, server_port))
                replyMessage, peerServerAddress = peerSocket.recvfrom(2048)
                print(replyMessage.decode())
        elif msg == "be a server":
            print("UDP Server Peer")
            peerSocket.bind((hostname, server_port))
            while True:
                message, peerClientAddress = peerSocket.recvfrom(2048)
                print(message.decode())
                send = input("<:")
                peerSocket.sendto(send.encode(), peerClientAddress)

def user_command(username,clientSocket,address,peers):
    command = input("[list or chat]: ").strip().lower()
    if command == "list":
        peers = list_peers(clientSocket, address, username)

    elif command == "chat":
        request = chat_request(peers)
        msg = handle_request(clientSocket, address, request)

        print(msg.response)
        instruction = msg.response['command']
        port = msg.response['port']
        handle_peer_communication(instruction, port)

    elif command == "receive":
        msg = Message(clientSocket, address, "")
        msg.receive()
        print(msg.response)

        instruction = msg.response['command']
        port = msg.response['port']
        handle_peer_communication(instruction, port)


def start_client(address):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as clientSocket:
        clientSocket.connect(address)

        action = input("Enter action [register, login] : ").strip().lower()
        # Send and receive messages

        # Register
        if action == "register":
            peers, username = user_registration(clientSocket, address)
            while 1:
                # list or chat
                user_command(username,clientSocket,address,peers);


            # Login
        elif action == "login":
            peers, username = user_login(clientSocket, address)
            while 1:
                # list or chat
                user_command(username,clientSocket,address,peers);

                # chat with [name]


def create_request(action, value):
    if action in ["register", "login", "list", "chat", "search"]:
        return dict(
            type="text/json",
            encoding="utf-8",
            content=dict(action=action, value=value)
        )
    else:
        return dict(
            type="binary/custom-client-binary-type",
            encoding="binary",
            content=bytes(action + value, encoding="utf-8"),
        )


# Example usage:
if __name__ == "__main__":
    server_address = ("localhost", 12345)
    start_client(server_address)
