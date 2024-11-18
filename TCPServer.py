import csv
import random
import json
import io
import struct
import socket
import threading
import sys


def username_exists(username):
    with open("data.csv", mode="r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == username:
                return True
    return False


def password_matches(username, password):
    with open("data.csv", mode="r", newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row['username'] == username and row['password'] == password:
                return True
    return False


class Message:
    clients = []
    lock = threading.Lock()

    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
        self._recv_buffer = b""
        self._send_buffer = b""
        self._jsonheader_len = None
        self.jsonheader = None
        self.request = None
        self.response_created = False

    def _read(self):
        try:
            # Should be ready to read
            data = self.sock.recv(4096)
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
            try:
                # Should be ready to write
                sent = self.sock.send(self._send_buffer)
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

    def _create_message(self, *, content_bytes, content_type, content_encoding):
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

    def _create_response_json_content(self):
        action = self.request.get("action")
        hostname, port_number = self.addr[0], self.addr[1]
        if action == "list":
            username = self.request.get("value")
            print(f"List: {Message.clients}")

            # Exclude current peer in the list
            filtered_list = list(filter(lambda c: c['username'] != username, Message.clients))

            print(f"mapped : {filtered_list}")

            with open("data.csv", mode="r", newline="") as file:
                reader = csv.DictReader(file)

                for index, (ip, port) in enumerate(filtered_list):
                    for row in reader:
                        if row['port_number'] == str(port):
                            filtered_list[index] = row['username']
                            break

            connected_clients = "\n".join(d['username'] for d in filtered_list)
            content = {"connected_clients": "No Online Peers" if len(connected_clients) == 0 else connected_clients}

        elif action == "register":
            value = self.request.get("value")
            username = value['username']
            if username_exists(value["username"]):
                content = {"register": "Username already exists"}
            else:
                Message.clients.append({"username": username, "sock": self.sock})
                with Message.lock:
                    with open("data.csv", mode="a", newline="") as file:
                        writer = csv.writer(file)
                        writer.writerow([value["username"], value["password"], str(port_number), str(hostname),
                                         "True", "available"])
                content = {"register": "OK", "username": username}

        elif action == "login":
            value = self.request.get("value")
            username, password = value["username"], value["password"]
            if not username_exists(username):
                content = {"login": "Failed, username not found"}
            else:
                if password_matches(username, password):
                    Message.clients.append({"username": username, "sock": self.sock})
                    # Read the data file, port are assigned by the OS, need to update everytime a user logs in
                    rows = []
                    with open("data.csv", mode="r", newline="") as file:
                        reader = csv.DictReader(file)
                        for row in reader:
                            rows.append(row)

                    # Find the row with matching username
                    for row in rows:
                        if row['username'] == username:
                            # update hostname and port
                            row['port_number'] = str(port_number)
                            row['host'] = str(hostname)
                            break

                    with Message.lock:
                        # Update the csv file
                        fieldnames = ["username", "password", "port_number", "host", "visible", "status"]
                        with open("data.csv", mode="w", newline="") as file:
                            writer = csv.DictWriter(file, fieldnames=fieldnames)
                            writer.writeheader()
                            writer.writerows(rows)

                    content = {"login": "Successful Login", "username": username}
                else:
                    content = {"login": "Incorrect password, try again", "username": username}
        elif action == "chat":
            recipient_username = (self.request.get("value"))["recipient_username"]
            recipient_sock = next(
                (client['sock'] for client in Message.clients if client['username'] == recipient_username), None)
            if recipient_sock:
                # peer_server_port = random.sample([12002, 13001],1)[0]
                peer_server_port = random.randint(12000, 13001)
                udp_server = {
                    "content_bytes": self._json_encode({"command": "be a server", "port": peer_server_port}, "utf-8"),
                    "content_type": "text/json",
                    "content_encoding": "utf-8",
                }
                udp_client = {
                    "content_bytes": self._json_encode({"command": "be a client", "port": peer_server_port}, "utf-8"),
                    "content_type": "text/json",
                    "content_encoding": "utf-8",
                }
                message = self._create_message(**udp_server)
                recipient_sock.send(message)
                return udp_client
            else:
                content = {"forward_status": "Recipient not found or unavailable"}

            content = {"message": "sent"}
        else:
            content = {"result": f"Error: invalid action '{action}'."}
        content_encoding = "utf-8"
        response = {
            "content_bytes": self._json_encode(content, content_encoding),
            "content_type": "text/json",
            "content_encoding": content_encoding,
        }
        return response

    def process_request(self):
        content_len = self.jsonheader["content-length"]
        if not len(self._recv_buffer) >= content_len:
            return
        data = self._recv_buffer[:content_len]
        self._recv_buffer = self._recv_buffer[content_len:]
        if self.jsonheader["content-type"] == "text/json":
            encoding = self.jsonheader["content-encoding"]
            self.request = self._json_decode(data, encoding)
            print(f"Received request {self.request!r} from {self.addr}")
        else:
            # Binary or unknown content-type
            self.request = data
            print(f"Received {self.jsonheader['content-type']} request from {self.addr}")

    def _create_response_binary_content(self):
        response = {
            "content_bytes": b"First 10 bytes of request: "
                             + self.request[:10],
            "content_type": "binary/custom-server-binary-type",
            "content_encoding": "binary",
        }
        return response

    def create_response(self):
        if self.jsonheader["content-type"] == "text/json":
            response = self._create_response_json_content()
        else:
            # Binary or unknown content-type
            response = self._create_response_binary_content()
        message = self._create_message(**response)
        self.response_created = True
        self._send_buffer += message
        self.response_created = False  # Reset Flag after send

    def handle_client(self):
        try:
            while True:
                self._read()

                if self._jsonheader_len is None:
                    self.process_protoheader()

                if self._jsonheader_len is not None:
                    if self.jsonheader is None:
                        self.process_jsonheader()

                if self.jsonheader:
                    if self.request is None:
                        self.process_request()
                if self.request:
                    if not self.response_created:
                        self.create_response()
                self._write()

                # Rest the args to default, for new requests
                self.request = None
                self._jsonheader_len = None
                self.jsonheader = None
                self.request = None
                self.response_created = False

        except Exception as e:
            print(f"Error handling client {self.addr}: {e}")
        finally:
            self.close()

    def close(self):
        print(f"Closing connection to {self.addr}")

        # Should update the status to [closed] before closing
        self.sock.close()

        for client in self.clients:
            if client["sock"] == self.sock:
                self.clients.remove(client)
                break  # Exit the loop after removing the client

    def process_protoheader(self):
        hdrlen = 2
        if len(self._recv_buffer) >= hdrlen:
            self._jsonheader_len = struct.unpack(">H", self._recv_buffer[:hdrlen])[0]
            self._recv_buffer = self._recv_buffer[hdrlen:]

    def process_jsonheader(self):
        hdrlen = self._jsonheader_len
        if len(self._recv_buffer) >= hdrlen:
            self.jsonheader = self._json_decode(self._recv_buffer[:hdrlen], "utf-8")
            self._recv_buffer = self._recv_buffer[hdrlen:]
            for reqhdr in ("byteorder", "content-length", "content-type", "content-encoding"):
                if reqhdr not in self.jsonheader:
                    raise ValueError(f"Missing required header '{reqhdr}'.")


def start_server():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serverSocket:
        serverSocket.bind(('localhost', 12345))
        serverSocket.listen(5)
        print('[LISTENING] The server is ready to receive')
        while True:
            clientSocket, address = serverSocket.accept()
            print(f'[NEW CONNECTION] {address} connected to the server')
            message = Message(clientSocket, address)
            client_thread = threading.Thread(target=message.handle_client)
            client_thread.start()


# Start the server
start_server()
