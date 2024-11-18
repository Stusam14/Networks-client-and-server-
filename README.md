# TCP Chat Application

This project implements a simple TCP-based chat application, allowing users to register, log in, and communicate via a server. The system also supports peer-to-peer communication.

# Features

* User Registration and Login: Secure registration and authentication using hashed passwords.
* List Online Users: View currently connected peers.
* Peer-to-Peer Chat: Initiate direct communication with other users.
* How to Use
* Start the Server:

# Run the server script:
bash
python TCPServer.py
Start a Client:

# Run the client script:
bash
python Client.py
Follow the prompts to register, log in, list peers, or chat.

# File Overview
TCPServer.py: The server handles user registration, login, and routing for peer communication.
Client.py: The client interacts with the server for registration, login, and peer-to-peer chatting.

# Requirements
Python 3.8 or later
Ensure a data.csv file exists with the following headers:
lua
username,password,port_number,host,visible,status