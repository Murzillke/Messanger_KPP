import socket
import threading
import json
from datetime import datetime


class ChatServer:
    def __init__(self, host='localhost', port=12345):
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.bind((host, port))
        self.server.listen(5)
        print(f"Server started on {host}:{port}")

        self.clients = {}
        self.load_users()
        self.load_chat_history()

    def load_users(self):
        try:
            with open("users.json", "r") as file:
                self.users = json.load(file)
        except FileNotFoundError:
            self.users = {}

    def save_users(self):
        with open("users.json", "w") as file:
            json.dump(self.users, file)

    def load_chat_history(self):
        try:
            with open("chat_history.json", "r") as file:
                self.chat_history = json.load(file)
        except FileNotFoundError:
            self.chat_history = {}

    def save_chat_history(self):
        with open("chat_history.json", "w") as file:
            json.dump(self.chat_history, file)

    def handle_client(self, client_socket, client_address):
        while True:
            try:
                message = client_socket.recv(1024).decode('utf-8')
                if not message:
                    break
                self.process_message(client_socket, message)
            except:
                break

        print(f"Connection closed: {client_address}")
        self.remove_client(client_socket)
        client_socket.close()

    def process_message(self, client_socket, message):
        try:
            data = json.loads(message)
            action = data.get('action')

            if action == 'register':
                self.register_user(client_socket, data)
            elif action == 'login':
                self.login_user(client_socket, data)
            elif action == 'message':
                self.send_message(client_socket, data)
            elif action == 'logout':
                self.logout_user(client_socket, data)
        except json.JSONDecodeError:
            pass

    def register_user(self, client_socket, data):
        username = data.get('username')
        password = data.get('password')

        if username in self.users:
            response = {'action': 'register', 'status': 'error', 'message': 'User already exists'}
        else:
            self.users[username] = {'password': password, 'online': False}
            self.save_users()
            response = {'action': 'register', 'status': 'success', 'message': 'Registration successful'}

        client_socket.send(json.dumps(response).encode('utf-8'))

    def login_user(self, client_socket, data):
        username = data.get('username')
        password = data.get('password')

        if username in self.users and self.users[username]['password'] == password:
            self.users[username]['online'] = True
            self.clients[client_socket] = username
            self.save_users()
            response = {'action': 'login', 'status': 'success', 'username': username, 'message': 'Login successful',
                        'users': self.get_users_list()}
        else:
            response = {'action': 'login', 'status': 'error', 'message': 'Invalid credentials'}

        client_socket.send(json.dumps(response).encode('utf-8'))

    def send_message(self, client_socket, data):
        from_user = self.clients.get(client_socket)
        to_user = data.get('to')
        message = data.get('message')
        timestamp = datetime.now().strftime('%H:%M')

        if from_user and to_user and message:
            if to_user not in self.chat_history:
                self.chat_history[to_user] = []
            if from_user not in self.chat_history:
                self.chat_history[from_user] = []

            self.chat_history[to_user].append({'from': from_user, 'message': message, 'time': timestamp})
            self.chat_history[from_user].append({'to': to_user, 'message': message, 'time': timestamp})

            self.save_chat_history()

            response = {'action': 'message', 'from': from_user, 'message': message, 'time': timestamp}
            for client, user in self.clients.items():
                if user == to_user:
                    client.send(json.dumps(response).encode('utf-8'))
                elif user == from_user:
                    client.send(
                        json.dumps({'action': 'message', 'to': to_user, 'message': message, 'time': timestamp}).encode(
                            'utf-8'))

    def logout_user(self, client_socket, data):
        username = self.clients.get(client_socket)
        if username:
            self.users[username]['online'] = False
            self.save_users()
            self.remove_client(client_socket)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            del self.clients[client_socket]

    def get_users_list(self):
        users_list = []
        for user, details in self.users.items():
            users_list.append({'username': user, 'online': details['online']})
        return users_list

    def start(self):
        while True:
            client_socket, client_address = self.server.accept()
            print(f"Connection established: {client_address}")
            threading.Thread(target=self.handle_client, args=(client_socket, client_address)).start()


if __name__ == "__main__":
    chat_server = ChatServer()
    chat_server.start()
