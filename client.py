import tkinter as tk
from tkinter import messagebox, scrolledtext
import socket
import threading
import json
from datetime import datetime


class ChatClient:
    def __init__(self, host='localhost', port=12345):
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.client_socket.connect((host, port))

        self.username = None

        self.root = tk.Tk()
        self.root.title("Chat Client")

        self.login_frame = tk.Frame(self.root)
        self.register_frame = tk.Frame(self.root)
        self.chat_frame = tk.Frame(self.root)

        self.build_login_frame()
        self.build_register_frame()
        self.build_chat_frame()

        self.current_chat_user = None
        self.chat_history = {}

        self.receive_thread = threading.Thread(target=self.receive_messages)
        self.receive_thread.start()

        self.show_login_frame()

        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        self.root.mainloop()

    def build_login_frame(self):
        tk.Label(self.login_frame, text="Username").grid(row=0, column=0)
        tk.Label(self.login_frame, text="Password").grid(row=1, column=0)

        self.login_username_entry = tk.Entry(self.login_frame)
        self.login_password_entry = tk.Entry(self.login_frame, show='*')

        self.login_username_entry.grid(row=0, column=1)
        self.login_password_entry.grid(row=1, column=1)

        tk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, column=0, columnspan=2)
        tk.Button(self.login_frame, text="Register", command=self.show_register_frame).grid(row=3, column=0,
                                                                                            columnspan=2)
        tk.Button(self.login_frame, text="Exit", command=self.on_closing).grid(row=4, column=0, columnspan=2)

    def build_register_frame(self):
        tk.Label(self.register_frame, text="Username").grid(row=0, column=0)
        tk.Label(self.register_frame, text="Password").grid(row=1, column=0)

        self.register_username_entry = tk.Entry(self.register_frame)
        self.register_password_entry = tk.Entry(self.register_frame, show='*')

        self.register_username_entry.grid(row=0, column=1)
        self.register_password_entry.grid(row=1, column=1)

        tk.Button(self.register_frame, text="Register", command=self.register).grid(row=2, column=0, columnspan=2)
        tk.Button(self.register_frame, text="Back", command=self.show_login_frame).grid(row=3, column=0, columnspan=2)

    def build_chat_frame(self):
        self.users_listbox = tk.Listbox(self.chat_frame)
        self.users_listbox.grid(row=0, column=0, rowspan=3, sticky=tk.N + tk.S)

        self.users_listbox.bind('<<ListboxSelect>>', self.on_user_select)

        self.chat_title = tk.Label(self.chat_frame, text="", font=("Arial", 14))
        self.chat_title.grid(row=0, column=1, columnspan=2)

        self.chat_text = scrolledtext.ScrolledText(self.chat_frame, state=tk.DISABLED, wrap=tk.WORD)
        self.chat_text.grid(row=1, column=1, columnspan=2, sticky=tk.N + tk.S + tk.E + tk.W)

        self.message_entry = tk.Entry(self.chat_frame)
        self.message_entry.grid(row=2, column=1, sticky=tk.W + tk.E)

        tk.Button(self.chat_frame, text="Send", command=self.send_message).grid(row=2, column=2)
        tk.Button(self.chat_frame, text="Logout", command=self.logout).grid(row=3, column=0, columnspan=3,
                                                                            sticky=tk.W + tk.E)

        self.chat_frame.grid_columnconfigure(1, weight=1)
        self.chat_frame.grid_rowconfigure(1, weight=1)

        self.chat_text.tag_configure("left", justify='left', foreground="blue")
        self.chat_text.tag_configure("right", justify='right', foreground="green")
        self.chat_text.tag_configure("time-left", justify='left', foreground="grey", font=("Arial", 8))
        self.chat_text.tag_configure("time-right", justify='right', foreground="grey", font=("Arial", 8))
        self.chat_text.tag_configure("center", justify='center', foreground="red", font=("Arial", 10, "bold"))

    def show_login_frame(self):
        self.register_frame.pack_forget()
        self.chat_frame.pack_forget()
        self.login_frame.pack()

    def show_register_frame(self):
        self.login_frame.pack_forget()
        self.register_frame.pack()

    def show_chat_frame(self):
        self.login_frame.pack_forget()
        self.register_frame.pack_forget()
        self.chat_frame.pack()

    def login(self):
        username = self.login_username_entry.get()
        password = self.login_password_entry.get()
        if username and password:
            self.send({'action': 'login', 'username': username, 'password': password})
        else:
            messagebox.showerror("Error", "Please enter both username and password")

    def register(self):
        username = self.register_username_entry.get()
        password = self.register_password_entry.get()
        if username and password:
            self.send({'action': 'register', 'username': username, 'password': password})
        else:
            messagebox.showerror("Error", "Please enter both username and password")

    def logout(self):
        self.send({'action': 'logout', 'username': self.username})
        self.username = None
        self.show_login_frame()

    def send_message(self):
        message = self.message_entry.get()
        if message and self.current_chat_user:
            self.send({'action': 'message', 'to': self.current_chat_user, 'message': message})
            self.message_entry.delete(0, tk.END)
            self.update_chat(self.username, message, "outgoing")

    def receive_messages(self):
        while True:
            try:
                message = self.client_socket.recv(1024).decode('utf-8')
                if message:
                    self.process_message(message)
            except:
                break

    def send(self, data):
        try:
            self.client_socket.send(json.dumps(data).encode('utf-8'))
        except:
            messagebox.showerror("Error", "Failed to send message")

    def process_message(self, message):
        data = json.loads(message)
        action = data.get('action')

        if action == 'login':
            self.handle_login_response(data)
        elif action == 'register':
            self.handle_register_response(data)
        elif action == 'message':
            self.handle_incoming_message(data)

    def handle_login_response(self, data):
        status = data.get('status')
        if status == 'success':
            self.username = data.get('username')
            self.update_users_list(data.get('users'))
            self.show_chat_frame()
        else:
            messagebox.showerror("Error", data.get('message'))

    def handle_register_response(self, data):
        status = data.get('status')
        if status == 'success':
            messagebox.showinfo("Success", data.get('message'))
            self.show_login_frame()
        else:
            messagebox.showerror("Error", data.get('message'))

    def handle_incoming_message(self, data):
        from_user = data.get('from')
        message = data.get('message')
        time = data.get('time')

        if from_user not in self.chat_history:
            self.chat_history[from_user] = []

        self.chat_history[from_user].append({'from': from_user, 'message': message, 'time': time})

        if self.current_chat_user == from_user:
            self.update_chat(from_user, message, "incoming")
        else:
            # Handle notification for new message
            pass

    def update_chat(self, user, message, direction):
        self.chat_text.config(state=tk.NORMAL)
        today_date = datetime.now().strftime('%d %B %Y')
        if not self.chat_text.get("1.0", tk.END).strip():
            self.chat_text.insert(tk.END, f"{today_date}\n\n", "center")

        time = datetime.now().strftime('%H:%M')

        if direction == "outgoing":
            self.chat_text.insert(tk.END, f"{self.username} (You): {message}\n", "right")
            self.chat_text.insert(tk.END, f"{time}\n\n", "time-right")
        else:
            self.chat_text.insert(tk.END, f"{user}: {message}\n", "left")
            self.chat_text.insert(tk.END, f"{time}\n\n", "time-left")

        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.yview(tk.END)

    def update_users_list(self, users):
        self.users_listbox.delete(0, tk.END)
        for user in users:
            if user['username'] != self.username:  # Exclude self from list
                status = "Online" if user['online'] else "Offline"
                self.users_listbox.insert(tk.END, f"{user['username']} ({status})")

    def on_user_select(self, event):
        selected_index = self.users_listbox.curselection()
        if selected_index:
            selected_user = self.users_listbox.get(selected_index[0]).split()[0]
            if selected_user != self.username:  # Prevent self-selection
                self.current_chat_user = selected_user
                self.chat_title.config(text=f"Chat with {self.current_chat_user}")
                self.load_chat_history()

    def load_chat_history(self):
        self.chat_text.config(state=tk.NORMAL)
        self.chat_text.delete(1.0, tk.END)
        today_date = datetime.now().strftime('%d %B %Y')
        self.chat_text.insert(tk.END, f"{today_date}\n\n", "center")
        if self.current_chat_user in self.chat_history:
            for entry in self.chat_history[self.current_chat_user]:
                if 'from' in entry and entry['from'] == self.username:
                    self.chat_text.insert(tk.END, f"{self.username} (You): {entry['message']}\n", "right")
                    self.chat_text.insert(tk.END, f"{entry['time']}\n\n", "time-right")
                else:
                    self.chat_text.insert(tk.END, f"{self.current_chat_user}: {entry['message']}\n", "left")
                    self.chat_text.insert(tk.END, f"{entry['time']}\n\n", "time-left")
        self.chat_text.config(state=tk.DISABLED)
        self.chat_text.yview(tk.END)

    def on_closing(self):
        self.client_socket.close()
        self.root.destroy()


if __name__ == "__main__":
    chat_client = ChatClient()
