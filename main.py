import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import hashlib

class FileSharingApp:
    def __init__(self, master):
        self.master = master
        self.master.title("File Sharing App")

        # Initialize socket for file transfer
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(('localhost', 12345))
        self.server_socket.listen(5)
        self.client_socket = None

        # GUI elements
        self.upload_button = tk.Button(master, text="Upload File", command=self.upload_file)
        self.upload_button.pack()

        self.download_button = tk.Button(master, text="Download File", command=self.download_file)
        self.download_button.pack()

        self.authenticate_button = tk.Button(master, text="Authenticate", command=self.authenticate)
        self.authenticate_button.pack()

        self.file_browser_button = tk.Button(master, text="Browse Files", command=self.browse_files)
        self.file_browser_button.pack()

        self.exit_button = tk.Button(master, text="Exit", command=self.exit_app)
        self.exit_button.pack()

        # Authentication
        self.logged_in = False

    def upload_file(self):
        if not self.logged_in:
            self.show_error("Please authenticate first.")
            return

        file_path = filedialog.askopenfilename()
        if file_path:
            try:
                # Implement file upload functionality here
                pass
            except Exception as e:
                self.show_error("Error uploading file: " + str(e))

    def download_file(self):
        if not self.logged_in:
            self.show_error("Please authenticate first.")
            return

        file_name = input("Enter file name to download: ")
        if file_name:
            try:
                # Implement file download functionality here
                pass
            except Exception as e:
                self.show_error("Error downloading file: " + str(e))

    def authenticate(self):
        username = input("Enter username: ")
        password = input("Enter password: ")
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        # Simulating authentication with hardcoded credentials
        if username == "user" and hashed_password == "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8":
            self.logged_in = True
            self.show_message("Authentication successful.")
            self.client_socket, _ = self.server_socket.accept()
        else:
            self.show_error("Authentication failed.")

    def browse_files(self):
        if not self.logged_in:
            self.show_error("Please authenticate first.")
            return

        # Implement file browsing functionality here
        pass

    def exit_app(self):
        if self.client_socket:
            self.client_socket.close()
        self.server_socket.close()
        self.master.destroy()

    def show_message(self, message):
        messagebox.showinfo("Message", message)

    def show_error(self, message):
        messagebox.showerror("Error", message)

def main():
    root = tk.Tk()
    app = FileSharingApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
