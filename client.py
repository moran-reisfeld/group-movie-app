__author__ = "moran reisfeld"

import socket
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog
import time

from encryption.GCM_functions import SecureSession

from encryption.key_exchange import (
    dh_client_generate,
    dh_derive_aes_key,
)

HOST = "127.0.0.1"
PORT = 8080
SIZE = 8


def send(sock, msg):
    data = msg.encode()
    sock.sendall(str(len(data)).zfill(SIZE).encode() + data)

def recv(sock):
    size = sock.recv(SIZE)
    if not size:
        return ""
    return sock.recv(int(size.decode())).decode()


def send_secure(sock, session, msg):
    encrypted = session.encrypt(msg.encode())
    sock.sendall(str(len(encrypted)).zfill(SIZE).encode() + encrypted)

def recv_secure(sock, session):
    size = sock.recv(SIZE)
    if not size:
        return ""
    encrypted_data = sock.recv(int(size.decode()))
    return session.decrypt(encrypted_data).decode()


class App:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.connect((HOST, PORT))
        self.sock.settimeout(0.5)

        self.session = None
        self.username = None
        self.group = None

        self.root = tk.Tk()
        self.root.title("client")
        self.root.geometry("500x500")

        self.container = tk.Frame(self.root)
        self.container.pack(fill="both", expand=True)

        self.frames = {}
        for F in (LoginFrame, SignupFrame,ForgotFrame,LobbyFrame,CreateGroupFrame,JoinGroupFrame,GroupMovieFrame):
            frame = F(self.container, self)
            self.frames[F.__name__] = frame
            frame.grid(row=0, column=0, sticky="nsew")

        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        self.start_key_exchange()
        self.show_frame("LoginFrame")

    def run(self):
        self.root.mainloop()

    def show_frame(self, name):
        self.frames[name].tkraise()

    def validation(self, username, password, mode="login", confirm_password=None, email=None):
        if mode == "login":
            if not username or not password:
                return False, "please fill all fields"
            return True, ""

        if mode == "signup":
            if not username or not password or not confirm_password or not email:
                return False, "please fill all fields"
            if password != confirm_password:
                return False, "passwords do not match"
            return True, ""

        return False, "invalid mode"

    def start_key_exchange(self):
        try:
            send(self.sock, f"KEY_METHOD|DH")
            response = recv(self.sock)

            if not response.startswith("OK"):
                raise RuntimeError(response)

            response = recv(self.sock)

            if not response.startswith("DH_PARAMS|"):
                raise RuntimeError(response)

            _, params_b64, server_pub_b64 = response.split("|", 2)

            my_private, my_pub_b64 = dh_client_generate(params_b64)
            send(self.sock, f"DH_PUBLIC|{my_pub_b64}")

            aes_key = dh_derive_aes_key(my_private, server_pub_b64)
            self.session = SecureSession(aes_key)

        except Exception as e:
            print("Key exchange failed:", e)


class LoginFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        frame = tk.Frame(self, padx=20, pady=20)
        frame.pack()

        tk.Label(frame, text="login", font=("Arial", 16, "bold")).pack(pady=10)

        user_frame = tk.Frame(frame)
        user_frame.pack(fill="x", pady=5)
        tk.Label(user_frame, text="username:", anchor="w", width=12).pack(side="left")
        self.user = tk.Entry(user_frame, width=30)
        self.user.pack(side="left")

        password_frame = tk.Frame(frame)
        password_frame.pack(fill="x", pady=5)
        tk.Label(password_frame, text="password:", anchor="w", width=12).pack(side="left")
        self.password = tk.Entry(password_frame, show="*", width=30)
        self.password.pack(side="left")

        btn_frame = tk.Frame(frame, pady=10)
        btn_frame.pack()
        tk.Button(btn_frame, text="login", width=12, command=self.login).pack(side="left", padx=5)
        tk.Button(
            btn_frame,
            text="sign up",
            width=12,
            command=lambda: self.app.show_frame("SignupFrame"),
        ).pack(side="left", padx=5)

        tk.Button(
            btn_frame,
            text="forgot password",
            width=15,
            command=lambda: self.app.show_frame("ForgotFrame"),
        ).pack(side="left", padx=5)

        self.user.bind("<Return>", lambda _e: self.login())
        self.password.bind("<Return>", lambda _e: self.login())

    def login(self):
        username = self.user.get().strip()
        password = self.password.get()

        ok, msg = self.app.validation(username, password, mode="login")
        if not ok:
            messagebox.showerror("error", msg)
            return

        send_secure(self.app.sock, self.app.session, f"LOGIN|{username}|{password}")
        response = recv_secure(self.app.sock,self.app.session)

        if response == "OK":
            self.app.username = username
            self.app.show_frame("LobbyFrame")
            return

        if response.startswith("ERROR|"):
            messagebox.showerror("error", response.split("|", 1)[1])
            return

        messagebox.showerror("error", "login failed")


class SignupFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        frame = tk.Frame(self, padx=20, pady=20)
        frame.pack()

        tk.Label(frame, text="sign up", font=("Arial", 16, "bold")).pack(pady=10)

        u_frame = tk.Frame(frame)
        u_frame.pack(fill="x", pady=5)
        tk.Label(u_frame, text="username:", anchor="w", width=15).pack(side="left")
        self.s_user = tk.Entry(u_frame, width=30)
        self.s_user.pack(side="left")

        p_frame = tk.Frame(frame)
        p_frame.pack(fill="x", pady=5)
        tk.Label(p_frame, text="password:", anchor="w", width=15).pack(side="left")
        self.s_password = tk.Entry(p_frame, show="*", width=30)
        self.s_password.pack(side="left")

        p2_frame = tk.Frame(frame)
        p2_frame.pack(fill="x", pady=5)
        tk.Label(p2_frame, text="confirm password:", anchor="w", width=15).pack(side="left")
        self.s_password2 = tk.Entry(p2_frame, show="*", width=30)
        self.s_password2.pack(side="left")

        e_frame = tk.Frame(frame)
        e_frame.pack(fill="x", pady=5)
        tk.Label(e_frame, text="email:", anchor="w", width=15).pack(side="left")
        self.s_email = tk.Entry(e_frame, width=30)
        self.s_email.pack(side="left")

        btn_frame = tk.Frame(frame, pady=10)
        btn_frame.pack()
        tk.Button(btn_frame, text="sign up", width=12, command=self.signup).pack(side="left", padx=5)
        tk.Button(
            btn_frame,
            text="back",
            width=12,
            command=lambda: self.app.show_frame("LoginFrame"),
        ).pack(side="left", padx=5)

        self.s_user.bind("<Return>", lambda _e: self.signup())
        self.s_password.bind("<Return>", lambda _e: self.signup())
        self.s_password2.bind("<Return>", lambda _e: self.signup())
        self.s_email.bind("<Return>", lambda _e: self.signup())

    def signup(self):
        username = self.s_user.get().strip()
        password = self.s_password.get()
        confirm_password = self.s_password2.get()
        email = self.s_email.get().strip()

        ok, msg = self.app.validation(username,password,mode="signup",
            confirm_password=confirm_password,email=email,)

        if not ok:
            messagebox.showerror("error", msg)
            return

        send_secure(self.app.sock, self.app.session,f"SIGNUP_START|{username}|{password}|{email}")
        res = recv_secure(self.app.sock,self.app.session)

        if res.startswith("ERROR|"):
            messagebox.showerror("error", res.split("|", 1)[1])
            return

        if res.startswith("INFO|"):
            messagebox.showinfo("info", res.split("|", 1)[1])

        while True:
            code = simpledialog.askstring("verify signup",
                f"Enter the code sent to {email}.\nPress Cancel to stop.")

            if code is None:
                return

            code = code.strip()
            if not code:
                messagebox.showerror("error", "please enter the code")
                continue

            send_secure(self.app.sock, self.app.session, f"SIGNUP_VERIFY|{email}|{code}")
            vres = recv_secure(self.app.sock, self.app.session)

            if vres == "OK":
                messagebox.showinfo("success", "registered successfully")
                self.app.show_frame("LoginFrame")
                return

            if vres.startswith("ERROR|"):
                err = vres.split("|", 1)[1]

                retry = messagebox.askyesno("error", err + "\ntry again?")
                if retry: continue

                resend = messagebox.askyesno("resend", "resend code?")
                if resend:
                    send_secure(self.app.sock, self.app.session, f"SIGNUP_RESEND|{email}")
                    r2 = recv_secure(self.app.sock, self.app.session)

                    if r2.startswith("INFO|"):
                        messagebox.showinfo("info", r2.split("|", 1)[1])
                    elif r2.startswith("ERROR|"):
                        messagebox.showerror("error", r2.split("|", 1)[1])
                    else:
                        messagebox.showinfo("info", "code sent")
                    continue

                return

            messagebox.showerror("error", "verify failed")
            return


class ForgotFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        frame = tk.Frame(self, padx=20, pady=20)
        frame.pack()

        tk.Label(frame, text="forgot password", font=("Arial", 16, "bold")).pack(pady=10)

        e_frame = tk.Frame(frame)
        e_frame.pack(fill="x", pady=5)
        tk.Label(e_frame, text="email:", anchor="w", width=12).pack(side="left")
        self.email_entry = tk.Entry(e_frame, width=30)
        self.email_entry.pack(side="left")

        btn_frame = tk.Frame(frame, pady=10)
        btn_frame.pack()

        tk.Button(btn_frame, text="send code", width=12, command=self.start).pack(side="left", padx=5)
        tk.Button(btn_frame, text="back", width=12, command=lambda: self.app.show_frame("LoginFrame")).pack(side="left", padx=5)

        self.email_entry.bind("<Return>", lambda _e: self.start())

    def start(self):
        email = self.email_entry.get().strip()
        if not email:
            messagebox.showerror("error", "please enter email")
            return

        send_secure(self.app.sock, self.app.session, f"FORGOT_START|{email}")
        res = recv_secure(self.app.sock, self.app.session)

        if res.startswith("ERROR|"):
            messagebox.showerror("error", res.split("|", 1)[1])
            return

        if res.startswith("INFO|"):
            messagebox.showinfo("info", res.split("|", 1)[1])

        while True:
            code = simpledialog.askstring("verify reset", f"Enter the code sent to {email}.\nPress Cancel to stop.")
            if code is None:
                return

            code = code.strip()
            if not code:
                messagebox.showerror("error", "please enter the code")
                continue

            send_secure(self.app.sock, self.app.session, f"FORGOT_VERIFY|{email}|{code}")
            vres = recv_secure(self.app.sock, self.app.session)

            if vres == "OK":
                break

            if vres.startswith("ERROR|"):
                err = vres.split("|", 1)[1]
                retry = messagebox.askyesno("error", err + "\nTry again?")
                if retry:
                    continue

                resend = messagebox.askyesno("resend", "Resend code?")
                if resend:
                    send_secure(self.app.sock, self.app.session, f"FORGOT_RESEND|{email}")
                    r2 = recv_secure(self.app.sock, self.app.session)
                    if r2.startswith("INFO|"):
                        messagebox.showinfo("info", r2.split("|", 1)[1])
                    elif r2.startswith("ERROR|"):
                        messagebox.showerror("error", r2.split("|", 1)[1])
                    else:
                        messagebox.showinfo("info", "code sent")
                    continue

                return

            messagebox.showerror("error", "verify failed")
            return

        while True:
            new_pass = simpledialog.askstring("new password", "Enter new password.\nPress Cancel to stop.", show="*")
            if new_pass is None:
                return
            if not new_pass:
                messagebox.showerror("error", "password cant be empty")
                continue

            send_secure(self.app.sock, self.app.session, f"FORGOT_SET_PASSWORD|{email}|{code}|{new_pass}")
            pres = recv_secure(self.app.sock, self.app.session)

            if pres == "OK":
                messagebox.showinfo("success", "password updated")
                self.app.show_frame("LoginFrame")
                return

            if pres.startswith("ERROR|"):
                messagebox.showerror("error", pres.split("|", 1)[1])
                return

            messagebox.showerror("error", "failed to update password")
            return


# class ChatFrame(tk.Frame):
#     def __init__(self, parent, app):
#         super().__init__(parent)
#         self.app = app
#
#         frame = tk.Frame(self, padx=10, pady=10)
#         frame.pack(fill="both", expand=True)
#
#         self.header = tk.Label(frame, font=("Arial", 12, "bold"))
#         self.header.pack(pady=5)
#
#         tk.Label(frame, text="messages sent and received:").pack(anchor="w")
#         self.chat = tk.Text(frame, height=12, state="disabled")
#         self.chat.pack(fill="both", expand=True, pady=5)
#
#         tk.Label(frame, text="server errors or info:").pack(anchor="w")
#         self.errors = tk.Text(frame, height=4, fg="red", state="disabled")
#         self.errors.pack(fill="x", pady=5)
#
#         send_frame = tk.Frame(frame, pady=5)
#         send_frame.pack(fill="x")
#
#         tk.Label(send_frame, text="send format: username: message").pack(anchor="w")
#         self.msg_entry = tk.Entry(send_frame, width=50)
#         self.msg_entry.pack(side="left", fill="x", expand=True)
#         self.msg_entry.bind("<Return>", lambda _e: self.send_msg())
#         tk.Button(send_frame, text="send", width=8, command=self.send_msg).pack(side="left", padx=5)
#
#         tk.Button(frame, text="logout", width=10, command=self.logout).pack(anchor="e", pady=5)
#
#
#     def refresh_header(self):
#         self.header.config(text=f"messages, logged in as: {self.app.username}")
#
#     def add_message(self, msg):
#         self.chat.config(state="normal")
#         self.chat.insert(tk.END, msg + "\n")
#         self.chat.see(tk.END)
#         self.chat.config(state="disabled")
#
#     def add_error(self, error):
#         self.errors.config(state="normal")
#         self.errors.insert(tk.END, error + "\n")
#         self.errors.see(tk.END)
#         self.errors.config(state="disabled")
#
#     def send_msg(self):
#         text = self.msg_entry.get().strip()
#
#         if not text:
#             self.add_error("message cant be empty")
#             return
#
#         if ":" not in text:
#             self.add_error("need to look like: username:message")
#             return
#
#         to_user, msg = [p.strip() for p in text.split(":", 1)]
#         if not to_user or not msg:
#             self.add_error("you need both username and message")
#             return
#
#         send_secure(self.app.sock, self.app.session, f"MSG|{to_user}|{msg}")
#         self.add_message(f"You to {to_user}: {msg}")
#         self.msg_entry.delete(0, tk.END)
#
#     def logout(self):
#         try:
#             send_secure(self.app.sock, self.app.session, "LOGOUT")
#         except Exception:
#             pass
#
#         self.app.username = None
#         self.app.show_frame("LoginFrame")
#
#     def check_msgs(self):
#         try:
#             while True:
#                 try:
#                     res = recv_secure(self.app.sock, self.app.session)
#                 except socket.timeout:
#                     break
#
#                 if not res:
#                     break
#
#                 if res.startswith("MSG|"):
#                     self.add_message(res[4:])
#                 elif res.startswith("ERROR|"):
#                     self.add_error(res[6:])
#                 elif res.startswith("INFO|"):
#                     self.add_error(res[5:])
#         except OSError:
#             pass
#
#         self.after(500, self.check_msgs)


class LobbyFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        tk.Label(self, text="Lobby", font=("Arial", 24)).pack(pady=20)

        tk.Button(
            self,
            text="Create Group",
            command=lambda: app.show_frame("CreateGroupFrame")
        ).pack(pady=10)

        tk.Button(
            self,
            text="Join Group",
            command=lambda: app.show_frame("JoinGroupFrame")
        ).pack(pady=10)

        tk.Button(
            self,
            text="Logout",
            command=self.logout
        ).pack(pady=10)

    def logout(self):
        try:
            send_secure(self.app.sock, self.app.session, "LOGOUT")
        except Exception:
            pass

        self.app.username = None
        self.app.group = None
        self.app.show_frame("LoginFrame")


class CreateGroupFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        tk.Label(self, text="Create Group", font=("Arial", 20)).pack(pady=20)

        tk.Label(self, text="Group Name").pack()
        self.group_name_entry = tk.Entry(self)
        self.group_name_entry.pack(pady=5)

        tk.Label(self, text="Select Movie").pack()

        self.movie_listbox = tk.Listbox(self)
        self.movie_listbox.pack(pady=5)

        # temporary mock movies
        movies = ["Movie A", "Movie B", "Movie C"]
        for movie in movies:
            self.movie_listbox.insert(tk.END, movie)

        tk.Button(
            self,text="Create",command=self.create_group).pack(pady=10)

        tk.Button(
            self,
            text="Back",
            command=lambda: app.show_frame("LobbyFrame")
        ).pack()

    def create_group(self):
        group_name = self.group_name_entry.get()

        selected = self.movie_listbox.curselection()

        movie = self.movie_listbox.get(selected[0])

        print(f"Creating group: {group_name}, Movie: {movie}")

        msg = f"CREATE_GROUP|{group_name}|{movie}|{self.app.username}"
        send_secure(self.app.sock, self.app.session,msg)

        res = recv_secure(self.app.sock,self.app.session)
        parts = res.split("|",1)

        if parts[0] == "OK":
            self.app.group = parts[1]
            self.app.frames["GroupMovieFrame"].on_join()
            self.app.show_frame("GroupMovieFrame")

        elif parts[0] == "ERROR":
            messagebox.showerror("error", parts[1])

class JoinGroupFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        tk.Label(self, text="Join Group", font=("Arial", 20)).pack(pady=20)

        tk.Label(self, text="Enter Group Pin").pack()
        self.pin_entry = tk.Entry(self)
        self.pin_entry.pack(pady=5)

        tk.Button(
            self,
            text="Join",
            command=self.join_group
        ).pack(pady=10)

        tk.Button(
            self,
            text="Back",
            command=lambda: app.show_frame("LobbyFrame")
        ).pack()

    def join_group(self):
        group_pin  = self.pin_entry.get().strip()

        msg = f"JOIN_GROUP|{group_pin}|{self.app.username}"
        send_secure(self.app.sock, self.app.session,msg)

        res = recv_secure(self.app.sock,self.app.session)
        parts = res.split("|", 2)

        if parts[0] == "OK":
            self.app.group = parts[1]
            self.app.frames["GroupMovieFrame"].on_join()
            self.app.show_frame("GroupMovieFrame")

        elif parts[0] == "ERROR":
            messagebox.showerror("error", parts[1])

class GroupMovieFrame(tk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app

        self.is_in_group = False
        self.base_movie_time = 0
        self.last_sync_time = time.time()
        self.is_playing = False

        top_bar = tk.Frame(self)
        top_bar.pack(fill="x", pady=5)

        self.title_label = tk.Label(top_bar, text="Group Movie", font=("Arial", 16))
        self.title_label.pack(side="left", padx=10)
        self.info_label = tk.Label(top_bar, text="none",font=("Arial", 16))
        self.info_label.pack(side="right", padx=10)

        # ===== Video Placeholder =====
        self.video_frame = tk.Frame(self, width=800, height=400)
        self.video_frame.pack(pady=20)

        self.video_label = tk.Label(self.video_frame, text="Video Area")
        self.video_label.place(relx=0.5, rely=0.5, anchor="center")
        # =============================

        controls = tk.Frame(self)
        controls.pack(pady=10)

        tk.Button(controls, text="<<", width=8, command=lambda: self.send_controls("BACKWORD_10")).pack(side="left", padx=5)
        tk.Button(controls, text="Play", width=8, command=lambda: self.send_controls("PLAY")).pack(side="left", padx=5)
        tk.Button(controls, text="Pause", width=8, command=lambda: self.send_controls("PAUSE")).pack(side="left", padx=5)
        tk.Button(controls, text=">>", width=8, command=lambda: self.send_controls("FORWARD_10")).pack(side="left", padx=5)

        self.leave_btn = tk.Button(self, text="Leave Group",command=self.leave_group)
        self.leave_btn.pack(pady=10)

    def on_join(self):
        username = self.app.username
        group_pin = self.app.group
        self.info_label.config(text=f"{username} | Group: {group_pin}")

        if not self.is_in_group:
            self.is_in_group = True

            self.movie_thread = threading.Thread(target=self.movie_loop, daemon=True).start()
            self.control_thread = threading.Thread(target=self.control_loop, daemon=True).start()


    def send_controls(self,code):
        group_pin = self.app.group
        if code in ["PLAY","PAUSE","FORWARD_10","BACKWORD_10"]:
            send_secure(self.app.sock,self.app.session,f"{code}|{group_pin}")

    def movie_loop(self):
        while self.is_in_group:
            # load data / manage buffer
            print(self.get_current_time())
            time.sleep(0.1)

    def control_loop(self):
        while self.is_in_group:
            try:
                msg = recv_secure(self.app.sock, self.app.session)
                if msg:
                    code,current_movie_time  = msg.split("|",1)
                    current_movie_time = int(current_movie_time)
                    now = time.time()

                    if code == "PLAY":
                        self.base_movie_time = current_movie_time
                        self.last_sync_time = now
                        self.is_playing = True

                    elif code == "PAUSE":
                        self.base_movie_time = current_movie_time
                        self.last_sync_time = now
                        self.is_playing = False

                    elif code == "FORWARD_10":
                        self.base_movie_time = current_movie_time
                        self.last_sync_time = now

                    elif code == "BACKWORD_10":
                        self.base_movie_time = current_movie_time
                        self.last_sync_time = now

            except socket.timeout:
                continue

    def leave_group(self):
        group_pin = self.app.group

        send_secure(self.app.sock, self.app.session, f"LEAVE_GROUP|{group_pin}|{self.app.username}")

        self.is_in_group = False
        self.is_playing = False

        self.base_movie_time = 0

        self.app.group = None
        self.app.show_frame("LobbyFrame")

    def get_current_time(self):
        if self.is_playing:
            now = time.time()
            elapsed = int(now - self.last_sync_time)
            return self.base_movie_time + elapsed

        return self.base_movie_time







if __name__ == "__main__":
    App().run()