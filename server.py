__author__ = "moran reisfeld"

import base64,time

from encryption.key_exchange import (
    dh_server_generate,
    dh_derive_aes_key,
)

import socket,threading
import database

from encryption.GCM_functions import SecureSession
from AsyncMessages import AsyncMessages
AsyncMsgs = AsyncMessages()



HOST = "0.0.0.0"
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

def get_current_time(group):
    if group.is_playing:
        now = time.time()
        elapsed = int(now - group.last_sync_time)
        return group.base_movie_time + elapsed
    return group.base_movie_time

class ClientThread(threading.Thread):
    def __init__(self, sock):
        threading.Thread.__init__(self)
        self.sock = sock
        self.username = None
        self.session = None
        self.sock.settimeout(0.5)
        AsyncMsgs.add_new_socket(self.sock)

    def run(self):
        self.running = True
        while self.running:
            try:
                if self.session is None:
                    data = recv(self.sock)
                else:
                    data = recv_secure(self.sock, self.session)

                if data:
                    self.handle_msg(data)
            except socket.timeout:
                self.send_pending_messages()
            except OSError:
                break

    def do_dh_handshake(self):
        dh_private, params_b64, server_pub_b64 = dh_server_generate()
        send(self.sock, f"DH_PARAMS|{params_b64}|{server_pub_b64}")

        msg = recv(self.sock)
        if not msg.startswith("DH_PUBLIC|"):
            send(self.sock, "ERROR|expected DH_PUBLIC")
            return False

        aes_key = dh_derive_aes_key(dh_private, msg.split("|", 1)[1])
        self.session = SecureSession(aes_key)
        return True

    def handle_msg(self, data):
        if data.startswith("KEY_METHOD|"):
            method = data.split("|", 1)[1].strip().upper()

            if method not in "DH":
                send(self.sock, f"ERROR|method not supported")
                return

            send(self.sock, "OK|supported")
            self.do_dh_handshake()
            return

        elif data.startswith("KEY|"):
            key_b64 = data.split("|", 1)[1]
            key = base64.b64decode(key_b64)
            self.session = SecureSession(key)
            return

        parts = data.split("|")
        code = parts[0]

        if code == "SIGNUP_START":
            if len(parts) != 4:
                send_secure(self.sock, self.session, "ERROR|please fill all fields")
                return

            user, password, email = parts[1], parts[2], parts[3]

            if database.isUserExist(user):
                send_secure(self.sock, self.session, "ERROR|username already exists")
                return

            success, message = database.startSignup(user, email, password)

            if success:
                send_secure(self.sock, self.session, "INFO|" + message)
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        elif code == "LOGIN":
            if len(parts) != 3:
                send_secure(self.sock, self.session, "ERROR|please fill all fields")
                return

            user, password = parts[1], parts[2]

            if database.isPasswordOk(user, password):
                self.username = user
                AsyncMsgs.sock_by_user[user] = self.sock
                send_secure(self.sock, self.session, "OK")
            else:
                send_secure(self.sock, self.session, "ERROR|invalid username or password")
            return

        elif code == "CREATE_GROUP":
            group_name , movie_id , username  = parts[1], parts[2], parts[3]

            if not group_name or len(group_name) > 30:
                send_secure(self.sock,self.session, "ERROR|Empty group name or too long")
                return

            if not movie_id:
                send_secure(self.sock,self.session,"ERROR|no movie selected")
                return

            group_pin = database.createGroup(group_name, movie_id,username)
            send_secure(self.sock, self.session, f"OK|{group_pin}")

            group = database.getGroupByPin(group_pin)
            current_time = get_current_time(group)

            AsyncMsgs.put_msg_by_user(f"PAUSE|{current_time}", username)

        elif code == "JOIN_GROUP":
            group_pin,username = parts[1],parts[2]
            if not group_pin or len(group_pin)!=6:
                send_secure(self.sock, self.session, "ERROR|Empty group pin or incorrect length")
                return

            success, err_msg = database.joinGroup(group_pin, username)
            if not success:
                send_secure(self.sock, self.session, f"ERROR|{err_msg}")
                return

            send_secure(self.sock, self.session, f"OK|{group_pin}")

            group = database.getGroupByPin(group_pin)
            current_time = get_current_time(group)

            if group.is_playing:
                msg = f"PLAY|{current_time}"
            else:
                msg = f"PAUSE|{current_time}"

            AsyncMsgs.put_msg_by_user(msg, username)

        elif code == "LEAVE_GROUP":
            group_pin, username = parts[1], parts[2]

            success, msg = database.leaveGroup(group_pin, username)

            if not success:
                send_secure(self.sock, self.session, f"ERROR|{msg}")
                return

            send_secure(self.sock, self.session, "OK")

        elif code in ["PLAY", "PAUSE", "FORWARD_10", "BACKWORD_10"]:
            group_pin = parts[1]
            group = database.getGroupByPin(group_pin)

            if not group:
                return

            current_time = get_current_time(group)

            if code == "PLAY":
                group.is_playing = True
                group.last_sync_time = time.time()

            elif code == "PAUSE":
                group.is_playing = False
                group.base_movie_time = current_time
                group.last_sync_time = time.time()

            elif code == "FORWARD_10":
                current_time += 10
                group.base_movie_time = current_time
                group.last_sync_time = time.time()

            elif code == "BACKWORD_10":
                current_time = max(0, current_time - 10)
                group.base_movie_time = current_time
                group.last_sync_time = time.time()


            members = database.getGroupMembers(group_pin)
            for user in members:
                sock = AsyncMsgs.sock_by_user.get(user)

                if sock: AsyncMsgs.put_msg_by_user(f"{code}|{current_time}", user)

        elif code == "START_STREAM":
            pass

        elif code == "END_STREAM":
            pass

        elif code == "LOGOUT":
            send_secure(self.sock, self.session, "INFO|logged out")
            self.disconnect()
            return

        elif code == "SIGNUP_VERIFY":
            if len(parts) != 3:
                send_secure(self.sock, self.session, "ERROR|invalid request")
                return

            email, verification_code = parts[1], parts[2]

            success, message = database.verifySignupCode(email, verification_code)

            if success:
                send_secure(self.sock, self.session, "OK")
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        elif code == "SIGNUP_RESEND":
            if len(parts) != 2:
                send_secure(self.sock, self.session, "ERROR|invalid request")
                return

            email = parts[1]

            success, message = database.resendSignupCode(email)

            if success:
                send_secure(self.sock, self.session, "INFO|" + message)
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        elif code == "FORGOT_START":
            if len(parts) != 2:
                send_secure(self.sock, self.session, "ERROR|invalid request")
                return

            email = parts[1]
            success, message = database.startForgotPassword(email)

            if success:
                send_secure(self.sock, self.session, "INFO|" + message)
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        elif code == "FORGOT_VERIFY":
            if len(parts) != 3:
                send_secure(self.sock, self.session, "ERROR|invalid request")
                return

            email, reset_code = parts[1], parts[2]
            success, message = database.verifyForgotCode(email, reset_code)

            if success:
                send_secure(self.sock, self.session, "OK")
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        elif code == "FORGOT_RESEND":
            if len(parts) != 2:
                send_secure(self.sock, self.session, "ERROR|invalid request")
                return

            email = parts[1]
            success, message = database.resendForgotCode(email)

            if success:
                send_secure(self.sock, self.session, "INFO|" + message)
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        elif code == "FORGOT_SET_PASSWORD":
            if len(parts) != 4:
                send_secure(self.sock, self.session, "ERROR|invalid request")
                return

            email, reset_code, new_password = parts[1], parts[2], parts[3]
            success, message = database.setNewPassword(email, reset_code, new_password)

            if success:
                send_secure(self.sock, self.session, "OK")
            else:
                send_secure(self.sock, self.session, "ERROR|" + message)
            return

        else: send_secure(self.sock, self.session, "ERROR|unknown command")

    def send_pending_messages(self):
        msgs = AsyncMsgs.get_async_messages_to_send(self.sock)
        for msg in msgs:
            if self.session is not None:
                send_secure(self.sock, self.session, msg)

    def disconnect(self):
        self.running = False
        AsyncMsgs.delete_socket(self.sock)
        try:
            self.sock.close()
        except:
            pass
        self.username = None

def main():
    server = socket.socket()
    server.bind((HOST, PORT))
    server.listen(20)

    try:
        while True:
            sock, addr = server.accept()
            ClientThread(sock).start()
    finally:
        server.close()

if __name__ == "__main__":
    main()