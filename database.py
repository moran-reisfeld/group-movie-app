__author__ = "moran reisfeld"

import os
import pickle
import threading
import hashlib
import secrets
import time
import string,random


from smtp_mail import generate_security_code, send_signup_code, send_reset_code

data_file = "encryption/data.pkl"
obj_lock = threading.RLock()
pepper_file = "encryption/pepper.secret"

with open(pepper_file, "r", encoding="utf-8") as f:
    PEPPER = f.read().strip()


def hashPassword(password: str):
    salt = secrets.token_hex(16)
    combined = f"{password}{salt}{PEPPER}"
    hash_val = hashlib.sha256(combined.encode()).hexdigest()
    return salt, hash_val


def hashWithSalt(password: str, salt: str):
    combined = f"{password}{salt}{PEPPER}"
    return hashlib.sha256(combined.encode()).hexdigest()


class User:
    def __init__(self, username, password_hash, email="", salt=""):
        self.username = username
        self.password_hash = password_hash
        self.email = email
        self.salt = salt


class PendingUser:
    def __init__(self, username, email, password_hash, salt, verification_code, expires_at):
        self.username = username
        self.email = email
        self.password_hash = password_hash
        self.salt = salt
        self.verification_code = verification_code
        self.expires_at = expires_at


class PasswordReset:
    def __init__(self, email, reset_code, expires_at):
        self.email = email
        self.reset_code = reset_code
        self.expires_at = expires_at

class Group:
    def __init__(self, group_pin, group_name, movie_pin):
        self.group_pin = group_pin
        self.group_name = group_name
        self.movie_pin = movie_pin
        self.members = []

        self.base_movie_time = 0
        self.is_playing = False
        self.last_sync_time = time.time()

        self.stream_clients = set()
        self.stream_lock = threading.Lock()
        self.skip_count = 0

    def __getstate__(self):
        state = self.__dict__.copy()
        del state["stream_lock"]
        del state["stream_clients"]
        return state

    def __setstate__(self, state):
        self.__dict__.update(state)
        self.stream_clients = set()
        self.stream_lock = threading.Lock()

class Movie:
    def __init__(self, movie_id, title, path):
        self.movie_id = movie_id
        self.title = title
        self.path = path



data = {"users": [], "pending_users": [], "password_resets": [],"groups": [],"movies": []}


def emptyData():
    return {"users": [], "pending_users": [], "password_resets": [],"groups": [],"movies": []}


def loadData():
    global data

    if not os.path.exists(data_file):
        data = emptyData()
        return

    try:
        with open(data_file, "rb") as f:
            loaded = pickle.load(f)

        if isinstance(loaded, list):
            data = emptyData()
            data["users"] = loaded
            saveData()
            return

        if isinstance(loaded, dict):
            data = emptyData()
            data["users"] = loaded.get("users", [])
            data["pending_users"] = loaded.get("pending_users", [])
            data["password_resets"] = loaded.get("password_resets", [])
            data["groups"] = loaded.get("groups", [])
            data["movies"] = loaded.get("movies", [])

            for group in data["groups"]:
                if not hasattr(group, "stream_clients"):
                    group.stream_clients = set()
                if not hasattr(group, "stream_lock"):
                    group.stream_lock = threading.Lock()
            return

        data = emptyData()

    except Exception:
        data = emptyData()


def saveData():
    with obj_lock:
        with open(data_file, "wb") as f:
            pickle.dump(data, f)


def getUserByUsername(username):
    with obj_lock:
        for user in data["users"]:
            if user.username == username:
                return user
        return None


def getUserByEmail(email):
    with obj_lock:
        for user in data["users"]:
            if user.email == email:
                return user
        return None


def saveUser(username, password, email):
    with obj_lock:
        salt, password_hash = hashPassword(password)
        user = User(username, password_hash, email, salt)
        data["users"].append(user)
        saveData()


def isUserExist(username):
    return getUserByUsername(username) is not None


def isPasswordOk(username, password):
    user = getUserByUsername(username)
    if not user:
        return False

    calculated_hash = hashWithSalt(password, user.salt)
    return user.password_hash == calculated_hash


def getUserEmail(username):
    user = getUserByUsername(username)
    return user.email if user else None


def cleanupExpired():
    now = time.time()
    changed = False

    with obj_lock:
        before = len(data["pending_users"])
        data["pending_users"] = [p for p in data["pending_users"] if p.expires_at > now]
        if len(data["pending_users"]) != before:
            changed = True

        before = len(data["password_resets"])
        data["password_resets"] = [r for r in data["password_resets"] if r.expires_at > now]
        if len(data["password_resets"]) != before:
            changed = True

        if changed:
            saveData()


def startSignup(username, email, password):
    cleanupExpired()

    with obj_lock:
        if getUserByEmail(email):
            return False, "Email already exists"

        for p in data["pending_users"]:
            if p.email == email:
                return False, "Signup already in progress"

        salt, password_hash = hashPassword(password)
        code = generate_security_code()
        expires_at = time.time() + 300

        pending = PendingUser(username, email, password_hash, salt, code, expires_at)
        data["pending_users"].append(pending)
        saveData()

    threading.Thread(target=send_signup_code, args=(email, code), daemon=True).start()
    return True, "Verification code sent"


def verifySignupCode(email, code):
    cleanupExpired()

    with obj_lock:
        pending = None
        for p in data["pending_users"]:
            if p.email == email:
                pending = p
                break

        if not pending:
            return False, "No active signup"

        if pending.verification_code != code:
            return False, "Invalid code"

        user = User(pending.username, pending.password_hash, pending.email, pending.salt)
        data["users"].append(user)
        data["pending_users"] = [p for p in data["pending_users"] if p.email != email]
        saveData()

    return True, "Signup completed"


def resendSignupCode(email):
    cleanupExpired()

    with obj_lock:
        for p in data["pending_users"]:
            if p.email == email:
                new_code = generate_security_code()
                p.verification_code = new_code
                p.expires_at = time.time() + 300
                saveData()

                threading.Thread(target=send_signup_code, args=(email, new_code), daemon=True).start()
                return True, "New code sent"

        return False, "No active signup"


def startForgotPassword(email):
    cleanupExpired()

    with obj_lock:
        if not getUserByEmail(email):
            return False, "Email not found"

        code = generate_security_code()
        expires_at = time.time() + 300

        for r in data["password_resets"]:
            if r.email == email:
                r.reset_code = code
                r.expires_at = expires_at
                saveData()

                threading.Thread(target=send_reset_code, args=(email, code), daemon=True).start()
                return True, "Reset code sent"

        data["password_resets"].append(PasswordReset(email, code, expires_at))
        saveData()

    threading.Thread(target=send_reset_code, args=(email, code), daemon=True).start()
    return True, "Reset code sent"


def verifyForgotCode(email, code):
    cleanupExpired()

    with obj_lock:
        for r in data["password_resets"]:
            if r.email == email:
                if r.reset_code == code:
                    return True, "Code verified"
                return False, "Invalid code"

        return False, "No active reset request"


def setNewPassword(email, code, new_password):
    cleanupExpired()

    with obj_lock:
        target_reset = None
        for r in data["password_resets"]:
            if r.email == email:
                target_reset = r
                break

        if not target_reset:
            return False, "No active reset request"

        if target_reset.reset_code != code:
            return False, "Invalid code"

        user = getUserByEmail(email)
        if not user:
            data["password_resets"] = [x for x in data["password_resets"] if x.email != email]
            saveData()
            return False, "Email not found"

        salt, password_hash = hashPassword(new_password)
        user.salt = salt
        user.password_hash = password_hash

        data["password_resets"] = [x for x in data["password_resets"] if x.email != email]
        saveData()

    return True, "Password updated"


def resendForgotCode(email):
    cleanupExpired()

    with obj_lock:
        for r in data["password_resets"]:
            if r.email == email:
                code = generate_security_code()
                r.reset_code = code
                r.expires_at = time.time() + 300
                saveData()

                threading.Thread(target=send_reset_code, args=(email, code), daemon=True).start()
                return True, "Reset code resent"

        return False, "No active reset request"



def createGroup(group_name, movie_id,owner):
    with obj_lock:
        group_pin = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(6))

        group = Group(group_pin, group_name, movie_id)
        group.members.append(owner)

        data["groups"].append(group)
        saveData()

    return group_pin

def getGroupByPin(group_pin):
    with obj_lock:
        for group in data["groups"]:
            if group.group_pin == group_pin:
                return group
        return None

def joinGroup(group_pin, username):
    with obj_lock:
        group = getGroupByPin(group_pin)
        if not group:
            return False, "Group not found"

        if username in group.members:
            return False, "Already in group"

        group.members.append(username)
        saveData()

    return True, "Joined group"

def leaveGroup(group_pin, username):
    with obj_lock:
        group = getGroupByPin(group_pin)
        if not group:
            return False, "Group not found"

        if username in group.members:
            group.members.remove(username)
            saveData()

        if not group.members:
            data["groups"].remove(group)

    return True, "Left group"

def getGroupMembers(group_pin):
    group = getGroupByPin(group_pin)
    return group.members if group else None

def update_group_time(group):
    if group.is_playing:
        now_time = time.time()
        group.current_time += int(now_time - group.last_update_time)
        group.last_update_time = now_time

def getMoviePath(movie_id):
    with obj_lock:
        for movie in data["movies"]:
            if movie.movie_id == movie_id: return movie.path

        return None


def addMovie(movie_id, title, path):
    with obj_lock:
        data["movies"].append(Movie(movie_id, title, path))
        saveData()

loadData()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
MOVIES_DIR = os.path.join(BASE_DIR, "movies")

if not any(m.movie_id == "movie1" for m in data["movies"]):
    addMovie("movie1", "1min countdown", os.path.join(MOVIES_DIR, "1_movie.mp4"))
if not any(m.movie_id == "movie2" for m in data["movies"]):
    addMovie("movie2", "knicks highlights", os.path.join(MOVIES_DIR, "knicks_highlights.mp4"))
if not any(m.movie_id == "movie3" for m in data["movies"]):
    addMovie("movie3", "spurs_vs_okc", os.path.join(MOVIES_DIR, "spurs_vs_okc.mp4"))

if not isUserExist("m"):
    saveUser("m", "mm", "m@gmail.com")
if not isUserExist("r"):
    saveUser("r", "rr", "r@gmail.com")