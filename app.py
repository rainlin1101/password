from flask import Flask, render_template, request, redirect, flash, session, url_for
from cryptography.fernet import Fernet
import os
import hashlib

app = Flask(__name__)
app.secret_key = "super_secret_key"

# 预设的哈希主密码（yanli 的 SHA256 哈希值）
HASHED_MASTER_PASSWORD = "dd2539f2491d4bf516ceb1495a757c413350c4e4df67c718cc31fbdd2911cb49"

# 加密密钥文件
KEY_FILE = "secret.key"
PASSWORD_FILE = "passwords.txt"

# 生成密钥并存储
def generate_key():
    key = Fernet.generate_key()
    with open(KEY_FILE, "wb") as key_file:
        key_file.write(key)
    return key

# 加载密钥
def load_key():
    if os.path.exists(KEY_FILE):
        return open(KEY_FILE, "rb").read()
    return generate_key()

# 初始化密钥
key = load_key()
cipher = Fernet(key)

# 加密密码
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()

# 解密密码
def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()

# 哈希主密码（SHA256）
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        entered_password = request.form.get("password", "").strip()
        if hash_password(entered_password) == HASHED_MASTER_PASSWORD:
            session["authenticated"] = True
            return redirect(url_for("home"))
        else:
            flash("主密码错误，请重试。", "danger")

    return render_template("login.html")

@app.route("/home", methods=["GET", "POST"])
def home():
    if "authenticated" not in session:
        return redirect(url_for("login"))

    passwords = {}

    # 处理添加密码
    if request.method == "POST" and "save_password" in request.form:
        service = request.form["service"]
        password = request.form["password"]
        encrypted = encrypt_password(password)
        with open(PASSWORD_FILE, "a") as f:
            f.write(f"{service},{encrypted}\n")
        flash(f"密码已保存！({service})", "success")

    # 处理获取密码
    elif request.method == "POST" and "get_password" in request.form:
        service = request.form["service"]
        if os.path.exists(PASSWORD_FILE):
            with open(PASSWORD_FILE, "r") as f:
                for line in f.readlines():
                    stored_service, stored_encrypted = line.strip().split(",")
                    if service == stored_service:
                        decrypted_password = decrypt_password(stored_encrypted)
                        flash(f"【{service}】的密码是：{decrypted_password}", "info")
                        break
                else:
                    flash(f"未找到【{service}】的密码", "danger")

    return render_template("index.html")

@app.route("/logout")
def logout():
    session.pop("authenticated", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)