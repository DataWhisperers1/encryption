import os
import zipfile
from tkinter import Tk, filedialog, Button, Label, Entry, StringVar, Checkbutton, IntVar
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Signature import pkcs1_15
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from datetime import datetime

# توليد مفتاح AES من كلمة المرور
def get_key(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()

# تشفير الملف باستخدام AES
def encrypt_file_aes(file_name, key):
    chunk_size = 64 * 1024
    output_file = file_name + ".enc"
    
    with open(file_name, 'rb') as infile:
        with open(output_file, 'wb') as outfile:
            cipher = AES.new(key, AES.MODE_EAX)
            outfile.write(cipher.nonce)

            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk = pad(chunk, AES.block_size)
                
                ciphertext = cipher.encrypt(chunk)
                outfile.write(ciphertext)

def decrypt_file_aes(file_name_enc, key):
    chunk_size = 64 * 1024
    output_file = file_name_enc.replace(".enc", "")
    
    with open(file_name_enc, 'rb') as infile:
        nonce = infile.read(16)
        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)

        with open(output_file, 'wb') as outfile:
            while True:
                chunk = infile.read(chunk_size)
                if len(chunk) == 0:
                    break
                
                decrypted_chunk = cipher.decrypt(chunk)
                outfile.write(unpad(decrypted_chunk, AES.block_size))

# ضغط الملفات
def compress_file(file_name):
    zip_file_name = file_name + '.zip'
    with zipfile.ZipFile(zip_file_name, 'w') as zipf:
        zipf.write(file_name, os.path.basename(file_name))
    return zip_file_name

def decompress_file(zip_file_name):
    with zipfile.ZipFile(zip_file_name, 'r') as zipf:
        zipf.extractall()
    return zip_file_name.replace('.zip', '')

# توقيع الملفات
def sign_file(file_name, private_key_file):
    key = RSA.import_key(open(private_key_file).read())
    hasher = SHA256.new(open(file_name, 'rb').read())
    signature = pkcs1_15.new(key).sign(hasher)
    
    with open(file_name + ".sig", "wb") as sig_file:
        sig_file.write(signature)

def verify_signature(file_name, signature_file, public_key_file):
    key = RSA.import_key(open(public_key_file).read())
    hasher = SHA256.new(open(file_name, 'rb').read())
    
    with open(signature_file, 'rb') as sig_file:
        signature = sig_file.read()

    try:
        pkcs1_15.new(key).verify(hasher, signature)
        print("تم التحقق من صحة التوقيع!")
    except (ValueError, TypeError):
        print("التوقيع غير صحيح!")

# توليد مفاتيح RSA
def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("تم توليد مفاتيح RSA وحفظها!")

# السجل
def log_operation(operation, file_name):
    with open("operation_log.txt", "a") as log_file:
        log_file.write(f"{datetime.now()}: {operation} - {file_name}\n")

# اختيار الملف أو المجلد
def select_file_or_folder(action):
    path = filedialog.askdirectory() if folder_var.get() else filedialog.askopenfilename()
    password = password_var.get()
    
    if not password:
        label_result.config(text="يرجى إدخال كلمة مرور!")
        return
    
    key = get_key(password)
    
    if action == "encrypt":
        if compress_var.get():
            path = compress_file(path)
        if folder_var.get():
            encrypt_folder(path, key)
        else:
            encrypt_file_aes(path, key)
        log_operation("تشفير", path)
        label_result.config(text="تم التشفير بنجاح!")
    
    elif action == "decrypt":
        if folder_var.get():
            decrypt_folder(path, key)
        else:
            decrypt_file_aes(path, key)
            if compress_var.get():
                path = decompress_file(path)
        log_operation("فك التشفير", path)
        label_result.config(text="تم فك التشفير بنجاح!")

# واجهة المستخدم الرسومية
root = Tk()
root.title("أداة التشفير وفك التشفير")

folder_var = IntVar()
compress_var = IntVar()

label_password = Label(root, text="أدخل كلمة المرور:")
label_password.pack()
password_var = StringVar()
entry_password = Entry(root, textvariable=password_var, show="*")
entry_password.pack()

label_folder = Label(root, text="اختر مجلد؟")
label_folder.pack()
check_folder = Checkbutton(root, variable=folder_var)
check_folder.pack()

label_compress = Label(root, text="ضغط الملفات قبل التشفير؟")
label_compress.pack()
check_compress = Checkbutton(root, variable=compress_var)
check_compress.pack()

button_encrypt = Button(root, text="تشفير", command=lambda: select_file_or_folder("encrypt"))
button_encrypt.pack()

button_decrypt = Button(root, text="فك التشفير", command=lambda: select_file_or_folder("decrypt"))
button_decrypt.pack()

button_generate_rsa = Button(root, text="توليد مفاتيح RSA", command=generate_rsa_keys)
button_generate_rsa.pack()

label_result = Label(root, text="")
label_result.pack()

root.mainloop()