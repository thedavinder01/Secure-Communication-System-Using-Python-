# Secure-Communication-System-Using-Python-
It is based on Number System using encryption and Decrytption for Secure Communication System in Battle War .
import tkinter as tk
from tkinter import messagebox
import base64

# === Caesar Cipher Functions ===
def caesar_encrypt(text, shift):
    result = ''
    for char in text:
        if char.isalpha():
            base = 65 if char.isupper() else 97
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# === Base64 Functions ===
def base64_encrypt(msg):
    return base64.b64encode(msg.encode('utf-8')).decode('utf-8')

def base64_decrypt(encrypted_msg):
    try:
        base64_bytes = encrypted_msg.encode('utf-8')
        message_bytes = base64.b64decode(base64_bytes)
        return message_bytes.decode('utf-8')
    except Exception:
        return "❌ Invalid Base64 input."

# === Number System Info ===
def show_number_system_info():
    info = (
        "Number System Overview:\n\n"
        "1. Decimal (Base 10): Uses digits 0-9. Example: 245\n"
        "2. Binary (Base 2): Uses 0 and 1. Example: 10101\n"
        "3. Octal (Base 8): Uses digits 0-7. Example: 0754\n"
        "4. Hexadecimal (Base 16): Uses 0-9 and A-F. Example: 0x1A3F\n\n"
        "Conversions between these systems are key in Digital Electronics and Computer Architecture."
    )
    messagebox.showinfo("Number System", info)

# === GUI Actions ===
def do_encrypt():
    msg = msg_entry.get()
    shift_val = shift_entry.get()
    method = encryption_method.get()

    if not msg:
        messagebox.showwarning("Input Missing", "Please enter a message.")
        return

    if method == "Caesar":
        if not shift_val.isdigit():
            messagebox.showerror("Invalid Shift", "Shift must be a number.")
            return
        encrypted = caesar_encrypt(msg, int(shift_val))
        result.set(encrypted)
        result_label.config(text="🔐 Caesar Encrypted:")
    elif method == "Base64":
        encrypted = base64_encrypt(msg)
        result.set(encrypted)
        result_label.config(text="🔐 Base64 Encrypted:")

def do_decrypt():
    msg = msg_entry.get()
    shift_val = shift_entry.get()
    method = encryption_method.get()

    if not msg:
        messagebox.showwarning("Input Missing", "Please enter a message.")
        return

    if method == "Caesar":
        if not shift_val.isdigit():
            messagebox.showerror("Invalid Shift", "Shift must be a number.")
            return
        decrypted = caesar_decrypt(msg, int(shift_val))
        result.set(decrypted)
        result_label.config(text="🔓 Caesar Decrypted:")
    elif method == "Base64":
        decrypted = base64_decrypt(msg)
        result.set(decrypted)
        result_label.config(text="🔓 Base64 Decrypted:")

def copy_to_clipboard():
    text = result.get()
    if text:
        root.clipboard_clear()
        root.clipboard_append(text)
        messagebox.showinfo("Copied", "Message copied to clipboard.")
    else:
        messagebox.showwarning("Empty", "Nothing to copy.")

# === GUI Setup ===
root = tk.Tk()
root.title("🪖 Soldier Secure Communication System")
root.geometry("700x550")
root.config(bg="#0f1a2b")

# --- Labels and Inputs ---
tk.Label(root, text="Enter Message:", font=("Helvetica", 12), bg="#0f1a2b", fg="white").pack(pady=5)
msg_entry = tk.Entry(root, width=60, font=("Helvetica", 12))
msg_entry.pack(pady=5)

tk.Label(root, text="Enter Shift (For Caesar only):", font=("Helvetica", 12), bg="#0f1a2b", fg="white").pack(pady=5)
shift_entry = tk.Entry(root, width=20, font=("Helvetica", 12))
shift_entry.pack(pady=5)

encryption_method = tk.StringVar(value="Caesar")
tk.Radiobutton(root, text="Caesar Cipher", variable=encryption_method, value="Caesar", font=("Helvetica", 11), bg="#0f1a2b", fg="white").pack()
tk.Radiobutton(root, text="Base64", variable=encryption_method, value="Base64", font=("Helvetica", 11), bg="#0f1a2b", fg="white").pack()

# --- Buttons ---
tk.Button(root, text="🔐 Encrypt", command=do_encrypt, font=("Helvetica", 12), bg="#007ACC", fg="white", width=15).pack(pady=10)
tk.Button(root, text="🔓 Decrypt", command=do_decrypt, font=("Helvetica", 12), bg="#00CC66", fg="white", width=15).pack(pady=5)

# --- Result Display ---
result_label = tk.Label(root, text="Result:", font=("Helvetica", 12, "bold"), bg="#0f1a2b", fg="lightblue")
result_label.pack()

result = tk.StringVar()
tk.Label(root, textvariable=result, font=("Courier", 12), wraplength=600, justify="left", bg="#0f1a2b", fg="lightgreen").pack(pady=10)

# --- Extra Buttons ---
tk.Button(root, text="📋 Copy to Clipboard", command=copy_to_clipboard, font=("Helvetica", 12), bg="#FF9900", fg="black", width=20).pack(pady=5)
tk.Button(root, text="📘 Number System Info", command=show_number_system_info, font=("Helvetica", 12), bg="#9933FF", fg="white", width=20).pack(pady=5)

root.mainloop()
