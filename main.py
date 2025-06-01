## @file
#  @brief Generator kluczy RSA z szyfrowaniem klucza prywatnego przy użyciu PIN-u.
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import secrets

## @brief Generuje parę kluczy RSA i zapisuje je na dysku.
#  @param pin PIN wprowadzony przez użytkownika.
#  @param save_path Ścieżka do folderu gdzie zapisane zostaną klucze.
#  @details Klucz prywatny jest szyfrowany algorytmem AES (CFB) z użyciem klucza pochodzącego z PBKDF2HMAC. Klucz publiczny jest zapisywany w formacie PEM.
def generate_keys(pin, save_path):
    # generowanie klucza RSA, 65537 <- liczba pierwsza,
    # 2^n + 1: 3, 5, 17, 257, 65537
    priv_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    pub_key = priv_key.public_key()

    # klicz AES z pinu
    #wartosc losowa
    random_number = secrets.token_bytes(16)
    # tworzymy instancje klasy PBKDF2HMAC z wykrozystanie soli
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=random_number, iterations=100000)
    aes_key = kdf.derive(pin.encode())

    # serialiozacja klucza prywatnego do formatu PEM
    priv_key_serialised = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    #szyfrowanie klucza prywatnego
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    encrypted_priv = encryptor.update(priv_key_serialised) + encryptor.finalize()

    #zapisanie klucza prywatnego
    with open(os.path.join(save_path, "private_encrypted.bin"), "wb") as f:
        f.write(random_number + iv + encrypted_priv)

    # serialiozacja klucza publicznego do formatu PEM
    public_bytes = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # zapisanie publicznego
    with open(os.path.join(save_path, "public.pem"), "wb") as f:
        f.write(public_bytes)

    messagebox.showinfo("Sukces", "Klucze zapisane pomyślnie")

## @brief Obsługuje zdarzenie kliknięcia przycisku "Generuj klucze".
#  @details Weryfikuje wprowadzenie PIN-u, prosi użytkownika o wybór ścieżki i wywołuje funkcję `generate_keys`.
def on_generate():
    pin = pin_entry.get()
    if not pin:
        messagebox.showerror("Błąd", "Należy wprowadzić PIN")
        return
    path = filedialog.askdirectory(title="Wybierz ścieżke do zapisu")
    if path:
        generate_keys(pin, path)


root = tk.Tk()
root.title("Generator Kluczy RSA")
root.geometry("320x115")

tk.Label(root, text="dodaj pin: ").pack(pady=5)
pin_entry = tk.Entry(root, show="*")
pin_entry.pack(pady=5)

tk.Button(root, text="Generuj klucze", command=on_generate).pack(pady=10)

root.mainloop()