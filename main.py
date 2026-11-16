
import tkinter as tk
from tkinter import messagebox
import json
import base64
import os
import uuid

from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag


# ==========================================
# НАСТРОЙКИ
# ==========================================

root = tk.Tk()
root.title("Password Vault")
root.geometry("600x760")
root.resizable(False, False)

VAULT_PATH = Path(__file__).resolve().parent / "vault.dat"

vault_data = None
vault_key = None
vault_salt = None
selected_password = None

COLORS = {
    "bg": "#F3F5F9",
    "card": "#FFFFFF",
    "text": "#252A35",
    "secondary": "#858B98",
    "entry": "#F6F7FA",
    "border": "#E2E5EC",
    "button": "#6678E8",
    "button_hover": "#5365D4",
    "danger": "#D9534F",
    "success": "#269B68"
}


# ==========================================
# КРИПТОГРАФИЯ
# ==========================================

def derive_key(password, salt):
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=3,
        memory_cost=65536,
        parallelism=2,
        hash_len=32,
        type=Type.ID
    )


def encrypt_vault(data, key):
    aes = AESGCM(key)
    nonce = os.urandom(12)

    plaintext = json.dumps(
        data,
        ensure_ascii=False
    ).encode("utf-8")

    ciphertext = aes.encrypt(
        nonce,
        plaintext,
        b"PasswordVault_v1"
    )

    return {
        "version": 1,
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii")
    }


def save_vault():
    encrypted = encrypt_vault(vault_data, vault_key)

    file_data = {
        "version": 1,
        "salt": base64.b64encode(vault_salt).decode("ascii"),
        "nonce": encrypted["nonce"],
        "ciphertext": encrypted["ciphertext"]
    }

    temp_path = VAULT_PATH.with_name(
        VAULT_PATH.name + ".tmp"
    )

    try:
        with open(temp_path, "w", encoding="utf-8") as file:
            json.dump(file_data, file, ensure_ascii=False)

        os.replace(temp_path, VAULT_PATH)

    finally:
        if temp_path.exists():
            temp_path.unlink()


def load_vault(password):
    with open(VAULT_PATH, "r", encoding="utf-8") as file:
        file_data = json.load(file)

    if file_data.get("version") != 1:
        raise ValueError("Неподдерживаемая версия хранилища")

    salt = base64.b64decode(
        file_data["salt"],
        validate=True
    )

    nonce = base64.b64decode(
        file_data["nonce"],
        validate=True
    )

    ciphertext = base64.b64decode(
        file_data["ciphertext"],
        validate=True
    )

    if len(salt) != 16 or len(nonce) != 12:
        raise ValueError("Повреждён файл хранилища")

    key = derive_key(password, salt)

    aes = AESGCM(key)

    plaintext = aes.decrypt(
        nonce,
        ciphertext,
        b"PasswordVault_v1"
    )

    data = json.loads(plaintext.decode("utf-8"))

    if not isinstance(data, dict):
        raise ValueError("Некорректное хранилище")

    if not isinstance(data.get("passwords"), list):
        raise ValueError("Некорректная структура записей")

    return data, key, salt


# ==========================================
# ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
# ==========================================

def clear_window():
    for widget in root.winfo_children():
        widget.destroy()


def create_label(parent, text, size=11, bold=False, color=None):
    return tk.Label(
        parent,
        text=text,
        font=("Arial", size, "bold" if bold else "normal"),
        bg=COLORS["card"],
        fg=color or COLORS["text"]
    )


def create_entry(parent, show=None):
    return tk.Entry(
        parent,
        font=("Arial", 12),
        bg=COLORS["entry"],
        fg=COLORS["text"],
        insertbackground=COLORS["text"],
        relief="flat",
        bd=0,
        show=show
    )


def create_button(parent, text, command, color=None):
    return tk.Button(
        parent,
        text=text,
        font=("Arial", 11, "bold"),
        bg=color or COLORS["button"],
        fg="white",
        activebackground=COLORS["button_hover"],
        activeforeground="white",
        relief="flat",
        bd=0,
        cursor="hand2",
        command=command
    )


# ==========================================
# ОКНО АВТОРИЗАЦИИ
# ==========================================

def show_auth_window():

    clear_window()

    root.state("normal")
    root.geometry("600x760")
    root.resizable(False, False)
    root.configure(bg=COLORS["bg"])

    is_existing = VAULT_PATH.exists()

    frame = tk.Frame(
        root,
        bg=COLORS["card"],
        highlightthickness=1,
        highlightbackground=COLORS["border"]
    )

    frame.place(
        relx=0.5,
        rely=0.5,
        anchor="center",
        width=480,
        height=680
    )

    tk.Label(
        frame,
        text="🔐",
        font=("Arial", 38),
        bg=COLORS["card"]
    ).pack(pady=(35, 5))

    create_label(
        frame,
        "Добро пожаловать в дом для ваших паролей!",
        10
    ).pack(pady=(0, 10))

    create_label(
        frame,
        "Открытие хранилища" if is_existing
        else "Создание хранилища",
        21,
        True
    ).pack()

    create_label(
        frame,
        "Введите мастер-пароль для доступа к хранилищу"
        if is_existing
        else "Создайте надёжный мастер-пароль",
        10,
        color=COLORS["secondary"]
    ).pack(pady=(6, 20))

    info_frame = tk.Frame(
        frame,
        bg="#EEF1FF"
    )

    info_frame.pack(
        fill="x",
        padx=32,
        pady=(0, 25)
    )

    tk.Label(
        info_frame,
        text="ⓘ  Важно знать",
        font=("Arial", 10, "bold"),
        bg="#EEF1FF",
        fg="#5868B8"
    ).pack(anchor="w", padx=14, pady=(10, 4))

    tk.Label(
        info_frame,
        text=(
            "Мастер-пароль — главный ключ к вашему хранилищу.\n"
            "Он понадобится для доступа ко всем сохранённым\n"
            "паролям. Не забывайте его: восстановить доступ\n"
            "без него может быть невозможно."
        ),
        font=("Arial", 9),
        justify="left",
        bg="#EEF1FF",
        fg="#5868B8"
    ).pack(anchor="w", padx=14, pady=(0, 10))

    # Мастер-пароль

    create_label(
        frame,
        "Мастер-пароль",
        10,
        True
    ).pack(anchor="w", padx=32, pady=(0, 7))

    password_entry = create_entry(frame, show="●")
    password_entry.pack(
        fill="x",
        padx=46,
        ipady=12,
        pady=(0, 18)
    )

    # Повтор пароля при создании

    repeat_entry = None

    if not is_existing:

        create_label(
            frame,
            "Повторите мастер-пароль",
            10,
            True
        ).pack(anchor="w", padx=32, pady=(0, 7))

        repeat_entry = create_entry(frame, show="●")
        repeat_entry.pack(
            fill="x",
            padx=46,
            ipady=12,
            pady=(0, 10)
        )

    # Показать пароль

    password_visible = False

    def toggle_visibility():

        nonlocal password_visible

        password_visible = not password_visible

        symbol = "" if password_visible else "●"

        password_entry.config(show=symbol)

        if repeat_entry is not None:
            repeat_entry.config(show=symbol)

        visibility_button.config(
            text="Скрыть пароль" if password_visible
            else "Показать пароль"
        )

    visibility_button = tk.Button(
        frame,
        text="Показать пароль",
        font=("Arial", 9),
        bg=COLORS["card"],
        fg=COLORS["secondary"],
        relief="flat",
        bd=0,
        cursor="hand2",
        command=toggle_visibility
    )

    visibility_button.pack(
        anchor="e",
        padx=32,
        pady=(0, 10)
    )

    message_label = tk.Label(
        frame,
        text="",
        font=("Arial", 10),
        bg=COLORS["card"],
        fg=COLORS["danger"],
        wraplength=400
    )

    message_label.pack(pady=(0, 10))

    # ======================================
    # СОЗДАНИЕ ХРАНИЛИЩА
    # ======================================

    def create_vault():

        global vault_data, vault_key, vault_salt

        password = password_entry.get()
        repeat = repeat_entry.get()

        if not password:
            message_label.config(text="Введите мастер-пароль")
            return

        if not repeat:
            message_label.config(text="Повторите мастер-пароль")
            return

        if len(password) < 12:
            message_label.config(
                text="Мастер-пароль должен содержать минимум 12 символов"
            )
            return

        if password != repeat:
            message_label.config(text="Пароли не совпадают")
            return

        try:
            vault_salt = os.urandom(16)
            vault_key = derive_key(password, vault_salt)

            vault_data = {
                "passwords": []
            }

            save_vault()

            messagebox.showinfo(
                "Password Vault",
                "Хранилище успешно создано!\nТеперь войдите с мастер-паролем."
            )

            # Переход к обычному окну входа
            show_auth_window()

        except Exception as error:
            messagebox.showerror(
                "Ошибка",
                f"Не удалось создать хранилище:\n{error}"
            )

    # ======================================
    # ВХОД В ХРАНИЛИЩЕ
    # ======================================

    def unlock_vault():

        global vault_data, vault_key, vault_salt

        password = password_entry.get()

        if not password:
            message_label.config(text="Введите мастер-пароль")
            return

        try:
            vault_data, vault_key, vault_salt = load_vault(password)

            show_main_window()

        except InvalidTag:
            password_entry.delete(0, tk.END)

            message_label.config(
                text="Неверный мастер-пароль или повреждён файл хранилища"
            )

        except (OSError, ValueError, KeyError, TypeError):
            message_label.config(
                text="Не удалось прочитать хранилище. Возможно, файл повреждён."
            )

        except Exception:
            message_label.config(
                text="Произошла ошибка при открытии хранилища."
            )

    # Кнопка

    create_button(
        frame,
        "Открыть хранилище" if is_existing
        else "Создать хранилище",
        unlock_vault if is_existing else create_vault
    ).pack(
        fill="x",
        padx=32,
        ipady=12,
        pady=(0, 0)
    )

    password_entry.focus_set()


# ==========================================
# ГЛАВНОЕ ОКНО
# ==========================================

def show_main_window():

    global selected_password

    selected_password = None

    clear_window()

    root.state("zoomed")
    root.resizable(True, True)
    root.configure(bg=COLORS["bg"])

    # Основной контейнер

    main_container = tk.Frame(
        root,
        bg=COLORS["bg"]
    )

    main_container.pack(
        fill="both",
        expand=True
    )

    # ======================================
    # ЛЕВАЯ БОКОВАЯ ПАНЕЛЬ
    # ======================================

    sidebar = tk.Frame(
        main_container,
        bg=COLORS["card"],
        width=310,
        highlightthickness=1,
        highlightbackground=COLORS["border"]
    )

    sidebar.pack(
        side="left",
        fill="y"
    )

    sidebar.pack_propagate(False)

    # Заголовок

    tk.Label(
        sidebar,
        text="🔐 Password Vault",
        font=("Arial", 17, "bold"),
        bg=COLORS["card"],
        fg=COLORS["text"]
    ).pack(
        anchor="w",
        padx=20,
        pady=(25, 25)
    )

    # Кнопка добавления

    add_button = tk.Button(
        sidebar,
        text="+   Добавить пароль",
        font=("Arial", 12, "bold"),
        bg=COLORS["button"],
        fg="white",
        activebackground=COLORS["button_hover"],
        relief="flat",
        bd=0,
        cursor="hand2",
        command=open_add_window
    )

    add_button.pack(
        fill="x",
        padx=15,
        ipady=12,
        pady=(0, 20)
    )

    tk.Label(
        sidebar,
        text="МОИ ПАРОЛИ",
        font=("Arial", 9, "bold"),
        bg=COLORS["card"],
        fg=COLORS["secondary"]
    ).pack(
        anchor="w",
        padx=20,
        pady=(0, 10)
    )

    # Список записей

    global password_list_frame

    password_list_frame = tk.Frame(
        sidebar,
        bg=COLORS["card"]
    )

    password_list_frame.pack(
        fill="both",
        expand=True,
        padx=10
    )

    # Кнопка выхода

    tk.Button(
        sidebar,
        text="Выйти из хранилища",
        font=("Arial", 10),
        bg=COLORS["card"],
        fg=COLORS["danger"],
        relief="flat",
        bd=0,
        cursor="hand2",
        command=logout
    ).pack(
        fill="x",
        padx=15,
        pady=15
    )

    # ======================================
    # ПРАВАЯ ОБЛАСТЬ
    # ======================================

    global content_frame

    content_frame = tk.Frame(
        main_container,
        bg=COLORS["bg"]
    )

    content_frame.pack(
        side="left",
        fill="both",
        expand=True
    )

    refresh_password_list()
    show_empty_content()


# ==========================================
# СПИСОК ПАРОЛЕЙ
# ==========================================

def refresh_password_list():

    for widget in password_list_frame.winfo_children():
        widget.destroy()

    passwords = vault_data["passwords"]

    if not passwords:

        tk.Label(
            password_list_frame,
            text="Пока нет сохранённых паролей",
            font=("Arial", 10),
            bg=COLORS["card"],
            fg=COLORS["secondary"],
            wraplength=250
        ).pack(
            anchor="w",
            padx=10,
            pady=15
        )

        return

    for item in passwords:

        button = tk.Button(
            password_list_frame,
            text="🔑  " + item["title"],
            font=("Arial", 11),
            anchor="w",
            bg=COLORS["card"],
            fg=COLORS["text"],
            activebackground=COLORS["bg"],
            relief="flat",
            bd=0,
            cursor="hand2",
            command=lambda current=item: show_password_details(current)
        )

        button.pack(
            fill="x",
            ipady=10,
            padx=3
        )


# ==========================================
# ПУСТОЙ ЭКРАН
# ==========================================

def show_empty_content():

    for widget in content_frame.winfo_children():
        widget.destroy()

    tk.Label(
        content_frame,
        text="Добро пожаловать!",
        font=("Arial", 27, "bold"),
        bg=COLORS["bg"],
        fg=COLORS["text"]
    ).place(
        relx=0.5,
        rely=0.43,
        anchor="center"
    )

    tk.Label(
        content_frame,
        text="Выберите сохранённый сайт слева\nили добавьте новую запись",
        font=("Arial", 13),
        bg=COLORS["bg"],
        fg=COLORS["secondary"],
        justify="center"
    ).place(
        relx=0.5,
        rely=0.51,
        anchor="center"
    )


# ==========================================
# ПРОСМОТР ПАРОЛЯ
# ==========================================

def show_password_details(item):

    global selected_password

    selected_password = item

    for widget in content_frame.winfo_children():
        widget.destroy()

    card = tk.Frame(
        content_frame,
        bg=COLORS["card"],
        highlightthickness=1,
        highlightbackground=COLORS["border"]
    )

    card.place(
        relx=0.5,
        rely=0.5,
        anchor="center",
        width=550,
        height=470
    )

    tk.Label(
        card,
        text=item["title"],
        font=("Arial", 24, "bold"),
        bg=COLORS["card"],
        fg=COLORS["text"]
    ).pack(
        pady=(30, 25)
    )

    # URL

    tk.Label(
        card,
        text="Адрес сайта",
        font=("Arial", 10, "bold"),
        bg=COLORS["card"],
        fg=COLORS["secondary"]
    ).pack(anchor="w", padx=35)

    tk.Label(
        card,
        text=item["url"],
        font=("Arial", 12),
        bg=COLORS["card"],
        fg=COLORS["text"]
    ).pack(anchor="w", padx=35, pady=(5, 20))

    # Логин

    tk.Label(
        card,
        text="Логин",
        font=("Arial", 10, "bold"),
        bg=COLORS["card"],
        fg=COLORS["secondary"]
    ).pack(anchor="w", padx=35)

    tk.Label(
        card,
        text=item["username"],
        font=("Arial", 12),
        bg=COLORS["card"],
        fg=COLORS["text"]
    ).pack(anchor="w", padx=35, pady=(5, 20))

    # Пароль

    tk.Label(
        card,
        text="Пароль",
        font=("Arial", 10, "bold"),
        bg=COLORS["card"],
        fg=COLORS["secondary"]
    ).pack(anchor="w", padx=35)

    password_frame = tk.Frame(
        card,
        bg=COLORS["entry"]
    )

    password_frame.pack(
        fill="x",
        padx=35,
        pady=(7, 20)
    )

    password_entry = tk.Entry(
        password_frame,
        font=("Arial", 12),
        bg=COLORS["entry"],
        fg=COLORS["text"],
        relief="flat",
        bd=0,
        show="●"
    )

    password_entry.insert(0, item["password"])

    password_entry.pack(
        side="left",
        fill="x",
        expand=True,
        padx=12,
        pady=12
    )

    def toggle_password():

        if password_entry.cget("show"):
            password_entry.config(show="")
            show_button.config(text="Скрыть")
        else:
            password_entry.config(show="●")
            show_button.config(text="Показать")

    show_button = tk.Button(
        password_frame,
        text="Показать",
        font=("Arial", 9),
        bg=COLORS["entry"],
        fg=COLORS["button"],
        relief="flat",
        bd=0,
        command=toggle_password
    )

    show_button.pack(side="right", padx=10)

    # Кнопки

    button_frame = tk.Frame(
        card,
        bg=COLORS["card"]
    )

    button_frame.pack(
        fill="x",
        padx=35,
        pady=15
    )

    def copy_password():

        root.clipboard_clear()
        root.clipboard_append(item["password"])

        messagebox.showinfo(
            "Password Vault",
            "Пароль скопирован!"
        )

    create_button(
        button_frame,
        "Копировать пароль",
        copy_password
    ).pack(
        side="left",
        fill="x",
        expand=True,
        ipady=10,
        padx=(0, 5)
    )

    tk.Button(
        button_frame,
        text="Удалить",
        font=("Arial", 11, "bold"),
        bg=COLORS["danger"],
        fg="white",
        relief="flat",
        bd=0,
        cursor="hand2",
        command=lambda: delete_password(item)
    ).pack(
        side="left",
        fill="x",
        expand=True,
        ipady=10,
        padx=(5, 0)
    )


# ==========================================
# ДОБАВЛЕНИЕ НОВОГО ПАРОЛЯ
# ==========================================

def open_add_window():

    add_window = tk.Toplevel(root)

    add_window.title("Добавление пароля")
    add_window.geometry("430x480")
    add_window.resizable(False, False)
    add_window.configure(bg=COLORS["card"])

    add_window.transient(root)
    add_window.grab_set()

    tk.Label(
        add_window,
        text="Новая запись",
        font=("Arial", 21, "bold"),
        bg=COLORS["card"],
        fg=COLORS["text"]
    ).pack(pady=(25, 20))

    fields = {}

    field_names = [
        ("title", "Название сайта"),
        ("url", "URL"),
        ("username", "Логин"),
        ("password", "Пароль")
    ]

    for key, label_text in field_names:

        tk.Label(
            add_window,
            text=label_text,
            font=("Arial", 10, "bold"),
            bg=COLORS["card"],
            fg=COLORS["text"]
        ).pack(anchor="w", padx=35, pady=(5, 5))

        entry = create_entry(
            add_window,
            show="●" if key == "password" else None
        )

        entry.pack(
            fill="x",
            padx=35,
            ipady=9,
            pady=(0, 8)
        )

        fields[key] = entry

    def save_new_password():

        title = fields["title"].get().strip()
        url = fields["url"].get().strip()
        username = fields["username"].get().strip()
        password = fields["password"].get()

        if not title or not url or not username or not password:
            messagebox.showwarning(
                "Внимание",
                "Заполните все поля."
            )
            return

        new_item = {
            "id": str(uuid.uuid4()),
            "title": title,
            "url": url,
            "username": username,
            "password": password
        }

        vault_data["passwords"].append(new_item)

        try:
            save_vault()

            refresh_password_list()
            show_password_details(new_item)

            add_window.destroy()

        except Exception as error:

            vault_data["passwords"].remove(new_item)

            messagebox.showerror(
                "Ошибка",
                f"Не удалось сохранить запись:\n{error}"
            )

    create_button(
        add_window,
        "Сохранить пароль",
        save_new_password
    ).pack(
        fill="x",
        padx=35,
        ipady=11,
        pady=(15, 0)
    )


# ==========================================
# УДАЛЕНИЕ ПАРОЛЯ
# ==========================================

def delete_password(item):

    result = messagebox.askyesno(
        "Удаление записи",
        f"Вы действительно хотите удалить запись «{item['title']}»?"
    )

    if not result:
        return

    vault_data["passwords"].remove(item)

    try:
        save_vault()

        refresh_password_list()
        show_empty_content()

    except Exception as error:

        messagebox.showerror(
            "Ошибка",
            f"Не удалось сохранить изменения:\n{error}"
        )


# ==========================================
# ВЫХОД ИЗ ХРАНИЛИЩА
# ==========================================

def logout():

    global vault_data, vault_key, vault_salt

    vault_data = None
    vault_key = None
    vault_salt = None

    show_auth_window()


# ==========================================
# ЗАПУСК
# ==========================================

show_auth_window()

root.mainloop()



