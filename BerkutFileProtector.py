import os
import sys
from tkinter import *
from tkinter import ttk, filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64
import zipfile
import io
import shutil
import webbrowser
import requests
from PIL import Image, ImageTk

class App:
    def __init__(self, root, initial_file=None):
        self.root = root
        self.root.title("Berkut File Protector")
        self.files_to_encrypt = []
        self.encrypted_data = {}
        self.opened_files = {}
        self.files_to_delete = []

        self.tabControl = ttk.Notebook(root)
        self.create_tab = ttk.Frame(self.tabControl)
        self.open_tab = ttk.Frame(self.tabControl)
        self.about_tab = self.create_about_tab(self.tabControl)
        self.tabControl.add(self.open_tab, text="Открыть")
        self.tabControl.add(self.create_tab, text="Создать")
        self.tabControl.add(self.about_tab, text="Об авторе")
        self.tabControl.pack(expand=1, fill="both")

        self.container_name_label = ttk.Label(self.create_tab, text="Имя контейнера:")
        self.container_name_label.place(x=10, y=10)
        self.container_name_entry = ttk.Entry(self.create_tab, width=50)
        self.container_name_entry.place(x=150, y=10)

        self.file_label = ttk.Label(self.create_tab, text="Файл для добавления:")
        self.file_label.place(x=10, y=40)
        self.file_path_entry = ttk.Entry(self.create_tab, width=50)
        self.file_path_entry.place(x=150, y=40)
        self.select_file_button = ttk.Button(self.create_tab, text="Выбрать файл", command=self.select_file)
        self.select_file_button.place(x=460, y=40)
        self.add_file_button = ttk.Button(self.create_tab, text="Добавить", command=self.add_file_to_container)
        self.add_file_button.place(x=560, y=40)

        self.folder_label = ttk.Label(self.create_tab, text="Папка для добавления:")
        self.folder_label.place(x=10, y=70)
        self.folder_path_entry = ttk.Entry(self.create_tab, width=50)
        self.folder_path_entry.place(x=150, y=70)
        self.select_folder_button = ttk.Button(self.create_tab, text="Выбрать папку", command=self.select_folder)
        self.select_folder_button.place(x=460, y=70)
        self.add_folder_button = ttk.Button(self.create_tab, text="Добавить", command=self.add_folder_to_container)
        self.add_folder_button.place(x=560, y=70)

        self.password_label = ttk.Label(self.create_tab, text="Пароль для контейнера:")
        self.password_label.place(x=10, y=100)
        self.password_entry = ttk.Entry(self.create_tab, show='*', width=50)
        self.password_entry.place(x=150, y=100)

        self.confirm_password_label = ttk.Label(self.create_tab, text="Подтверждение пароля:")
        self.confirm_password_label.place(x=10, y=130)
        self.confirm_password_entry = ttk.Entry(self.create_tab, show='*', width=50)
        self.confirm_password_entry.place(x=150, y=130)

        self.file_list_label = ttk.Label(self.create_tab, text="Добавленные файлы и папки:")
        self.file_list_label.place(x=10, y=160)
        self.file_list = Text(self.create_tab, wrap=WORD, width=50, height=5)
        self.file_list.place(x=180, y=160)

        self.create_container_button = ttk.Button(self.create_tab, text="Создать контейнер", command=self.save_container_as_file)
        self.create_container_button.place(x=480, y=115)

        self.container_path_label = ttk.Label(self.open_tab, text="Путь до контейнера:")
        self.container_path_label.place(x=10, y=10)
        self.container_path_entry = ttk.Entry(self.open_tab, width=50)
        self.container_path_entry.place(x=140, y=10)
        self.select_container_button = ttk.Button(self.open_tab, text="Выбрать", command=self.select_container)
        self.select_container_button.place(x=450, y=8)
        self.open_container_button = ttk.Button(self.open_tab, text="Открыть контейнер", command=self.open_container)
        self.open_container_button.place(x=530, y=60)
        self.close_container_button = ttk.Button(self.open_tab, text="Закрыть контейнер", command=self.close_container)
        self.close_container_button.place(x=530, y=100)
        self.modify_container_button = ttk.Button(self.open_tab, text="Внести изменения", command=self.modify_container)
        self.modify_container_button.place(x=530, y=140)

        self.tree = ttk.Treeview(self.open_tab, columns=("Size"))
        self.tree.heading("#0", text="Name", anchor=W)
        self.tree.heading("Size", text="Size", anchor=W)
        self.tree.column("#0", stretch=YES, minwidth=100, width=300)
        self.tree.column("Size", stretch=YES, minwidth=100, width=150)
        self.tree.place(x=10, y=50, width=500, height=200)

        self.add_file_open_button = ttk.Button(self.open_tab, text="Добавить файл", command=self.add_file_to_open_container)
        self.add_file_open_button.place(x=10, y=260)
        self.add_folder_open_button = ttk.Button(self.open_tab, text="Добавить папку", command=self.add_folder_to_open_container)
        self.add_folder_open_button.place(x=110, y=260)

        self.save_file_button = ttk.Button(self.open_tab, text="Сохранить файл", command=self.save_selected_file)
        self.save_file_button.place(x=213, y=260)

        self.save_all_button = ttk.Button(self.open_tab, text="Сохранить всё", command=self.save_all_files)
        self.save_all_button.place(x=320, y=260)

        self.delete_file_open_button = ttk.Button(self.open_tab, text="Удалить файл", command=self.delete_file_from_open_container)
        self.delete_file_open_button.place(x=415, y=260)

        self.tree.bind("<Double-1>", self.open_selected_file)

        if initial_file:
            self.container_path_entry.insert(0, initial_file)
            self.open_container()

    def encrypt_container(self, container_path, password):
        password = password.encode()

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = kdf.derive(password)

        with open(container_path, 'rb') as f:
            data = f.read()

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        with open(container_path + ".bfp", 'wb') as f:
            f.write(salt + iv + encrypted_data)

        os.remove(container_path)

        return container_path + ".bfp"

    def decrypt_container(self, encrypted_container_path, password):
        password = password.encode()

        with open(encrypted_container_path, 'rb') as f:
            encrypted_data = f.read()

        salt = encrypted_data[:16]
        iv = encrypted_data[16:32]
        encrypted_data = encrypted_data[32:]

        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(password)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_data) + unpadder.finalize()

        return data

    def save_selected_file(self):
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item)
            file_name = item['text']
            file_data = self.opened_files.get(file_name)
            if file_data:
                try:
                    folder_path = filedialog.askdirectory()
                    if folder_path:
                        save_path = os.path.join(folder_path, file_name)
                        with open(save_path, 'wb') as f:
                            f.write(file_data)
                        messagebox.showinfo("Успех", f"Файл '{file_name}' успешно сохранен в папке '{folder_path}'.")
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка при сохранении файла: {str(e)}")

    def save_all_files(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            try:
                for file_name, file_data in self.opened_files.items():
                    save_path = os.path.join(folder_path, file_name)
                    with open(save_path, 'wb') as f:
                        f.write(file_data)
                messagebox.showinfo("Успех", f"Все файлы успешно сохранены в папке '{folder_path}'.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка при сохранении файлов: {str(e)}")

    def open_selected_file(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item)
            file_name = item['text']
            file_data = self.opened_files.get(file_name)
            if file_data:
                try:
                    temp_file = os.path.join(os.environ['TEMP'], file_name)
                    with open(temp_file, 'wb') as f:
                        f.write(file_data)
                    os.startfile(temp_file)
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка при открытии файла: {str(e)}")
            else:
                messagebox.showwarning("Предупреждение", "Не удалось найти данные файла.")

    def create_container(self):
        container_name = self.container_name_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not container_name or not password or not confirm_password:
            messagebox.showerror("Ошибка", "Заполните все поля для создания контейнера.")
            return

        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        if not self.files_to_encrypt:
            messagebox.showerror("Ошибка", "Добавьте хотя бы один файл или папку для зашифровки.")
            return

        try:
            container_path = container_name

            with zipfile.ZipFile(container_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in self.files_to_encrypt:
                    if os.path.isfile(file_path):
                        zipf.write(file_path, os.path.basename(file_path))

            encrypted_container_path = self.encrypt_container(container_path, password)

            messagebox.showinfo("Успех", f"Контейнер {container_name} успешно создан и сохранён.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при сохранении контейнера: {str(e)}")

    def modify_container(self):
        container_path = self.container_path_entry.get()
        password = simpledialog.askstring("Пароль", "Введите пароль для криптоконтейнера:", show='*')

        if not container_path or not password:
            messagebox.showerror("Ошибка", "Укажите путь до контейнера и введите пароль.")
            return

        try:
            decrypted_data = self.decrypt_container(container_path, password)

            temp_dir = os.path.join(os.environ['TEMP'], "temp_container")
            os.makedirs(temp_dir, exist_ok=True)

            with zipfile.ZipFile(io.BytesIO(decrypted_data), 'r') as zipf:
                zipf.extractall(temp_dir)

            for file_to_delete in self.files_to_delete:
                file_path = os.path.join(temp_dir, file_to_delete)
                if os.path.isfile(file_path):
                    os.remove(file_path)

            for file_path in self.files_to_encrypt:
                if os.path.isfile(file_path):
                    shutil.copy(file_path, temp_dir)

            new_container_bytes_io = io.BytesIO()
            with zipfile.ZipFile(new_container_bytes_io, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path = os.path.join(root, file)
                        zipf.write(file_path, os.path.basename(file_path))

            shutil.rmtree(temp_dir)

            new_container_bytes_io.seek(0)
            encrypted_container_path = self.encrypt_container_data(new_container_bytes_io.read(), password)

            with open(container_path, 'wb') as f:
                f.write(encrypted_container_path)

            messagebox.showinfo("Успех", "Изменения успешно внесены в контейнер.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при внесении изменений в контейнер: {str(e)}")

    def encrypt_container_data(self, data, password):
        password = password.encode()

        salt = os.urandom(16)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )

        key = kdf.derive(password)

        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()

        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

        return salt + iv + encrypted_data

    def create_about_tab(self, tab):
        about_frame = ttk.Frame(tab)
        about_frame.pack(fill='both', expand=True)

        about_text = ("Программа была разработана для безопасного хранения файлов в криптоконтейнерах.\n"
                      "\n"
                      "Привет, пользователь!\n"
                      "Благодарю тебя за использование моего ПО\n"
                      "Я являюсь дипломированным специалистом по защите информации\n"
                      "Если у тебя появятся какие-либо вопросы, можешь обращаться по контактам ниже\n\n"
                      "Контакты:")
        about_label = ttk.Label(about_frame, text=about_text, justify=LEFT, anchor="n", wraplength=500)
        about_label.grid(row=0, column=0, padx=10, pady=10)

        telegram_link = ttk.Label(about_frame, text="Telegram", foreground="blue", cursor="hand2")
        telegram_link.grid(row=1, column=0, padx=10, pady=5, sticky='w')
        telegram_link.bind("<Button-1>", lambda e: webbrowser.open_new("https://t.me/berkutmraz"))

        email_link = ttk.Label(about_frame, text="Почта", foreground="blue", cursor="hand2")
        email_link.grid(row=1, column=0, padx=70, pady=5, sticky='w')
        email_link.bind("<Button-1>", lambda e: webbrowser.open_new("mailto:berkutosint@proton.me"))

        image_url = "https://i.postimg.cc/fR19xcKc/Kasper-Flipper512.png"
        response = requests.get(image_url)
        image_data = response.content

        image = Image.open(io.BytesIO(image_data))
        desired_width = 150
        desired_height = 150
        image = image.resize((desired_width, desired_height), Image.LANCZOS)
        render = ImageTk.PhotoImage(image)

        image_label = ttk.Label(about_frame, image=render)
        image_label.image = render
        image_label.place(x=500, y=10)

        return about_frame

    def select_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file_path:
            self.file_path_entry.delete(0, END)
            self.file_path_entry.insert(0, file_path)

    def add_file_to_container(self):
        file_path = self.file_path_entry.get()
        if file_path:
            self.files_to_encrypt.append(file_path)
            self.file_list.insert(END, file_path + "\n")
            self.file_path_entry.delete(0, END)
        else:
            messagebox.showerror("Ошибка", "Выберите файл для добавления в контейнер.")

    def select_folder(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            self.folder_path_entry.delete(0, END)
            self.folder_path_entry.insert(0, folder_path)

    def add_folder_to_container(self):
        folder_path = self.folder_path_entry.get()
        if folder_path:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    self.files_to_encrypt.append(file_path)
                    self.file_list.insert(END, file_path + "\n")
            self.folder_path_entry.delete(0, END)
        else:
            messagebox.showerror("Ошибка", "Выберите папку для добавления в контейнер.")

    def delete_file_from_open_container(self):
        selected_item = self.tree.selection()
        if selected_item:
            item = self.tree.item(selected_item)
            file_name = item['text']
            self.tree.delete(selected_item)
            if file_name in self.opened_files:
                del self.opened_files[file_name]
            self.files_to_delete.append(file_name)
            messagebox.showinfo("Успех", f"Файл {file_name} успешно удалён из контейнера.")
        else:
            messagebox.showerror("Ошибка", "Выберите файл для удаления из контейнера.")

    def save_container_as_file(self):
        container_name = self.container_name_entry.get()
        password = self.password_entry.get()
        confirm_password = self.confirm_password_entry.get()

        if not container_name or not password or not confirm_password:
            messagebox.showerror("Ошибка", "Заполните все поля для создания контейнера.")
            return

        if password != confirm_password:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        if not self.files_to_encrypt:
            messagebox.showerror("Ошибка", "Добавьте хотя бы один файл или папку для зашифровки.")
            return

        try:
            container_path = container_name

            with zipfile.ZipFile(container_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                for file_path in self.files_to_encrypt:
                    if os.path.isfile(file_path):
                        zipf.write(file_path, os.path.basename(file_path))

            encrypted_container_path = self.encrypt_container(container_path, password)

            messagebox.showinfo("Успех", f"Контейнер {container_name} успешно создан и сохранён.")
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка при сохранении контейнера: {str(e)}")

    def select_container(self):
        container_path = filedialog.askopenfilename(filetypes=[("Berkut Containers", "*.bfp")])
        if container_path:
            self.container_path_entry.delete(0, END)
            self.container_path_entry.insert(0, container_path)
            self.open_container()

    def open_container(self):
        container_path = self.container_path_entry.get()
        password = simpledialog.askstring("Пароль", "Введите пароль для криптоконтейнера:", show='*')

        if container_path and password:
            try:
                decrypted_data = self.decrypt_container(container_path, password)
                container_files = self.get_container_files_from_data(decrypted_data)

                self.tree.delete(*self.tree.get_children())
                self.files_to_encrypt = []
                self.files_to_delete = []

                for file_name, file_data in container_files.items():
                    file_size = len(file_data)
                    self.tree.insert('', 'end', text=file_name, values=(file_size,))
                    self.opened_files[file_name] = file_data

                messagebox.showinfo("Успех", f"Контейнер {os.path.splitext(os.path.basename(container_path))[0]} успешно открыт.")
            except Exception as e:
                messagebox.showerror("Ошибка", f"Невозможно открыть контейнер: {str(e)}")

    def close_container(self):
        self.tree.delete(*self.tree.get_children())
        self.opened_files.clear()
        messagebox.showinfo("Успех", "Контейнер закрыт.")

    def get_container_files_from_data(self, data):
        container_files = {}
        with zipfile.ZipFile(io.BytesIO(data), 'r') as zipf:
            for file_name in zipf.namelist():
                with zipf.open(file_name) as f:
                    container_files[file_name] = f.read()
        return container_files

    def add_file_to_open_container(self):
        file_path = filedialog.askopenfilename(filetypes=[("All Files", "*.*")])
        if file_path:
            file_name = os.path.basename(file_path)
            file_size = os.path.getsize(file_path)
            self.tree.insert('', 'end', text=file_name, values=(file_size,))
            self.opened_files[file_name] = open(file_path, 'rb').read()
            self.files_to_encrypt.append(file_path)

    def add_folder_to_open_container(self):
        folder_path = filedialog.askdirectory()
        if folder_path:
            for root, dirs, files in os.walk(folder_path):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_name = os.path.basename(file_path)
                    file_size = os.path.getsize(file_path)
                    self.tree.insert('', 'end', text=file_name, values=(file_size,))
                    self.opened_files[file_name] = open(file_path, 'rb').read()
                    self.files_to_encrypt.append(file_path)

if __name__ == "__main__":
    initial_file = None
    if len(sys.argv) > 1:
        initial_file = sys.argv[1]

    root = Tk()

    root.geometry("670x320")
    root.resizable(False, False)

    root.update_idletasks()
    width = root.winfo_width()
    height = root.winfo_height()
    x = (root.winfo_screenwidth() // 2) - (width // 2)
    y = (root.winfo_screenheight() // 2) - (height // 2)
    root.geometry(f'{width}x{height}+{x}+{y}')

    app = App(root, initial_file)
    root.mainloop()
