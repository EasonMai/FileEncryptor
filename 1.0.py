import os
import sys
import struct
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QLineEdit,
    QPushButton, QFileDialog, QVBoxLayout, QHBoxLayout,
    QMessageBox, QProgressDialog
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from Cryptodome.Cipher import AES
from Cryptodome.Protocol.KDF import PBKDF2
from Cryptodome.Random import get_random_bytes

BLOCK_SIZE = AES.block_size
KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
ITERATIONS = 100000
CHUNK_SIZE = 1024 * 1024  # 1MB chunks

class CryptoWorker(QThread):
    progress_updated = pyqtSignal(int)
    finished = pyqtSignal(bool, str)

    def __init__(self, mode, file_path, password, output_dir):
        super().__init__()
        self.mode = mode
        self.file_path = file_path
        self.password = password
        self.output_dir = output_dir
        self._is_running = True

    def stop(self):
        self._is_running = False

    def run(self):
        try:
            if self.mode == 'encrypt':
                self.encrypt_file()
            else:
                self.decrypt_file()
            self.finished.emit(True, "")
        except Exception as e:
            self.finished.emit(False, str(e))

    def encrypt_file(self):
        salt = get_random_bytes(SALT_SIZE)
        iv = get_random_bytes(IV_SIZE)
        key = PBKDF2(self.password.encode(), salt, dkLen=KEY_SIZE, count=ITERATIONS)
        cipher = AES.new(key, AES.MODE_CFB, iv)

        original_filename = os.path.basename(self.file_path)
        base_name = os.path.splitext(original_filename)[0]
        output_path = os.path.join(self.output_dir, f"{base_name}.enc")

        file_size = os.path.getsize(self.file_path)
        processed = 0

        with open(self.file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
            # 写入文件头（salt + iv + 原始文件名）
            f_out.write(salt)
            f_out.write(iv)
            name_bytes = original_filename.encode('utf-8')
            f_out.write(struct.pack('>I', len(name_bytes)))  # 4字节文件名长度
            f_out.write(name_bytes)

            while self._is_running:
                chunk = f_in.read(CHUNK_SIZE)
                if not chunk:
                    break
                
                encrypted = cipher.encrypt(chunk)
                f_out.write(encrypted)
                processed += len(chunk)
                self.progress_updated.emit(int((processed / file_size) * 100))

    def decrypt_file(self):
        with open(self.file_path, 'rb') as f_in:
            salt = f_in.read(SALT_SIZE)
            iv = f_in.read(IV_SIZE)
            name_length = struct.unpack('>I', f_in.read(4))[0]
            original_filename = f_in.read(name_length).decode('utf-8')
            key = PBKDF2(self.password.encode(), salt, dkLen=KEY_SIZE, count=ITERATIONS)
            cipher = AES.new(key, AES.MODE_CFB, iv)

            output_path = os.path.join(self.output_dir, original_filename)
            file_size = os.path.getsize(self.file_path) - (SALT_SIZE + IV_SIZE + 4 + name_length)
            processed = 0

            with open(output_path, 'wb') as f_out:
                while self._is_running:
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    decrypted = cipher.decrypt(chunk)
                    f_out.write(decrypted)
                    processed += len(chunk)
                    self.progress_updated.emit(int((processed / file_size) * 100))

class CryptoApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.file_path = ""
        self.worker = None

    def initUI(self):
        self.setWindowTitle('智能文件加密工具')
        self.setGeometry(300, 300, 600, 200)

        layout = QVBoxLayout()

        # 文件选择部件
        file_layout = QHBoxLayout()
        self.file_label = QLabel("选择文件:")
        self.file_entry = QLineEdit()
        self.file_entry.setReadOnly(True)
        browse_btn = QPushButton("浏览")
        browse_btn.clicked.connect(self.select_file)
        file_layout.addWidget(self.file_label)
        file_layout.addWidget(self.file_entry)
        file_layout.addWidget(browse_btn)

        # 密码输入部件
        pwd_layout = QHBoxLayout()
        self.pwd_label = QLabel("输入密码:")
        self.pwd_entry = QLineEdit()
        self.pwd_entry.setEchoMode(QLineEdit.EchoMode.Password)
        pwd_layout.addWidget(self.pwd_label)
        pwd_layout.addWidget(self.pwd_entry)

        # 操作按钮
        btn_layout = QHBoxLayout()
        encrypt_btn = QPushButton("加密")
        encrypt_btn.clicked.connect(lambda: self.start_process('encrypt'))
        decrypt_btn = QPushButton("解密")
        decrypt_btn.clicked.connect(lambda: self.start_process('decrypt'))
        btn_layout.addWidget(encrypt_btn)
        btn_layout.addWidget(decrypt_btn)

        layout.addLayout(file_layout)
        layout.addLayout(pwd_layout)
        layout.addLayout(btn_layout)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择文件")
        if file_path:
            self.file_path = file_path
            self.file_entry.setText(file_path)

    def start_process(self, mode):
        if not self.validate_input(mode):
            return

        output_dir = os.path.dirname(self.file_path)
        self.progress = QProgressDialog(
            "正在处理文件...", 
            "取消", 
            0, 
            100, 
            self
        )
        self.progress.setWindowTitle("请稍候")
        self.progress.setWindowModality(Qt.WindowModality.WindowModal)
        self.progress.canceled.connect(self.cancel_process)

        self.worker = CryptoWorker(
            mode,
            self.file_path,
            self.pwd_entry.text(),
            output_dir
        )
        self.worker.progress_updated.connect(self.update_progress)
        self.worker.finished.connect(self.process_finished)
        self.worker.start()

    def validate_input(self, mode):
        if not self.file_path:
            QMessageBox.warning(self, "警告", "请先选择文件！")
            return False
        if not self.pwd_entry.text():
            QMessageBox.warning(self, "警告", "请输入密码！")
            return False
        if mode == 'decrypt' and not self.file_path.endswith('.enc'):
            QMessageBox.warning(self, "警告", "只能解密.enc后缀的加密文件！")
            return False
        return True

    def update_progress(self, value):
        self.progress.setValue(value)

    def cancel_process(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop()
            self.worker.wait()
            QMessageBox.warning(self, "取消", "操作已被用户取消")

    def process_finished(self, success, message):
        self.progress.close()
        if success:
            QMessageBox.information(self, "成功", "文件处理完成！")
        else:
            QMessageBox.critical(self, "错误", f"操作失败: {message}")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = CryptoApp()
    window.show()
    sys.exit(app.exec())
