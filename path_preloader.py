import sys
from pathlib import Path
from PySide6.QtCore import QObject, Signal, QThread, QEventLoop
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QPushButton, QLineEdit, QFileDialog,
                               QTextEdit, QMessageBox, QLabel, QComboBox)

class LanguageManager:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.current_lang = 'en'
            cls._instance.strings = {
                'en': {
                    'window_title': 'PLPatcher',
                    'src_label': 'Source file:',
                    'browse_btn': 'Browse...',
                    'start_btn': 'Start Processing',
                    'ask_continue': 'Do you wish to continue?',
                    'ask_ignore_size': 'File size mismatch, ignore and continue?',
                    'ask_flag_not_found': 'Flag block not found! Continue without flag block?',
                    'ask_unknown_type': 'Unknown file type, continue?',
                    'ask_retry': 'File not found, retry?',
                    'error_cancelled': 'Operation cancelled by user',
                    'error_raw': 'RAW preloader cannot be processed',
                    'error_offset': 'Code offset > 0x2000, cannot proceed',
                    'error_exception': 'Exception occurred: {}',
                    'author': 'Dev. Max_Goblin - 4pda',
                },
                'zh': {
                    'window_title': 'PLPatcher',
                    'src_label': '源文件：',
                    'browse_btn': '浏览...',
                    'start_btn': '开始处理',
                    'ask_continue': '是否继续？',
                    'ask_ignore_size': '文件大小不匹配，是否忽略并继续？',
                    'ask_flag_not_found': '未找到标志块，是否继续（不带标志块）？',
                    'ask_unknown_type': '未知文件类型，是否继续？',
                    'ask_retry': '文件未找到，是否重试？',
                    'error_cancelled': '用户取消操作',
                    'error_raw': 'RAW格式预加载器无法处理',
                    'error_offset': '代码偏移量大于0x2000，无法处理',
                    'error_exception': '发生异常：{}',
                    'author': 'Dev. Max_Goblin - 4pda',
                }
            }
        return cls._instance

    def get(self, key, *args):
        text = self.strings[self.current_lang].get(key, key)
        if args:
            return text.format(*args)
        return text

    def set_language(self, lang):
        if lang in self.strings:
            self.current_lang = lang

lang = LanguageManager()

class PreloaderWorker(QObject):
    log_signal = Signal(str)
    ask_signal = Signal(str, int)
    error_signal = Signal(str, str)
    finished_signal = Signal()

    def __init__(self, src_path):
        super().__init__()
        self.src_path = Path(src_path)
        self.normal_file_size = 4 * 1024 * 1024
        self.ndc = Path("preloader_path/boot1.bin")
        self._current_loop = None
        self._current_req_id = None
        self._ask_result = False

    def ask_user(self, key):
        self._current_req_id = (self._current_req_id or 0) + 1
        req_id = self._current_req_id
        self.ask_signal.emit(key, req_id)
        loop = QEventLoop()
        self._current_loop = loop
        loop.exec()
        self._current_loop = None
        return self._ask_result

    def on_user_decision(self, req_id, result):
        if req_id == self._current_req_id and self._current_loop:
            self._ask_result = result
            self._current_loop.quit()

    def auto_path_preloader(self, flag: bytes, fastboot_lock_state: bytes, file_size: int):
        with open(self.ndc, "r+b") as f:
            data = f.read()
            code_offset = data[0x20d] * 256
            code_offset1 = data[0x21d]
            code_offset2 = data[0x211]
            code_offset3 = data[0x212]
            code_offset4 = data[0x221]
            code_offset5 = data[0x222]
            data_raw = data[code_offset : file_size - 0x3000]
            self.log_signal.emit(f"Write range zeros: 0x{code_offset:X}:0x2000")
            f.seek(code_offset)
            f.write(b'\x00' * (file_size - code_offset))
            if 0x2000 - code_offset >= 0:
                self.log_signal.emit(f"Jump offset code: 0x{code_offset:X} to 0x2000")
                f.seek(0x2000)
                f.write(data_raw)
            else:
                self.log_signal.emit("Initial code indentation causes 0x2000. Script cannot work correctly")
                self.error_signal.emit("error_offset", "")
                return False
            self.log_signal.emit("--------------------\nChange BRLYT offset")
            self.log_signal.emit(f"0x20d: {int(code_offset/256):02x} -> 20")
            f.seek(0x20D)
            f.write(b"\x20")
            self.log_signal.emit(f"0x21d: {code_offset1:02x} -> 20")
            f.seek(0x21D)
            f.write(b"\x20")
            self.log_signal.emit(f"0x211: {code_offset2:02x} -> 10")
            f.seek(0x211)
            f.write(b"\x10")
            self.log_signal.emit(f"0x212: {code_offset3:02x} -> 10")
            f.seek(0x212)
            f.write(b"\x10")
            self.log_signal.emit(f"0x221: {code_offset4:02x} -> 10")
            f.seek(0x221)
            f.write(b"\x10")
            self.log_signal.emit(f"0x222: {code_offset5:02x} -> 10")
            f.seek(0x222)
            f.write(b"\x10")
            self.log_signal.emit("--------------------\nWrite flag block to: 0x1000")
            f.seek(0x1000)
            f.write(flag)
            self.log_signal.emit(f"Fastboot lock state: 0x{fastboot_lock_state[0]:02x} -> 00")
            f.seek(0x104C)
            f.write(b"\x00")
        self.log_signal.emit(f"Create new preloader to: {self.ndc.resolve()}")
        return True

    def read_flag_block(self, file_size: int):
        pattern_flag = bytes.fromhex("41 4E 44 5F 52 4F 4D 49 4E 46 4F 5F 76")
        with open(self.ndc, "rb") as f:
            data = f.read()
            patt_stat = data.find(pattern_flag)
            if patt_stat != -1:
                self.log_signal.emit("Flag block find state: successfully")
                flag = data[patt_stat : patt_stat + 0x78]
                patt_lock = patt_stat + 0x4C
                fastboot_lock_state = data[patt_lock : (patt_lock + 1)]
            else:
                self.log_signal.emit("Magic numbers of flag block not found! Use manual instruction or contact me.")
                if self.ask_user("ask_flag_not_found"):
                    flag = b""
                    fastboot_lock_state = b"\x00"
                else:
                    self.error_signal.emit("error_cancelled", "")
                    return False
            if fastboot_lock_state[0] == 0x22:
                self.log_signal.emit("lock state: 22 (lock)")
            else:
                self.log_signal.emit("lock state: unlock")
            return self.auto_path_preloader(flag, fastboot_lock_state, file_size)

    def check_validation(self):
        file_size = self.ndc.stat().st_size
        if file_size != self.normal_file_size:
            self.log_signal.emit(f"Expected file size - 0x400000 byte, received size - {hex(file_size)}.")
            if not self.ask_user("ask_ignore_size"):
                self.error_signal.emit("error_cancelled", "")
                return False
            self.log_signal.emit(f"continue with file with size difference {hex(self.normal_file_size - file_size)} byte")
        with open(self.ndc, "rb") as f:
            magic_sign = f.read(0x10)
        if magic_sign.startswith(b"UFS_BOOT"):
            self.log_signal.emit("Memory type: UFS_BOOT")
        elif magic_sign.startswith(b"EMMC_BOOT"):
            self.log_signal.emit("Memory type: EMMC_BOOT")
        elif magic_sign.startswith(b"COMBO_BOOT"):
            self.log_signal.emit("Memory type: COMBO_BOOT (UFS)")
        elif magic_sign.startswith(b"MMM\x018\x00\x00\x00FILE_INF"):
            self.log_signal.emit("Memory type: RAW\n\nThis script cannot work with RAW preloader.\nRAW preloader is not a full-fledged boot1 region and does not have an offset header, which this script works with.")
            self.error_signal.emit("error_raw", "")
            return False
        else:
            self.log_signal.emit("Memory type: Unknown")
            if not self.ask_user("ask_unknown_type"):
                self.error_signal.emit("error_cancelled", "")
                return False
        return self.read_flag_block(file_size)

    def copy_preloader(self):
        self.ndc.parent.mkdir(exist_ok=True)
        while True:
            try:
                with open(self.src_path, "rb") as f_src:
                    with open(self.ndc, "wb") as f_dst:
                        f_dst.write(f_src.read())
                self.log_signal.emit("boot1.bin found state: successfully")
                break
            except FileNotFoundError:
                self.log_signal.emit("boot1.bin found state: fail\nPlease use mtkclient to read your preloader (boot1).")
                if not self.ask_user("ask_retry"):
                    self.error_signal.emit("error_cancelled", "")
                    return False
        return self.check_validation()

    def run(self):
        try:
            if self.copy_preloader():
                self.log_signal.emit("Processing completed!")
            else:
                self.log_signal.emit("Processing failed or cancelled.")
        except Exception as e:
            self.error_signal.emit("error_exception", str(e))
        finally:
            self.finished_signal.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(lang.get('window_title'))
        self.resize(700, 500)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        top_layout = QHBoxLayout()
        self.author_label = QLabel(lang.get('author'))
        top_layout.addWidget(self.author_label)
        top_layout.addStretch()
        self.lang_combo = QComboBox()
        self.lang_combo.addItems(['English', '中文'])
        self.lang_combo.currentIndexChanged.connect(self.change_language)
        top_layout.addWidget(self.lang_combo)
        layout.addLayout(top_layout)
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel(lang.get('src_label')))
        self.src_edit = QLineEdit()
        self.src_edit.setPlaceholderText(lang.get('src_label'))
        file_layout.addWidget(self.src_edit)
        self.browse_btn = QPushButton(lang.get('browse_btn'))
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        self.start_btn = QPushButton(lang.get('start_btn'))
        self.start_btn.clicked.connect(self.start_processing)
        layout.addWidget(self.start_btn)
        self.thread = None
        self.worker = None

    def change_language(self, index):
        lang.set_language('en' if index == 0 else 'zh')
        self.setWindowTitle(lang.get('window_title'))
        self.author_label.setText(lang.get('author'))
        self.src_edit.setPlaceholderText(lang.get('src_label'))
        self.browse_btn.setText(lang.get('browse_btn'))
        self.start_btn.setText(lang.get('start_btn'))
        for i in range(file_layout.count()):
            widget = file_layout.itemAt(i).widget()
            if isinstance(widget, QLabel) and widget.text() in ['Source file:', '源文件：']:
                widget.setText(lang.get('src_label'))
                break

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, lang.get('src_label'), "", "Binary files (*.bin);;All files (*)")
        if file_path:
            self.src_edit.setText(file_path)

    def log(self, message):
        self.log_text.append(message)

    def start_processing(self):
        src = self.src_edit.text().strip()
        if not src:
            QMessageBox.warning(self, lang.get('window_title'), lang.get('src_label') + " " + lang.get('ask_continue'))
            return
        if not Path(src).exists():
            QMessageBox.warning(self, lang.get('window_title'), lang.get('src_label') + " " + lang.get('ask_continue'))
            return
        self.start_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)
        self.log_text.clear()
        self.thread = QThread()
        self.worker = PreloaderWorker(src)
        self.worker.moveToThread(self.thread)
        self.worker.log_signal.connect(self.log)
        self.worker.error_signal.connect(self.on_error)
        self.worker.finished_signal.connect(self.on_finished)
        self.worker.ask_signal.connect(self.on_ask)
        self.thread.started.connect(self.worker.run)
        self.thread.start()

    def on_ask(self, key, req_id):
        reply = QMessageBox.question(self, lang.get('window_title'), lang.get(key),
                                     QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
        result = (reply == QMessageBox.Yes)
        self.worker.on_user_decision(req_id, result)

    def on_error(self, key, detail):
        msg = lang.get(key, detail) if detail else lang.get(key)
        QMessageBox.critical(self, lang.get('window_title'), msg)

    def on_finished(self):
        self.thread.quit()
        self.thread.wait()
        self.thread = None
        self.worker = None
        self.start_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)

    def closeEvent(self, event):
        if self.thread and self.thread.isRunning():
            self.thread.quit()
            self.thread.wait()
        event.accept()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())
