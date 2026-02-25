import sys
from pathlib import Path
from PySide6.QtCore import QObject, Signal, QThread, QEventLoop
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QPushButton, QLineEdit, QFileDialog,
                               QTextEdit, QMessageBox, QLabel)

class PreloaderWorker(QObject):
    log_signal = Signal(str)
    ask_signal = Signal(str, int)
    error_signal = Signal(str)
    finished_signal = Signal()

    def __init__(self, src_path):
        super().__init__()
        self.src_path = Path(src_path)
        self.normal_file_size = 4 * 1024 * 1024
        self.ndc = Path("preloader_path/boot1.bin")
        self._current_loop = None
        self._current_req_id = None
        self._ask_result = False

    def ask_user(self, question):
        self._current_req_id = (self._current_req_id or 0) + 1
        req_id = self._current_req_id
        self.ask_signal.emit(question, req_id)
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
                self.error_signal.emit("错误：代码偏移量大于0x2000，无法处理")
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
                choice = self.ask_user("未找到标志块，是否继续？（没有标志块可能导致后续失败）")
                if choice:
                    flag = b""
                    fastboot_lock_state = b"\x00"
                else:
                    self.error_signal.emit("用户取消操作")
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
            choice = self.ask_user("文件大小不匹配，是否忽略并继续？")
            if not choice:
                self.error_signal.emit("用户取消操作")
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
            self.error_signal.emit("错误：RAW格式的预加载器无法处理")
            return False
        else:
            self.log_signal.emit("Memory type: Unknown")
            choice = self.ask_user("未知文件类型，继续可能会导致不可预知的结果，是否继续？")
            if not choice:
                self.error_signal.emit("用户取消操作")
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
                self.log_signal.emit("boot1.bin found state: fail\n请使用mtkclient读取您的预加载器(boot1)。")
                choice = self.ask_user("文件未找到，是否重试？")
                if not choice:
                    self.error_signal.emit("用户取消操作")
                    return False
        return self.check_validation()

    def run(self):
        try:
            if self.copy_preloader():
                self.log_signal.emit("处理完成！")
            else:
                self.log_signal.emit("处理失败或已取消。")
        except Exception as e:
            self.error_signal.emit(f"发生异常：{str(e)}")
        finally:
            self.finished_signal.emit()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("PLPatcher")
        self.resize(700, 500)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QVBoxLayout(central)
        file_layout = QHBoxLayout()
        file_layout.addWidget(QLabel("源文件："))
        self.src_edit = QLineEdit()
        self.src_edit.setPlaceholderText("请选择 boot1.bin 文件")
        file_layout.addWidget(self.src_edit)
        self.browse_btn = QPushButton("浏览...")
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)
        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)
        self.start_btn = QPushButton("开始处理")
        self.start_btn.clicked.connect(self.start_processing)
        layout.addWidget(self.start_btn)
        self.thread = None
        self.worker = None

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "选择boot1.bin文件", "", "Binary files (*.bin);;All files (*)")
        if file_path:
            self.src_edit.setText(file_path)

    def log(self, message):
        self.log_text.append(message)

    def start_processing(self):
        src = self.src_edit.text().strip()
        if not src:
            QMessageBox.warning(self, "警告", "请先选择源文件！")
            return
        if not Path(src).exists():
            QMessageBox.warning(self, "警告", "源文件不存在！")
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

    def on_ask(self, question, req_id):
        reply = QMessageBox.question(self, "询问", question,
                                     QMessageBox.Yes | QMessageBox.No,
                                     QMessageBox.No)
        result = (reply == QMessageBox.Yes)
        self.worker.on_user_decision(req_id, result)

    def on_error(self, msg):
        QMessageBox.critical(self, "错误", msg)

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
