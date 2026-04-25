import sys
import shutil
from pathlib import Path
from PySide6.QtCore import QObject, Signal, QThread, QEventLoop, QProcess, QSettings
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout,
                               QHBoxLayout, QPushButton, QLineEdit, QFileDialog,
                               QTextEdit, QMessageBox, QLabel, QComboBox, QMenuBar,
                               QMenu, QDialog, QDialogButtonBox, QFormLayout, QCheckBox,
                               QSpinBox, QFileDialog)
from PySide6.QtGui import QAction, QDesktopServices
from PySide6.QtCore import QUrl

class LanguageManager:
    _instance = None
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance.current_lang = 'en'
            cls._instance.strings = {
                'en': {
                    'window_title': 'PreLoader Patcher-v2.0.0',
                    'src_label': 'Source file:',
                    'output_label': 'Output filename (optional):',
                    'output_placeholder': 'Leave empty to use source filename',
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
                    'author': 'Dev. Shocked-Cat | Hy1Fly Fork',
                    'menu_file': 'File',
                    'menu_new': 'New',
                    'menu_open': 'Open...',
                    'menu_close': 'Close',
                    'menu_save_as': 'Save As...',
                    'menu_recent': 'Recent Files',
                    'menu_exit': 'Exit',
                    'menu_tools': 'Tools',
                    'menu_options': 'Options...',
                    'submenu_adb': 'ADB',
                    'submenu_fastboot': 'Fastboot',
                    'tool_adb_reboot_bootloader': 'Reboot to Bootloader',
                    'tool_adb_reboot_fastboot': 'Reboot to Fastboot',
                    'tool_fastboot_unlock': 'Flashing Unlock',
                    'tool_fastboot_reboot': 'Reboot Device',
                    'tool_fastboot_reboot_bootloader': 'Reboot to Bootloader',
                    'menu_help': 'Help',
                    'help_website': 'Official Website',
                    'help_about': 'About',
                    'about_title': 'About',
                    'about_text': '<h3>PreLoaderPatcher</h3><p>Version 2.0</p><p>Tool for patching MediaTek Preloader to unlock bootloader.</p><p>Developed by Shocked-Cat | Hy1Fly Fork</p><p>License: GPL-3</p>',
                    'website_url': 'https://github.com/LF-Repo/PLPatcher',
                    'tool_platform_tools_missing': 'platform-tools folder not found!\nPlease check the path in Options.',
                    'tool_cmd_failed': 'Command failed:\n{}',
                    'save_as_title': 'Save Patched Preloader As',
                    'save_as_filter': 'Binary files (*.bin);;All files (*)',
                    'save_as_not_ready': 'No patched file available yet.\nPlease run processing first.',
                    'save_as_success': 'File saved to:\n{}',
                    'save_as_error': 'Failed to save file:\n{}',
                    'auto_save_success': 'Auto-saved to: {}',
                    'auto_save_error': 'Auto-save failed: {}',
                    'new_session': 'Cleared current file selection.',
                    'close_session': 'Closed current file.',
                    'options_title': 'Settings',
                    'options_platform_tools': 'platform-tools folder:',
                    'options_browse': 'Browse...',
                    'options_default_output_dir': 'Default output directory:',
                    'options_auto_save': 'Automatically save patched file after processing',
                    'options_verbose_log': 'Verbose logging (show all details)',
                    'options_clear_log_before_start': 'Clear log before starting processing',
                    'options_confirm_overwrite': 'Confirm before overwriting existing file',
                    'options_auto_confirm_fastboot_unlock': 'Automatically confirm "fastboot flashing unlock" (no prompt)',
                    'select_default_output_dir': 'Select Default Output Directory',
                    'recent_file_not_exist': 'File does not exist:\n{}',
                },
                'zh': {
                    'window_title': 'PreLoader Patcher-V2.0.0',
                    'src_label': '源文件：',
                    'output_label': '输出文件名（可选）：',
                    'output_placeholder': '留空则使用源文件名',
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
                    'author': 'Dev. Shocked-Cat | Hy1Fly Fork',
                    'menu_file': '文件',
                    'menu_new': '新建',
                    'menu_open': '打开...',
                    'menu_close': '关闭',
                    'menu_save_as': '另存为...',
                    'menu_recent': '最近文件',
                    'menu_exit': '退出',
                    'menu_tools': '工具',
                    'menu_options': '选项...',
                    'submenu_adb': 'ADB',
                    'submenu_fastboot': 'Fastboot',
                    'tool_adb_reboot_bootloader': '重启到 Bootloader',
                    'tool_adb_reboot_fastboot': '重启到 Fastboot',
                    'tool_fastboot_unlock': '解锁 Bootloader',
                    'tool_fastboot_reboot': '重启设备',
                    'tool_fastboot_reboot_bootloader': '重启到 Bootloader',
                    'menu_help': '帮助',
                    'help_website': '官方网站',
                    'help_about': '关于',
                    'about_title': '关于',
                    'about_text': '<h3>PreLoader Patcher</h3><p>版本 2.0</p><p>用于修补联发科 Preloader 以解锁 Bootloader 的工具。</p><p>开发者：Shocked-Cat | Hy1Fly 分支</p><p>许可证：GPL-3</p>',
                    'website_url': 'https://github.com/LF-Repo/PLPatcher',
                    'tool_platform_tools_missing': '未找到 platform-tools 文件夹！\n请检查选项中的路径。',
                    'tool_cmd_failed': '命令执行失败：\n{}',
                    'save_as_title': '保存修补后的 Preloader 为',
                    'save_as_filter': '二进制文件 (*.bin);;所有文件 (*)',
                    'save_as_not_ready': '尚未生成修补后的文件。\n请先执行处理。',
                    'save_as_success': '文件已保存至：\n{}',
                    'save_as_error': '保存文件失败：\n{}',
                    'auto_save_success': '已自动保存至：{}',
                    'auto_save_error': '自动保存失败：{}',
                    'new_session': '已清空当前选择。',
                    'close_session': '已关闭当前文件。',
                    'options_title': '设置',
                    'options_platform_tools': 'platform-tools 文件夹：',
                    'options_browse': '浏览...',
                    'options_default_output_dir': '默认输出目录：',
                    'options_auto_save': '处理完成后自动保存修补文件',
                    'options_verbose_log': '详细日志（显示所有细节）',
                    'options_clear_log_before_start': '开始处理前清空日志',
                    'options_confirm_overwrite': '覆盖已有文件前询问',
                    'options_auto_confirm_fastboot_unlock': '自动确认 "fastboot flashing unlock"（不弹出确认）',
                    'select_default_output_dir': '选择默认输出目录',
                    'recent_file_not_exist': '文件不存在：\n{}',
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

    def __init__(self, src_path, output_name, verbose=False):
        super().__init__()
        self.src_path = Path(src_path)
        self.output_name = Path(output_name).name
        self.normal_file_size = 4 * 1024 * 1024
        self.ndc = Path("preloader_path") / self.output_name
        self.verbose = verbose
        self._current_loop = None
        self._current_req_id = None
        self._ask_result = False

    def log(self, msg, force=False):
        if self.verbose or force:
            self.log_signal.emit(msg)

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
            self.log(f"Write range zeros: 0x{code_offset:X}:0x2000")
            f.seek(code_offset)
            f.write(b'\x00' * (file_size - code_offset))
            if 0x2000 - code_offset >= 0:
                self.log(f"Jump offset code: 0x{code_offset:X} to 0x2000")
                f.seek(0x2000)
                f.write(data_raw)
            else:
                self.log("Initial code indentation causes 0x2000. Script cannot work correctly", force=True)
                self.error_signal.emit("error_offset", "")
                return False
            self.log("--------------------\nChange BRLYT offset")
            self.log(f"0x20d: {int(code_offset/256):02x} -> 20")
            f.seek(0x20D)
            f.write(b"\x20")
            self.log(f"0x21d: {code_offset1:02x} -> 20")
            f.seek(0x21D)
            f.write(b"\x20")
            self.log(f"0x211: {code_offset2:02x} -> 10")
            f.seek(0x211)
            f.write(b"\x10")
            self.log(f"0x212: {code_offset3:02x} -> 10")
            f.seek(0x212)
            f.write(b"\x10")
            self.log(f"0x221: {code_offset4:02x} -> 10")
            f.seek(0x221)
            f.write(b"\x10")
            self.log(f"0x222: {code_offset5:02x} -> 10")
            f.seek(0x222)
            f.write(b"\x10")
            self.log("--------------------\nWrite flag block to: 0x1000")
            f.seek(0x1000)
            f.write(flag)
            self.log(f"Fastboot lock state: 0x{fastboot_lock_state[0]:02x} -> 00")
            f.seek(0x104C)
            f.write(b"\x00")
        self.log(f"Create new preloader to: {self.ndc.resolve()}")
        return True

    def read_flag_block(self, file_size: int):
        pattern_flag = bytes.fromhex("41 4E 44 5F 52 4F 4D 49 4E 46 4F 5F 76")
        with open(self.ndc, "rb") as f:
            data = f.read()
            patt_stat = data.find(pattern_flag)
            if patt_stat != -1:
                self.log("Flag block find state: successfully")
                flag = data[patt_stat : patt_stat + 0x78]
                patt_lock = patt_stat + 0x4C
                fastboot_lock_state = data[patt_lock : (patt_lock + 1)]
            else:
                self.log("Magic numbers of flag block not found! Use manual instruction or contact me.", force=True)
                if self.ask_user("ask_flag_not_found"):
                    flag = b""
                    fastboot_lock_state = b"\x00"
                else:
                    self.error_signal.emit("error_cancelled", "")
                    return False
            if fastboot_lock_state[0] == 0x22:
                self.log("lock state: 22 (lock)")
            elif fastboot_lock_state[0] == 0x11:
                self.log("lock state: 11 (hard lock)")
            else:
                self.log(f"lock state: {fastboot_lock_state[0]} (unlock)")
            return self.auto_path_preloader(flag, fastboot_lock_state, file_size)

    def check_validation(self):
        file_size = self.ndc.stat().st_size
        if file_size != self.normal_file_size:
            self.log(f"Expected file size - 0x400000 byte, received size - {hex(file_size)}.", force=True)
            if not self.ask_user("ask_ignore_size"):
                self.error_signal.emit("error_cancelled", "")
                return False
            self.log(f"continue with file with size difference {hex(self.normal_file_size - file_size)} byte")
        with open(self.ndc, "rb") as f:
            magic_sign = f.read(0x10)
        if magic_sign.startswith(b"UFS_BOOT"):
            self.log("Memory type: UFS_BOOT")
        elif magic_sign.startswith(b"EMMC_BOOT"):
            self.log("Memory type: EMMC_BOOT")
        elif magic_sign.startswith(b"COMBO_BOOT"):
            self.log("Memory type: COMBO_BOOT (UFS)")
        elif magic_sign.startswith(b"MMM\x018\x00\x00\x00FILE_INF"):
            self.log("Memory type: RAW\n\nThis script cannot work with RAW preloader.\nRAW preloader is not a full-fledged boot1 region and does not have an offset header, which this script works with.", force=True)
            self.error_signal.emit("error_raw", "")
            return False
        else:
            self.log("Memory type: Unknown", force=True)
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
                self.log("boot1.bin found state: successfully")
                break
            except FileNotFoundError:
                self.log("boot1.bin found state: fail\nPlease use mtkclient to read your preloader (boot1).", force=True)
                if not self.ask_user("ask_retry"):
                    self.error_signal.emit("error_cancelled", "")
                    return False
        return self.check_validation()

    def run(self):
        try:
            if self.copy_preloader():
                self.log("Processing completed!", force=True)
            else:
                self.log("Processing failed or cancelled.", force=True)
        except Exception as e:
            self.error_signal.emit("error_exception", str(e))
        finally:
            self.finished_signal.emit()

class OptionsDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle(lang.get('options_title'))
        self.setModal(True)
        layout = QFormLayout(self)

        self.platform_tools_edit = QLineEdit()
        self.platform_tools_edit.setText(str(parent.platform_tools_path) if parent else "")
        self.browse_btn = QPushButton(lang.get('options_browse'))
        self.browse_btn.clicked.connect(lambda: self.browse_folder(self.platform_tools_edit))
        path_layout = QHBoxLayout()
        path_layout.addWidget(self.platform_tools_edit)
        path_layout.addWidget(self.browse_btn)
        layout.addRow(lang.get('options_platform_tools'), path_layout)

        self.default_output_edit = QLineEdit()
        self.default_output_edit.setText(parent.default_output_dir if parent else "")
        self.default_output_browse = QPushButton(lang.get('options_browse'))
        self.default_output_browse.clicked.connect(lambda: self.browse_folder(self.default_output_edit, is_dir=True))
        default_layout = QHBoxLayout()
        default_layout.addWidget(self.default_output_edit)
        default_layout.addWidget(self.default_output_browse)
        layout.addRow(lang.get('options_default_output_dir'), default_layout)

        self.auto_save_check = QCheckBox()
        self.auto_save_check.setChecked(parent.auto_save if parent else False)
        layout.addRow(lang.get('options_auto_save'), self.auto_save_check)

        self.verbose_log_check = QCheckBox()
        self.verbose_log_check.setChecked(parent.verbose_log if parent else False)
        layout.addRow(lang.get('options_verbose_log'), self.verbose_log_check)

        self.clear_log_check = QCheckBox()
        self.clear_log_check.setChecked(parent.clear_log_before_start if parent else True)
        layout.addRow(lang.get('options_clear_log_before_start'), self.clear_log_check)

        self.confirm_overwrite_check = QCheckBox()
        self.confirm_overwrite_check.setChecked(parent.confirm_overwrite if parent else True)
        layout.addRow(lang.get('options_confirm_overwrite'), self.confirm_overwrite_check)

        self.auto_fastboot_unlock_check = QCheckBox()
        self.auto_fastboot_unlock_check.setChecked(parent.auto_confirm_fastboot_unlock if parent else False)
        layout.addRow(lang.get('options_auto_confirm_fastboot_unlock'), self.auto_fastboot_unlock_check)

        self.button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)
        layout.addRow(self.button_box)

    def browse_folder(self, line_edit, is_dir=False):
        if is_dir:
            folder = QFileDialog.getExistingDirectory(self, lang.get('select_default_output_dir'))
        else:
            folder = QFileDialog.getExistingDirectory(self, lang.get('options_browse'))
        if folder:
            line_edit.setText(folder)

    def get_platform_tools_path(self):
        return Path(self.platform_tools_edit.text())

    def get_default_output_dir(self):
        return self.default_output_edit.text()

    def get_auto_save(self):
        return self.auto_save_check.isChecked()

    def get_verbose_log(self):
        return self.verbose_log_check.isChecked()

    def get_clear_log(self):
        return self.clear_log_check.isChecked()

    def get_confirm_overwrite(self):
        return self.confirm_overwrite_check.isChecked()

    def get_auto_fastboot_unlock(self):
        return self.auto_fastboot_unlock_check.isChecked()

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.settings = QSettings("Hy1Fly", "PLPatcher")
        self.platform_tools_path = Path(self.settings.value("platform_tools_path", str(Path.cwd() / "platform-tools")))
        self.default_output_dir = self.settings.value("default_output_dir", "")
        self.auto_save = self.settings.value("auto_save", False, type=bool)
        self.verbose_log = self.settings.value("verbose_log", False, type=bool)
        self.clear_log_before_start = self.settings.value("clear_log_before_start", True, type=bool)
        self.confirm_overwrite = self.settings.value("confirm_overwrite", True, type=bool)
        self.auto_confirm_fastboot_unlock = self.settings.value("auto_confirm_fastboot_unlock", False, type=bool)

        self.recent_files = self.settings.value("recent_files", [])
        if not isinstance(self.recent_files, list):
            self.recent_files = []
        self.recent_files = [f for f in self.recent_files if Path(f).exists()]
        self.max_recent = 5

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
        self.src_label = QLabel(lang.get('src_label'))
        file_layout.addWidget(self.src_label)
        self.src_edit = QLineEdit()
        self.src_edit.setPlaceholderText(lang.get('src_label'))
        file_layout.addWidget(self.src_edit)
        self.browse_btn = QPushButton(lang.get('browse_btn'))
        self.browse_btn.clicked.connect(self.browse_file)
        file_layout.addWidget(self.browse_btn)
        layout.addLayout(file_layout)

        output_layout = QHBoxLayout()
        self.output_label = QLabel(lang.get('output_label'))
        output_layout.addWidget(self.output_label)
        self.output_edit = QLineEdit()
        self.output_edit.setPlaceholderText(lang.get('output_placeholder'))
        output_layout.addWidget(self.output_edit)
        layout.addLayout(output_layout)

        self.log_text = QTextEdit()
        self.log_text.setReadOnly(True)
        layout.addWidget(self.log_text)

        self.start_btn = QPushButton(lang.get('start_btn'))
        self.start_btn.clicked.connect(self.start_processing)
        layout.addWidget(self.start_btn)

        self.create_menu_bar()
        self.update_recent_menu()

        self.thread = None
        self.worker = None

    def create_menu_bar(self):
        menubar = self.menuBar()

        self.file_menu = QMenu(lang.get('menu_file'), self)
        menubar.addMenu(self.file_menu)

        self.new_action = QAction(lang.get('menu_new'), self)
        self.new_action.triggered.connect(self.new_session)
        self.file_menu.addAction(self.new_action)

        self.open_action = QAction(lang.get('menu_open'), self)
        self.open_action.triggered.connect(self.browse_file)
        self.file_menu.addAction(self.open_action)

        self.close_action = QAction(lang.get('menu_close'), self)
        self.close_action.triggered.connect(self.close_session)
        self.file_menu.addAction(self.close_action)

        self.file_menu.addSeparator()

        self.save_as_action = QAction(lang.get('menu_save_as'), self)
        self.save_as_action.triggered.connect(self.save_as_file)
        self.file_menu.addAction(self.save_as_action)

        self.file_menu.addSeparator()

        self.recent_menu = QMenu(lang.get('menu_recent'), self)
        self.file_menu.addMenu(self.recent_menu)

        self.file_menu.addSeparator()

        self.exit_action = QAction(lang.get('menu_exit'), self)
        self.exit_action.triggered.connect(self.close)
        self.file_menu.addAction(self.exit_action)

        self.tools_menu = QMenu(lang.get('menu_tools'), self)
        menubar.addMenu(self.tools_menu)

        self.options_action = QAction(lang.get('menu_options'), self)
        self.options_action.triggered.connect(self.show_options_dialog)
        self.tools_menu.addAction(self.options_action)
        self.tools_menu.addSeparator()

        self.adb_menu = QMenu(lang.get('submenu_adb'), self)
        self.tools_menu.addMenu(self.adb_menu)
        self.adb_reboot_bootloader_action = QAction(lang.get('tool_adb_reboot_bootloader'), self)
        self.adb_reboot_bootloader_action.triggered.connect(lambda: self.run_tool_command("adb", ["reboot", "bootloader"]))
        self.adb_menu.addAction(self.adb_reboot_bootloader_action)
        self.adb_reboot_fastboot_action = QAction(lang.get('tool_adb_reboot_fastboot'), self)
        self.adb_reboot_fastboot_action.triggered.connect(lambda: self.run_tool_command("adb", ["reboot", "fastboot"]))
        self.adb_menu.addAction(self.adb_reboot_fastboot_action)

        self.fastboot_menu = QMenu(lang.get('submenu_fastboot'), self)
        self.tools_menu.addMenu(self.fastboot_menu)
        self.fastboot_unlock_action = QAction(lang.get('tool_fastboot_unlock'), self)
        if self.auto_confirm_fastboot_unlock:
            self.fastboot_unlock_action.triggered.connect(lambda: self.run_tool_command("fastboot", ["flashing", "unlock"]))
        else:
            self.fastboot_unlock_action.triggered.connect(self.run_fastboot_unlock_with_confirm)
        self.fastboot_menu.addAction(self.fastboot_unlock_action)
        self.fastboot_reboot_action = QAction(lang.get('tool_fastboot_reboot'), self)
        self.fastboot_reboot_action.triggered.connect(lambda: self.run_tool_command("fastboot", ["reboot"]))
        self.fastboot_menu.addAction(self.fastboot_reboot_action)
        self.fastboot_reboot_bootloader_action = QAction(lang.get('tool_fastboot_reboot_bootloader'), self)
        self.fastboot_reboot_bootloader_action.triggered.connect(lambda: self.run_tool_command("fastboot", ["reboot", "bootloader"]))
        self.fastboot_menu.addAction(self.fastboot_reboot_bootloader_action)

        self.help_menu = QMenu(lang.get('menu_help'), self)
        menubar.addMenu(self.help_menu)
        self.website_action = QAction(lang.get('help_website'), self)
        self.website_action.triggered.connect(self.open_website)
        self.help_menu.addAction(self.website_action)
        self.about_action = QAction(lang.get('help_about'), self)
        self.about_action.triggered.connect(self.show_about_dialog)
        self.help_menu.addAction(self.about_action)

    def update_recent_menu(self):
        self.recent_menu.clear()
        if not self.recent_files:
            empty_action = QAction("(No recent files)", self)
            empty_action.setEnabled(False)
            self.recent_menu.addAction(empty_action)
        else:
            for file_path in self.recent_files:
                action = QAction(Path(file_path).name, self)
                action.setData(file_path)
                action.triggered.connect(lambda checked, p=file_path: self.load_recent_file(p))
                self.recent_menu.addAction(action)
            self.recent_menu.addSeparator()
            clear_action = QAction("Clear Recent Files", self)
            clear_action.triggered.connect(self.clear_recent_files)
            self.recent_menu.addAction(clear_action)

    def add_recent_file(self, file_path):
        if file_path in self.recent_files:
            self.recent_files.remove(file_path)
        self.recent_files.insert(0, file_path)
        self.recent_files = self.recent_files[:self.max_recent]
        self.settings.setValue("recent_files", self.recent_files)
        self.update_recent_menu()

    def clear_recent_files(self):
        self.recent_files = []
        self.settings.setValue("recent_files", [])
        self.update_recent_menu()

    def load_recent_file(self, file_path):
        if not Path(file_path).exists():
            QMessageBox.warning(self, lang.get('window_title'), lang.get('recent_file_not_exist', file_path))
            self.recent_files.remove(file_path)
            self.settings.setValue("recent_files", self.recent_files)
            self.update_recent_menu()
            return
        self.src_edit.setText(file_path)
        if not self.output_edit.text().strip():
            self.output_edit.setText(Path(file_path).name)
        self.add_recent_file(file_path)

    def new_session(self):
        self.src_edit.clear()
        self.output_edit.clear()
        self.log_text.clear()
        self.log(lang.get('new_session'))

    def close_session(self):
        self.src_edit.clear()
        self.output_edit.clear()
        self.log(lang.get('close_session'))

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, lang.get('src_label'), "", "Binary files (*.bin);;All files (*)")
        if file_path:
            self.src_edit.setText(file_path)
            if not self.output_edit.text().strip():
                self.output_edit.setText(Path(file_path).name)
            self.add_recent_file(file_path)

    def save_as_file(self):
        if self.worker is None or not hasattr(self.worker, 'ndc') or not self.worker.ndc.exists():
            QMessageBox.warning(self, lang.get('window_title'), lang.get('save_as_not_ready'))
            return

        save_path, _ = QFileDialog.getSaveFileName(self, lang.get('save_as_title'), "",
                                                   lang.get('save_as_filter'))
        if save_path:
            try:
                if self.confirm_overwrite and Path(save_path).exists():
                    if QMessageBox.question(self, lang.get('window_title'), f"File exists. Overwrite?") != QMessageBox.Yes:
                        return
                shutil.copy2(self.worker.ndc, save_path)
                self.log(lang.get('save_as_success', save_path))
                QMessageBox.information(self, lang.get('window_title'), lang.get('save_as_success', save_path))
            except Exception as e:
                self.log(lang.get('save_as_error', str(e)))
                QMessageBox.critical(self, lang.get('window_title'), lang.get('save_as_error', str(e)))

    def show_options_dialog(self):
        dialog = OptionsDialog(self)
        if dialog.exec() == QDialog.Accepted:
            new_platform_path = dialog.get_platform_tools_path()
            if new_platform_path != self.platform_tools_path:
                self.platform_tools_path = new_platform_path
                self.settings.setValue("platform_tools_path", str(new_platform_path))
                self.log(f"platform-tools path updated to: {new_platform_path}")

            new_default_output = dialog.get_default_output_dir()
            if new_default_output != self.default_output_dir:
                self.default_output_dir = new_default_output
                self.settings.setValue("default_output_dir", new_default_output)
                self.log(f"Default output directory set to: {new_default_output}")

            self.auto_save = dialog.get_auto_save()
            self.settings.setValue("auto_save", self.auto_save)

            self.verbose_log = dialog.get_verbose_log()
            self.settings.setValue("verbose_log", self.verbose_log)

            self.clear_log_before_start = dialog.get_clear_log()
            self.settings.setValue("clear_log_before_start", self.clear_log_before_start)

            self.confirm_overwrite = dialog.get_confirm_overwrite()
            self.settings.setValue("confirm_overwrite", self.confirm_overwrite)

            old_auto_unlock = self.auto_confirm_fastboot_unlock
            self.auto_confirm_fastboot_unlock = dialog.get_auto_fastboot_unlock()
            self.settings.setValue("auto_confirm_fastboot_unlock", self.auto_confirm_fastboot_unlock)
            if old_auto_unlock != self.auto_confirm_fastboot_unlock:
                if self.auto_confirm_fastboot_unlock:
                    self.fastboot_unlock_action.triggered.disconnect()
                    self.fastboot_unlock_action.triggered.connect(lambda: self.run_tool_command("fastboot", ["flashing", "unlock"]))
                else:
                    self.fastboot_unlock_action.triggered.disconnect()
                    self.fastboot_unlock_action.triggered.connect(self.run_fastboot_unlock_with_confirm)

    def run_tool_command(self, tool, args):
        if not self.platform_tools_path.exists() or not self.platform_tools_path.is_dir():
            QMessageBox.critical(self, lang.get('window_title'), lang.get('tool_platform_tools_missing'))
            return

        exe_name = tool + (".exe" if sys.platform == "win32" else "")
        exe_path = self.platform_tools_path / exe_name
        if not exe_path.exists():
            QMessageBox.critical(self, lang.get('window_title'), lang.get('tool_platform_tools_missing'))
            return

        self.log(f"Running: {exe_path} {' '.join(args)}")
        process = QProcess(self)
        process.setProgram(str(exe_path))
        process.setArguments(args)
        process.setProcessChannelMode(QProcess.MergedChannels)

        process.readyReadStandardOutput.connect(lambda: self.log(process.readAllStandardOutput().data().decode(errors='replace')))
        process.readyReadStandardError.connect(lambda: self.log(process.readAllStandardError().data().decode(errors='replace')))
        process.finished.connect(lambda code, status: self.log(f"Command finished with code {code}"))
        process.errorOccurred.connect(lambda err: self.log(f"Process error: {err}"))

        process.start()

    def run_fastboot_unlock_with_confirm(self):
        if QMessageBox.question(self, lang.get('window_title'),
                                "WARNING: Unlocking bootloader will wipe all user data.\nContinue?",
                                QMessageBox.Yes | QMessageBox.No) == QMessageBox.Yes:
            self.run_tool_command("fastboot", ["flashing", "unlock"])

    def open_website(self):
        url = QUrl(lang.get('website_url'))
        if not QDesktopServices.openUrl(url):
            QMessageBox.warning(self, lang.get('window_title'), f"Failed to open URL: {url.toString()}")

    def show_about_dialog(self):
        QMessageBox.about(self, lang.get('about_title'), lang.get('about_text'))

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

        output_name = self.output_edit.text().strip()
        if not output_name:
            output_name = Path(src).name

        if self.clear_log_before_start:
            self.log_text.clear()

        self.start_btn.setEnabled(False)
        self.browse_btn.setEnabled(False)

        self.thread = QThread()
        self.worker = PreloaderWorker(src, output_name, verbose=self.verbose_log)
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
        if self.auto_save and self.worker and self.worker.ndc.exists():
            if self.default_output_dir:
                dest_dir = Path(self.default_output_dir)
                dest_dir.mkdir(parents=True, exist_ok=True)
                dest_file = dest_dir / self.worker.output_name
                try:
                    if self.confirm_overwrite and dest_file.exists():
                        if QMessageBox.question(self, lang.get('window_title'),
                                                f"File already exists: {dest_file}\nOverwrite?") != QMessageBox.Yes:
                            pass
                        else:
                            shutil.copy2(self.worker.ndc, dest_file)
                            self.log(lang.get('auto_save_success', dest_file))
                    else:
                        shutil.copy2(self.worker.ndc, dest_file)
                        self.log(lang.get('auto_save_success', dest_file))
                except Exception as e:
                    self.log(lang.get('auto_save_error', str(e)))
            else:
                self.log("Auto-save disabled: default output directory not set.")

        self.thread.quit()
        self.thread.wait()
        self.thread = None
        self.worker = None
        self.start_btn.setEnabled(True)
        self.browse_btn.setEnabled(True)

    def change_language(self, index):
        lang.set_language('en' if index == 0 else 'zh')
        self.setWindowTitle(lang.get('window_title'))
        self.author_label.setText(lang.get('author'))
        self.src_label.setText(lang.get('src_label'))
        self.src_edit.setPlaceholderText(lang.get('src_label'))
        self.output_label.setText(lang.get('output_label'))
        self.output_edit.setPlaceholderText(lang.get('output_placeholder'))
        self.browse_btn.setText(lang.get('browse_btn'))
        self.start_btn.setText(lang.get('start_btn'))

        self.file_menu.setTitle(lang.get('menu_file'))
        self.new_action.setText(lang.get('menu_new'))
        self.open_action.setText(lang.get('menu_open'))
        self.close_action.setText(lang.get('menu_close'))
        self.save_as_action.setText(lang.get('menu_save_as'))
        self.recent_menu.setTitle(lang.get('menu_recent'))
        self.exit_action.setText(lang.get('menu_exit'))

        self.tools_menu.setTitle(lang.get('menu_tools'))
        self.options_action.setText(lang.get('menu_options'))
        self.adb_menu.setTitle(lang.get('submenu_adb'))
        self.adb_reboot_bootloader_action.setText(lang.get('tool_adb_reboot_bootloader'))
        self.adb_reboot_fastboot_action.setText(lang.get('tool_adb_reboot_fastboot'))
        self.fastboot_menu.setTitle(lang.get('submenu_fastboot'))
        self.fastboot_unlock_action.setText(lang.get('tool_fastboot_unlock'))
        self.fastboot_reboot_action.setText(lang.get('tool_fastboot_reboot'))
        self.fastboot_reboot_bootloader_action.setText(lang.get('tool_fastboot_reboot_bootloader'))

        self.help_menu.setTitle(lang.get('menu_help'))
        self.website_action.setText(lang.get('help_website'))
        self.about_action.setText(lang.get('help_about'))

        self.update_recent_menu()

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
