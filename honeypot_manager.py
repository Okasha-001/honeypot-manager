import sys
import time
import json
import os
import paramiko
import re
import threading
import subprocess
import html
import hashlib
import math
from datetime import datetime, timedelta

from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QMessageBox, QTabWidget, QProgressBar, QFrame, 
                             QGridLayout, QComboBox, QScrollArea, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QDialog, QDialogButtonBox, 
                             QTextEdit, QFormLayout, QSystemTrayIcon, QStyle, QMenu,
                             QRadioButton, QButtonGroup, QAbstractItemView, QCheckBox, 
                             QInputDialog, QFileDialog, QListWidget, QListWidgetItem, 
                             QStyledItemDelegate, QGroupBox, QStackedWidget, QSizePolicy, 
                             QSpinBox, QDateEdit, QSplitter)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QTimer, QSize, QDateTime, QDate, QRectF, QPointF, QRect
from PyQt6.QtGui import QFont, QColor, QIcon, QAction, QClipboard, QBrush, QTextDocument, QPainter, QPen, QPainterPath

# -------------------------------------------------------------------------
# CONSTANTS & STYLING
# -------------------------------------------------------------------------
CONFIG_FILE = "sessions.json"
RULES_FILE = "alert_rules.json"
FILTERS_FILE = "saved_filters.json"
GLOBAL_SETTINGS_FILE = "global_settings.json"
IGNORE_LIST_FILE = "ignore_list.json"
RISK_RULES_FILE = "risk_rules.json"

# عدّل هذا المسار ليشير إلى ملف صوت التنبيه على جهازك المحلي (Client)
DEFAULT_ALARM_FILE = os.path.join(os.path.expanduser("~"), "Downloads", "alarm.mp3")

# مسارات ملفات اللوج على جهاز الفخ (Honeypot VM) عبر SSH - عدّلها لتطابق بيئتك
HONEYPOT_BASE_PATH = "/home/honeypot/honeypot-project"
COWRIE_LOG_PATH = f"{HONEYPOT_BASE_PATH}/cowrie-logs/cowrie.json"
DIONAEA_LOG_PATH = f"{HONEYPOT_BASE_PATH}/dionaea/dionaea-logs/dionaea.log"

# قائمة ألوان عالية التباين (30 لون مختلف)
DISTINCT_COLORS = [
    QColor("#FF0000"), QColor("#00FF00"), QColor("#0000FF"), QColor("#FFFF00"), 
    QColor("#00FFFF"), QColor("#FF00FF"), QColor("#FF4500"), QColor("#8A2BE2"), 
    QColor("#00FF7F"), QColor("#DC143C"), QColor("#00BFFF"), QColor("#F4A460"), 
    QColor("#FF1493"), QColor("#7FFF00"), QColor("#40E0D0"), QColor("#FFD700"), 
    QColor("#C71585"), QColor("#1E90FF"), QColor("#ADFF2F"), QColor("#FF6347"),
    QColor("#DA70D6"), QColor("#B0C4DE"), QColor("#FA8072"), QColor("#20B2AA"),
    QColor("#BA55D3"), QColor("#87CEEB"), QColor("#32CD32"), QColor("#FF69B4"),
    QColor("#CD5C5C"), QColor("#4682B4")
]

STYLE_SHEET = """
QMainWindow, QDialog { background-color: #1e1e1e; }
QWidget { color: #e0e0e0; font-family: 'Segoe UI', 'Roboto', sans-serif; font-size: 14px; }
QLabel#BrandTitle { font-size: 32px; font-weight: bold; color: #007acc; margin-bottom: 5px; }
QLabel#HeaderTitle { font-size: 26px; font-weight: bold; color: #007acc; }
QLabel#BrandSubtitle { font-size: 12px; font-weight: bold; color: #666; margin-bottom: 20px; letter-spacing: 2px; }
QTabWidget::pane { border: 1px solid #333; background: #252526; }
QTabBar::tab { background: #333333; color: #fff; padding: 10px 20px; border-top-left-radius: 4px; border-top-right-radius: 4px; }
QTabBar::tab:selected { background: #007acc; font-weight: bold; }
QPushButton { background-color: #0e639c; color: white; border: none; padding: 8px 15px; border-radius: 4px; font-weight: bold; }
QPushButton:hover { background-color: #1177bb; }
QPushButton#StopBtn { background-color: #d32f2f; }
QPushButton#StopBtn:hover { background-color: #b71c1c; }
QPushButton#LogoutBtn { background-color: #ff9800; color: #000; }
QPushButton#UnbanBtn { background-color: #2e7d32; padding: 4px; font-size: 12px; }
QPushButton#RestartBtn { background-color: #f57f17; color: #000; }
QLineEdit, QTextEdit, QComboBox, QSpinBox, QDateEdit { background-color: #3c3c3c; border: 1px solid #555; color: #fff; padding: 5px; border-radius: 3px; }
QTableWidget { background-color: #252526; gridline-color: #444; border: 1px solid #444; }
QHeaderView::section { background-color: #333; padding: 4px; border: 1px solid #444; }
QFrame#Card { background-color: #2d2d30; border-radius: 8px; border: 1px solid #3e3e42; }
QFrame#SectionHeader { background-color: #333; border-radius: 4px; padding: 5px; margin-top: 10px; }
QLabel#StatusLampOn { background-color: #00e676; border-radius: 8px; border: 1px solid #00a152; min-width: 16px; max-width: 16px; min-height: 16px; max-height: 16px; }
QLabel#StatusLampBlocked { background-color: #ff1744; border-radius: 8px; border: 1px solid #b2102f; min-width: 16px; max-width: 16px; min-height: 16px; max-height: 16px; }
QLabel#StatusLampOff { background-color: #757575; border-radius: 8px; border: 1px solid #616161; min-width: 16px; max-width: 16px; min-height: 16px; max-height: 16px; }
QListWidget { background-color: #252526; border: 1px solid #444; }
QGroupBox { border: 1px solid #444; border-radius: 5px; margin-top: 20px; font-weight: bold; }
QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 3px; color: #007acc; }
"""

# -------------------------------------------------------------------------
# CUSTOM DELEGATE
# -------------------------------------------------------------------------
class HTMLDelegate(QStyledItemDelegate):
    def paint(self, painter, option, index):
        painter.save()
        text = index.data(Qt.ItemDataRole.DisplayRole)
        doc = QTextDocument()
        doc.setHtml(text if text else "")
        style = option.widget.style()
        option.text = "" 
        style.drawControl(QStyle.ControlElement.CE_ItemViewItem, option, painter, option.widget)
        painter.translate(option.rect.left(), option.rect.top())
        clip = option.rect.translated(-option.rect.left(), -option.rect.top())
        doc.drawContents(painter, QRectF(clip)) 
        painter.restore()

    def sizeHint(self, option, index):
        doc = QTextDocument()
        doc.setHtml(index.data(Qt.ItemDataRole.DisplayRole) if index.data(Qt.ItemDataRole.DisplayRole) else "")
        return QSize(int(doc.idealWidth()) + 10, int(doc.size().height()))

# -------------------------------------------------------------------------
# CUSTOM WIDGETS (Donut Chart)
# -------------------------------------------------------------------------
class DonutChart(QWidget):
    def __init__(self, data=None, title="Stats", color_map=None):
        super().__init__()
        self.data = data if data else {"Waiting": 1}
        self.title = title
        self.color_map = color_map if color_map else {}
        self.setMinimumSize(180, 180)
        self.setMaximumHeight(250)

    def set_data(self, data, dynamic_colors=None):
        self.data = data
        if dynamic_colors:
            self.color_map.update(dynamic_colors)
        self.update()

    def get_legend_widget(self):
        legend_widget = QWidget()
        l_layout = QVBoxLayout(legend_widget)
        l_layout.setContentsMargins(0, 0, 0, 0)
        
        total = sum(self.data.values())
        if total == 0: return legend_widget

        sorted_keys = sorted(self.data.keys(), key=lambda k: self.data[k], reverse=True)

        for key in sorted_keys:
            value = self.data[key]
            color = self.color_map.get(key, QColor("#757575"))
            
            h_layout = QHBoxLayout()
            color_dot = QLabel("●")
            color_dot.setStyleSheet(f"color: {color.name()}; font-size: 18px;")
            color_dot.setFixedWidth(20)
            
            percent = (value / total) * 100
            label = QLabel(f"{key}: {value} ({percent:.1f}%)")
            
            h_layout.addWidget(color_dot)
            h_layout.addWidget(label)
            h_layout.addStretch()
            l_layout.addLayout(h_layout)
        
        l_layout.addStretch()
        return legend_widget

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        
        rect = self.rect()
        size = min(rect.width(), rect.height())
        outer_radius = (size - 20) / 2
        inner_radius = outer_radius * 0.6
        center = QPointF(rect.center()) 

        total = sum(self.data.values())
        if total == 0: 
            painter.setPen(QPen(QColor("#444"), 2))
            painter.setBrush(QBrush(QColor("#252526")))
            painter.drawEllipse(center, outer_radius, outer_radius)
            painter.setPen(QColor("white"))
            painter.setFont(QFont("Segoe UI", 12))
            painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"No Data")
            return

        start_angle = 90 * 16 
        keys = list(self.data.keys())
        keys.sort(key=lambda k: self.data[k], reverse=True) 
        
        for key in keys:
            value = self.data[key]
            percent = value / total
            span_angle = -percent * 360 * 16
            color = self.color_map.get(key, QColor("#757575"))
            
            path = QPainterPath()
            angle_rad = (start_angle / 16.0) * (math.pi / 180.0)
            
            start_x = math.cos(angle_rad) * inner_radius
            start_y = -math.sin(angle_rad) * inner_radius 
            
            path.moveTo(center + QPointF(start_x, start_y))
            path.arcTo(QRectF(center.x() - outer_radius, center.y() - outer_radius, 2*outer_radius, 2*outer_radius), 
                       start_angle/16.0, span_angle/16.0)
            path.arcTo(QRectF(center.x() - inner_radius, center.y() - inner_radius, 2*inner_radius, 2*inner_radius), 
                       (start_angle + span_angle)/16.0, -span_angle/16.0)
            path.closeSubpath()
            
            painter.setBrush(QBrush(color))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPath(path)
            
            start_angle += span_angle

        painter.setPen(QColor("white"))
        painter.setFont(QFont("Segoe UI", 16, QFont.Weight.Bold))
        painter.drawText(rect, Qt.AlignmentFlag.AlignCenter, f"{int(total)}\n{self.title}")

# -------------------------------------------------------------------------
# CONFIG MANAGER
# -------------------------------------------------------------------------
class ConfigManager:
    @staticmethod
    def load_json(file_path, default):
        if not os.path.exists(file_path): return default
        try:
             with open(file_path, 'r') as f: return json.load(f)
        except: return default

    @staticmethod
    def save_json(file_path, data):
        with open(file_path, 'w') as f: json.dump(data, f, indent=4)

    @staticmethod
    def load_sessions(): return ConfigManager.load_json(CONFIG_FILE, {})
    
    @staticmethod
    def save_session(host, port, user, password):
        data = ConfigManager.load_sessions()
        key = f"{user}@{host}"
        data[key] = {"host": host, "port": port, "user": user, "password": password}
        ConfigManager.save_json(CONFIG_FILE, data)

    @staticmethod
    def load_rules(): return ConfigManager.load_json(RULES_FILE, [])
    @staticmethod
    def save_rules(rules): ConfigManager.save_json(RULES_FILE, rules)

    @staticmethod
    def load_filters(): return ConfigManager.load_json(FILTERS_FILE, [])
    @staticmethod
    def save_filters(filters): ConfigManager.save_json(FILTERS_FILE, filters)

    @staticmethod
    def load_ignore_list(): return ConfigManager.load_json(IGNORE_LIST_FILE, [])
    @staticmethod
    def save_ignore_list(lst): ConfigManager.save_json(IGNORE_LIST_FILE, lst)

    @staticmethod
    def load_risk_rules(): return ConfigManager.load_json(RISK_RULES_FILE, {})
    @staticmethod
    def save_risk_rules(rules): ConfigManager.save_json(RISK_RULES_FILE, rules)

    @staticmethod
    def load_global_settings():
        defaults = {
            "audio_path": DEFAULT_ALARM_FILE,
            "alert_delay": 5, 
            "snooze_duration": 60,
            "auto_ban_enabled": False,
            "auto_ban_delay": 10, 
            "auto_close_port": False,
            "auto_stop_service": False
        }
        return ConfigManager.load_json(GLOBAL_SETTINGS_FILE, defaults)
    
    @staticmethod
    def save_global_settings(settings):
        ConfigManager.save_json(GLOBAL_SETTINGS_FILE, settings)

# -------------------------------------------------------------------------
# WORKER THREADS
# -------------------------------------------------------------------------
class SSHWorker(QThread):
    result_signal = pyqtSignal(str, str)
    data_signal = pyqtSignal(object)
    
    def __init__(self, host, port, user, password, command=None, task_type="connect"):
        super().__init__()
        self.host, self.port, self.user, self.password = host, port, user, password
        self.command = command
        self.task_type = task_type

    def run(self):
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, port=self.port, username=self.user, password=self.password, timeout=8)
           
            if self.task_type == "connect":
                self.result_signal.emit("success", "Connected")
                
            elif self.task_type == "execute":
                stdin, stdout, stderr = client.exec_command(self.command, get_pty=True)
                self.result_signal.emit("output", stdout.read().decode().strip() + "\n" + stderr.read().decode().strip())
                
            elif self.task_type == "check_full_status":
                stdin, stdout, stderr = client.exec_command("docker ps --format '{{.Names}}'")
                docker_out = stdout.read().decode().splitlines()
                stdin, stdout, stderr = client.exec_command("systemctl is-active filebeat")
                fb_out = stdout.read().decode().strip()
                self.data_signal.emit({"containers": docker_out, "filebeat": fb_out})
                
            elif self.task_type == "check_ports_security":
                cmd = f"netstat -tuln && echo '|||' && echo {self.password} | sudo -S iptables -L DOCKER-USER -n"
                stdin, stdout, stderr = client.exec_command(cmd)
                self.data_signal.emit(stdout.read().decode())
                
            elif self.task_type == "get_bans" or self.task_type == "check_ip_ban":
                cmd = f"echo {self.password} | sudo -S iptables -L DOCKER-USER -n --line-numbers"
                stdin, stdout, stderr = client.exec_command(cmd)
                self.data_signal.emit(stdout.read().decode())

            elif self.task_type == "fetch_logs" or self.task_type == "fetch_full_analysis":
                # For heavy lifting, ensure we read fully
                stdin, stdout, stderr = client.exec_command(self.command)
                self.data_signal.emit(stdout.read().decode(errors='ignore'))
                
            client.close()
        except Exception as e:
            self.result_signal.emit("error", str(e))
        finally:
            if client: client.close()

class LogMonitorWorker(QThread):
    log_batch_signal = pyqtSignal(list) 
    
    def __init__(self, host, port, user, password):
        super().__init__()
        self.host, self.port, self.user, self.password = host, port, user, password
        self.running = True
        self.buffer = []
        self.lock = threading.Lock()

    def run(self):
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(self.host, port=self.port, username=self.user, password=self.password)
            
            cmd = f"tail -f -n 0 {COWRIE_LOG_PATH} {DIONAEA_LOG_PATH}"
            stdin, stdout, stderr = client.exec_command(cmd, get_pty=True)
            
            flusher = threading.Thread(target=self.flush_buffer, daemon=True)
            flusher.start()

            for line in iter(stdout.readline, ""):
                if not self.running: break
                if line.strip():
                    if "==>" in line: continue 
                    with self.lock:
                        self.buffer.append(line.strip())
                    
        except Exception as e:
            print(f"Log Monitor Error: {e}")
        finally:
            if client: client.close()

    def flush_buffer(self):
        while self.running:
            time.sleep(0.1) 
            with self.lock:
                if self.buffer:
                    self.log_batch_signal.emit(list(self.buffer))
                    self.buffer.clear()

    def stop(self):
        self.running = False
        self.quit()

# -------------------------------------------------------------------------
# DIALOGS (Added RiskConfigDialog)
# -------------------------------------------------------------------------
class RiskConfigDialog(QDialog):
    def __init__(self, parent, event_name):
        super().__init__(parent)
        self.setWindowTitle(f"Configure Risk: {event_name}")
        self.setFixedSize(400, 200)
        self.setStyleSheet(STYLE_SHEET)
        self.event_name = event_name
        
        layout = QVBoxLayout(self)
        layout.addWidget(QLabel(f"Set Severity Level for:\n{event_name}"))
        
        self.combo = QComboBox()
        self.combo.addItems(["Low (Green)", "Medium (Yellow)", "High (Red)", "Critical (Dark Red)"])
        
        rules = ConfigManager.load_risk_rules()
        current_val = rules.get(event_name, 1)
        
        if current_val == 0: self.combo.setCurrentIndex(0)
        elif current_val == 1: self.combo.setCurrentIndex(1)
        elif current_val == 2: self.combo.setCurrentIndex(2)
        else: self.combo.setCurrentIndex(3)
        
        layout.addWidget(self.combo)
        
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.save_rule)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)

    def save_rule(self):
        idx = self.combo.currentIndex()
        val = 1
        if idx == 0: val = 0
        elif idx == 1: val = 1
        elif idx == 2: val = 2
        else: val = 3
        
        rules = ConfigManager.load_risk_rules()
        rules[self.event_name] = val
        ConfigManager.save_risk_rules(rules)
        self.accept()

class GlobalSettingsDialog(QDialog):
    logout_signal = pyqtSignal()
    def __init__(self, parent, host, port, user, password):
        super().__init__(parent)
        self.setWindowTitle("Settings & Auto-Defense Manager")
        self.setFixedSize(550, 600)
        self.setStyleSheet(STYLE_SHEET)
        
        self.tabs = QTabWidget()
        layout = QVBoxLayout(self)
        layout.addWidget(self.tabs)
        
        conn_tab = QWidget()
        c_layout = QVBoxLayout(conn_tab)
        c_layout.addWidget(QLabel("Update Current SSH Connection:"))
        self.host_edit = QLineEdit(host)
        self.port_edit = QLineEdit(str(port))
        self.user_edit = QLineEdit(user)
        self.pass_edit = QLineEdit(password)
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        form = QFormLayout()
        form.addRow("Host IP:", self.host_edit)
        form.addRow("Port:", self.port_edit)
        form.addRow("Username:", self.user_edit)
        form.addRow("Password:", self.pass_edit)
        c_layout.addLayout(form)
        c_layout.addStretch()
        self.tabs.addTab(conn_tab, "SSH Connection")
        
        gen_tab = QWidget()
        g_layout = QVBoxLayout(gen_tab)
        g_layout.addWidget(QLabel("Alert Sound File:"))
        self.audio_path_edit = QLineEdit()
        gs = ConfigManager.load_global_settings()
        self.audio_path_edit.setText(gs.get("audio_path", DEFAULT_ALARM_FILE))
        h_aud = QHBoxLayout()
        h_aud.addWidget(self.audio_path_edit)
        btn_browse = QPushButton("Browse")
        btn_browse.clicked.connect(self.browse_audio)
        h_aud.addWidget(btn_browse)
        g_layout.addLayout(h_aud)
        
        g_layout.addSpacing(10)
        g_layout.addWidget(QLabel("<h3>Alert Timing</h3>"))
        form_time = QFormLayout()
        self.alert_delay_edit = QLineEdit(str(gs.get("alert_delay", 5)))
        form_time.addRow("Delay between alerts (sec):", self.alert_delay_edit)
        self.snooze_time_edit = QLineEdit(str(gs.get("snooze_duration", 60)))
        form_time.addRow("Snooze duration (sec):", self.snooze_time_edit)
        g_layout.addLayout(form_time)
        g_layout.addStretch()
        self.tabs.addTab(gen_tab, "General / Sound")

        def_tab = QWidget()
        d_layout = QVBoxLayout(def_tab)
        d_layout.addWidget(QLabel("<h3>🛡️ Auto-Defense / Deadman Switch</h3>"))
        
        self.chk_auto_ban = QCheckBox("Enable Auto-Ban IP (Ban Attacker IP automatically)")
        self.chk_auto_ban.setChecked(gs.get("auto_ban_enabled", False))
        d_layout.addWidget(self.chk_auto_ban)
        
        h_delay = QHBoxLayout()
        h_delay.addWidget(QLabel("Wait time before Action (sec):"))
        self.auto_ban_delay_spin = QLineEdit(str(gs.get("auto_ban_delay", 10)))
        h_delay.addWidget(self.auto_ban_delay_spin)
        d_layout.addLayout(h_delay)
        
        d_layout.addSpacing(10)
        d_layout.addWidget(QLabel("<b>Advanced Escalation (If attack persists):</b>"))
        self.chk_close_port = QCheckBox("Auto-Close Targeted Port (IPTables)")
        self.chk_close_port.setChecked(gs.get("auto_close_port", False))
        d_layout.addWidget(self.chk_close_port)
        
        self.chk_stop_service = QCheckBox("Auto-Stop Service (Stop Cowrie/Dionaea)")
        self.chk_stop_service.setChecked(gs.get("auto_stop_service", False))
        d_layout.addWidget(self.chk_stop_service)
        
        d_layout.addStretch()
        self.tabs.addTab(def_tab, "🛡️ Auto-Defense")

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Save | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(self.save_all)
        btns.rejected.connect(self.reject)
        layout.addWidget(btns)
        
        logout_btn = QPushButton("🚪 Logout & Exit to Menu")
        logout_btn.setObjectName("LogoutBtn")
        logout_btn.clicked.connect(self.trigger_logout)
        layout.addWidget(logout_btn)

    def browse_audio(self):
        f, _ = QFileDialog.getOpenFileName(self, "Select Audio", "", "Audio Files (*.mp3 *.wav *.ogg)")
        if f: self.audio_path_edit.setText(f)

    def save_all(self):
        gs = ConfigManager.load_global_settings()
        gs["audio_path"] = self.audio_path_edit.text()
        try:
            gs["alert_delay"] = int(self.alert_delay_edit.text())
            gs["snooze_duration"] = int(self.snooze_time_edit.text())
            gs["auto_ban_delay"] = int(self.auto_ban_delay_spin.text())
        except ValueError:
            QMessageBox.warning(self, "Error", "Please enter valid numbers.")
            return
            
        gs["auto_ban_enabled"] = self.chk_auto_ban.isChecked()
        gs["auto_close_port"] = self.chk_close_port.isChecked()
        gs["auto_stop_service"] = self.chk_stop_service.isChecked()
        
        ConfigManager.save_global_settings(gs)
        self.accept()

    def trigger_logout(self):
        self.logout_signal.emit()
        self.reject()

    def get_ssh_data(self):
        return (self.host_edit.text(), int(self.port_edit.text()), self.user_edit.text(), self.pass_edit.text())

class EmergencyDialog(QDialog):
    def __init__(self, message, title="INTRUSION DETECTED!", parent=None, attacker_ip=None):
        super().__init__(parent)
        self.setWindowTitle("🚨 SECURITY ALERT")
        self.setFixedSize(500, 500)
        self.parent_ref = parent
        self.attacker_ip = attacker_ip
        self.auto_acted = False
        
        self.color_state = False 
        self.bg_color_1 = "#b71c1c"
        self.bg_color_2 = "#ff5252"
        self.update_style()
        
        layout = QVBoxLayout(self)
        lbl_icon = QLabel("⚠️")
        lbl_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lbl_icon.setStyleSheet("font-size: 60px; margin-bottom: 10px; background: transparent;")
        layout.addWidget(lbl_icon)
        
        self.lbl_title = QLabel(title)
        self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_title.setStyleSheet("font-size: 24px; margin-bottom: 20px; text-transform: uppercase; background: transparent; color: white; font-weight: bold;")
        layout.addWidget(self.lbl_title)
        
        self.lbl_msg = QLabel(message)
        self.lbl_msg.setWordWrap(True)
        self.lbl_msg.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_msg.setStyleSheet("font-size: 14px; background-color: rgba(0,0,0,0.3); padding: 10px; border-radius: 4px; color: white;")
        layout.addWidget(self.lbl_msg)
        
        self.lbl_ip_info = QLabel()
        self.lbl_ip_info.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.lbl_ip_info.setStyleSheet("font-size: 18px; font-weight: bold; color: yellow; margin-top: 10px; background: transparent;")
        if self.attacker_ip and self.attacker_ip != "-":
             self.lbl_ip_info.setText(f"Target IP: {self.attacker_ip}")
        else:
             self.lbl_ip_info.setText("Searching for IP in logs...")
        layout.addWidget(self.lbl_ip_info)

        self.timer_label = QLabel("Waiting...")
        self.timer_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.timer_label.setStyleSheet("font-size: 20px; font-weight: bold; color: #fff; background-color: rgba(0,0,0,0.5); padding: 5px; border-radius: 5px;")
        layout.addWidget(self.timer_label)

        layout.addStretch()
        
        self.stop_btn = QPushButton("🔕 STOP ALARM")
        self.stop_btn.setStyleSheet("QPushButton { background-color: #fff; color: #b71c1c; font-weight: bold; border-radius: 5px; padding: 10px; font-size: 16px; } QPushButton:hover { background-color: #e0e0e0; }")
        self.stop_btn.clicked.connect(self.accept)
        layout.addWidget(self.stop_btn)

        self.snooze_btn = QPushButton("💤 SNOOZE (Pause)")
        self.snooze_btn.setStyleSheet("QPushButton { background-color: #ff9800; color: #000; font-weight: bold; border-radius: 5px; padding: 10px; font-size: 14px; margin-top: 5px; }")
        self.snooze_btn.clicked.connect(self.trigger_snooze)
        layout.addWidget(self.snooze_btn)
        
        self.alarm_active = True
        self.alarm_thread = threading.Thread(target=self.play_continuous_alarm, daemon=True)
        self.alarm_thread.start()
        
        self.flash_timer = QTimer(self)
        self.flash_timer.timeout.connect(self.flash_bg)
        self.flash_timer.start(800) 
        
        settings = ConfigManager.load_global_settings()
        self.auto_ban_enabled = settings.get("auto_ban_enabled", False)
        self.countdown = settings.get("auto_ban_delay", 10)
        
        if self.auto_ban_enabled:
            self.defense_timer = QTimer(self)
            self.defense_timer.timeout.connect(self.tick_countdown)
            self.defense_timer.start(1000)
            self.update_timer_label()
        else:
             self.timer_label.setText("Auto-Ban: DISABLED")

    def tick_countdown(self):
        self.countdown -= 1
        self.update_timer_label()
        if self.countdown <= 0:
            self.defense_timer.stop()
            self.trigger_auto_defense()

    def update_timer_label(self):
        self.timer_label.setText(f"⏳ Auto-Ban in: {self.countdown}s")

    def trigger_auto_defense(self):
        if self.parent_ref and self.attacker_ip and self.attacker_ip != "-":
            self.auto_acted = True
            self.timer_label.setText("🛡️ EXECUTING BAN NOW...")
            self.parent_ref.check_and_execute_ban(self.attacker_ip, silent=True)
            
            self.flash_timer.stop()
            self.timer_label.setText("✅ THREAT BANNED! ALARM ACTIVE.")
            self.stop_btn.setText("ACKNOWLEDGE & STOP")
            self.lbl_title.setText("THREAT ELIMINATED")
            
        elif not self.attacker_ip or self.attacker_ip == "-":
            self.timer_label.setText("⚠️ Cannot Ban: No IP Found")

    def trigger_snooze(self):
        if self.parent_ref: self.parent_ref.activate_snooze()
        self.accept()

    def flash_bg(self):
        self.color_state = not self.color_state
        self.update_style()

    def update_style(self):
        bg = self.bg_color_2 if self.color_state else self.bg_color_1
        self.setStyleSheet(f"QDialog {{ background-color: {bg}; border: 2px solid #fff; }}")

    def play_continuous_alarm(self):
        settings = ConfigManager.load_global_settings()
        sound_file = settings.get("audio_path", DEFAULT_ALARM_FILE)
        try:
            if not os.path.exists(sound_file):
                for _ in range(5):
                    if not self.alarm_active: break
                    QApplication.beep()
                    time.sleep(0.2)
                return
 
            while self.alarm_active:
                try:
                    cmd = ['cvlc', sound_file, '--play-and-exit', '--no-video', '--gain', '2.0', '--no-osd']
                    subprocess.run(cmd, capture_output=True, timeout=30)
                except:
                    try:
                        cmd = ['ffplay', '-nodisp', '-autoexit', '-loglevel', 'quiet', '-volume', '100', sound_file]
                        subprocess.run(cmd, capture_output=True, timeout=30)
                    except:
                        for _ in range(3):
                            if not self.alarm_active: break
                            QApplication.beep()
                time.sleep(0.5)
                time.sleep(0.1)
        except: pass

    def stop_alarm(self):
        self.alarm_active = False
        try:
            subprocess.run(['pkill', '-f', 'vlc'], capture_output=True)
            subprocess.run(['pkill', '-f', 'ffplay'], capture_output=True)
        except: pass

    def accept(self):
        self.stop_alarm()
        if hasattr(self, 'defense_timer'): self.defense_timer.stop()
        self.flash_timer.stop()
        super().accept()
    
    def reject(self):
        self.stop_alarm()
        if hasattr(self, 'defense_timer'): self.defense_timer.stop()
        self.flash_timer.stop()
        super().reject()
    
    def closeEvent(self, event):
        self.stop_alarm()
        if hasattr(self, 'defense_timer'): self.defense_timer.stop()
        self.flash_timer.stop()
        super().closeEvent(event)

class LogDetailsPopup(QDialog):
    def __init__(self, data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Log Summary Details")
        self.setFixedSize(650, 600)
        self.setStyleSheet(STYLE_SHEET)
        self.data = data
        self.mw_ref = parent if isinstance(parent, MainWindow) else None
        
        layout = QVBoxLayout(self)
        
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        tab_summary = QWidget()
        ts_layout = QVBoxLayout(tab_summary)
        ts_layout.addWidget(QLabel("<h3>Latest Event Summary</h3>"))
        
        form = QFormLayout()
        
        def add_row(label, val):
            l_w = QLabel(str(val))
            l_w.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            l_w.setStyleSheet("color: #00bcd4; font-weight: bold;" if label == "IP:" else "color: #fff;")
            form.addRow(label, l_w)
            
        add_row("Source:", data.get('source', '-'))
        add_row("IP:", data.get('ip', '-'))
        add_row("Latest Time:", data.get('time', '-'))
        add_row("Event:", data.get('event', '-'))
        add_row("Auth:", data.get('auth', '-'))
        add_row("Class:", data.get('classification', '-'))
        ts_layout.addLayout(form)
        
        ts_layout.addWidget(QLabel("Full Details:"))
        det_text = QTextEdit()
        det_text.setReadOnly(True)
        det_text.setText(data.get('details', ''))
        det_text.setMaximumHeight(100)
        ts_layout.addWidget(det_text)

        if data.get('ip') and data.get('ip') != "-":
            btn_ban_now = QPushButton("🚫 Ban IP (Quick Action)")
            btn_ban_now.setStyleSheet("background-color: #b71c1c; font-weight: bold; margin-top: 10px;")
            btn_ban_now.clicked.connect(self.trigger_ban)
            ts_layout.addWidget(btn_ban_now)
        
        ts_layout.addStretch()
        self.tabs.addTab(tab_summary, "Summary")
        
        if '_history' in data and len(data['_history']) > 1:
           tab_hist = QWidget()
           th_layout = QVBoxLayout(tab_hist)
           th_layout.addWidget(QLabel(f"<h3>Merged Occurrences ({len(data['_history'])})</h3>"))
            
           hist_table = QTableWidget()
           hist_table.setColumnCount(3)
           hist_table.setHorizontalHeaderLabels(["Time", "Event ID", "Details Snippet"])
           hist_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
           hist_table.setRowCount(len(data['_history']))
           
           for i, h_item in enumerate(reversed(data['_history'])): 
                hist_table.setItem(i, 0, QTableWidgetItem(h_item.get('time', '-')))
                hist_table.setItem(i, 1, QTableWidgetItem(h_item.get('event', '-')))
                hist_table.setItem(i, 2, QTableWidgetItem(h_item.get('details', '')[:60] + "..."))
           
           th_layout.addWidget(hist_table)
           self.tabs.addTab(tab_hist, "Merged History Log")
        
        btn_close = QPushButton("Close")
        btn_close.clicked.connect(self.accept)
        layout.addWidget(btn_close)

    def trigger_ban(self):
        ip = self.data.get('ip')
        if self.mw_ref and ip:
            self.mw_ref.check_and_execute_ban(ip, service_idx=0) 
        self.accept()

# -------------------------------------------------------------------------
# ANALYTICS DASHBOARD 
# -------------------------------------------------------------------------
class AnalyticsDashboard(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        # Use a dynamic map to ensure colors persist
        self.color_map = {} 
        
        main_layout = QVBoxLayout(self)
        
        top_frame = QFrame()
        top_frame.setObjectName("SectionHeader")
        tf_layout = QHBoxLayout(top_frame)
        
        tf_layout.addWidget(QLabel("🔍 Analytics Time Range:"))
        
        self.chk_all_history = QCheckBox("All History")
        self.chk_all_history.toggled.connect(self.toggle_time_filter)
        tf_layout.addWidget(self.chk_all_history)
        
        self.chk_specific_date = QCheckBox("Specific Date:")
        self.chk_specific_date.toggled.connect(self.toggle_date_picker)
        tf_layout.addWidget(self.chk_specific_date)
        
        self.date_picker = QDateEdit()
        self.date_picker.setCalendarPopup(True)
        self.date_picker.setDate(QDate.currentDate())
        self.date_picker.setEnabled(False)
        tf_layout.addWidget(self.date_picker)
        
        self.spin_value = QSpinBox()
        self.spin_value.setRange(1, 9999) 
        self.spin_value.setValue(24)
        
        self.combo_unit = QComboBox()
        self.combo_unit.addItems(["Hours", "Minutes", "Seconds", "Days"])
        
        tf_layout.addWidget(QLabel("OR Last"))
        tf_layout.addWidget(self.spin_value)
        tf_layout.addWidget(self.combo_unit)

        btn_refresh = QPushButton("♻ Fetch & Refresh")
        btn_refresh.clicked.connect(self.fetch_and_refresh_stats)
        tf_layout.addWidget(btn_refresh)
        
        main_layout.addWidget(top_frame)
        
        self.stack = QStackedWidget() 
        main_layout.addWidget(self.stack)
        
        self.page_charts = QWidget()
        pc_layout = QVBoxLayout(self.page_charts)
        
        split_analysis = QHBoxLayout()
        
        event_group = QGroupBox("📝 Event & Source Analysis")
        event_group.setStyleSheet("QGroupBox::title { color: #00bcd4; }")
        e_layout = QVBoxLayout(event_group)
        
        self.filter_event = QLineEdit()
        self.filter_event.setPlaceholderText("Filter Events by Name...")
        self.filter_event.textChanged.connect(self.update_visuals)
        e_layout.addWidget(self.filter_event)

        event_chart_box = QHBoxLayout()
        self.donut_attacks = DonutChart(title="Events", color_map=self.color_map)
        event_chart_box.addWidget(self.donut_attacks)
        self.legend_attacks = QScrollArea()
        self.legend_attacks.setWidgetResizable(True)
        self.legend_attacks.setMinimumWidth(250)
        self.legend_attacks.setMaximumHeight(200)
        event_chart_box.addWidget(self.legend_attacks)
        e_layout.addLayout(event_chart_box)
        
        e_layout.addWidget(QLabel("Top Events (Click to Filter):"))
        self.event_list = QListWidget()
        self.event_list.setStyleSheet("QListWidget::item { padding: 5px; border-bottom: 1px solid #333; }")
        self.event_list.itemClicked.connect(self.drill_down_event)
        e_layout.addWidget(self.event_list)
    
        split_analysis.addWidget(event_group)

        ip_group = QGroupBox("🌍 Attacker IP Analysis")
        ip_group.setStyleSheet("QGroupBox::title { color: #ff9800; }")
        r_layout = QVBoxLayout(ip_group)
        
        self.filter_ip = QLineEdit()
        self.filter_ip.setPlaceholderText("Filter by Specific IP...")
        self.filter_ip.textChanged.connect(self.update_visuals)
        r_layout.addWidget(self.filter_ip)
        
        source_chart_box = QHBoxLayout()
        self.donut_source = DonutChart(title="Top IPs")
        source_chart_box.addWidget(self.donut_source)
        
        self.legend_source = QScrollArea()
        self.legend_source.setWidgetResizable(True)
        self.legend_source.setMinimumWidth(250)
        self.legend_source.setMaximumHeight(200)
        source_chart_box.addWidget(self.legend_source)
        r_layout.addLayout(source_chart_box)
        
        r_layout.addWidget(QLabel("Top Attacker IPs (Click to Filter):"))
        self.ip_list = QListWidget()
        self.ip_list.setStyleSheet("QListWidget::item { padding: 5px; border-bottom: 1px solid #333; }")
        self.ip_list.itemClicked.connect(self.drill_down_ip)
        r_layout.addWidget(self.ip_list)
        
        split_analysis.addWidget(ip_group)
        
        pc_layout.addLayout(split_analysis)
        self.stack.addWidget(self.page_charts)
        
        self.page_details = QWidget()
        pd_layout = QVBoxLayout(self.page_details)
        
        pd_header = QHBoxLayout()
        btn_back = QPushButton("🔙 Back to Dashboard")
        btn_back.clicked.connect(lambda: self.stack.setCurrentIndex(0))
        btn_back.setStyleSheet("background-color: #555; font-size: 14px;")
        pd_header.addWidget(btn_back)
        
        self.local_search = QLineEdit()
        self.local_search.setPlaceholderText("🔍 Search in Results (Hides non-matching)...")
        self.local_search.textChanged.connect(self.apply_local_filter)
        self.local_search.setStyleSheet("border: 1px solid #00bcd4; padding: 5px; border-radius: 4px; width: 300px;")
        pd_header.addWidget(self.local_search)
        
        self.lbl_detail_title = QLabel("Details")
        self.lbl_detail_title.setStyleSheet("font-size: 20px; font-weight: bold; color: #00bcd4;")
        pd_header.addWidget(self.lbl_detail_title)
        pd_header.addStretch()
        pd_layout.addLayout(pd_header)
        
        self.details_table = QTableWidget()
        self.details_table.setColumnCount(7)
        self.details_table.setHorizontalHeaderLabels(["Time", "Source", "IP", "Event", "Auth/Cmd", "Full Details", "View"])
        self.details_table.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.details_table.setItemDelegateForColumn(2, HTMLDelegate(self.details_table)) # IP
        self.details_table.setItemDelegateForColumn(3, HTMLDelegate(self.details_table)) # Event
        self.details_table.setItemDelegateForColumn(5, HTMLDelegate(self.details_table)) # Details
        
        self.details_table.setColumnWidth(6, 50)
        pd_layout.addWidget(self.details_table)
        
        self.stack.addWidget(self.page_details)
        
        self.raw_logs_data = [] 

    def toggle_time_filter(self, checked):
        self.spin_value.setEnabled(not checked)
        self.combo_unit.setEnabled(not checked)
        self.chk_specific_date.setEnabled(not checked)
        self.date_picker.setEnabled(not checked and self.chk_specific_date.isChecked())

    def toggle_date_picker(self, checked):
        self.date_picker.setEnabled(checked)
        self.spin_value.setEnabled(not checked)
        self.combo_unit.setEnabled(not checked)

    # 2. FIX ALL HISTORY BUG
    def fetch_and_refresh_stats(self):
        self.mw.status_bar.showMessage("Fetching full log history for analysis. This may take a moment...")
        cowrie_path = COWRIE_LOG_PATH
        dionaea_path = DIONAEA_LOG_PATH
        cmd = ""
        
        if self.chk_all_history.isChecked():
            # Use 'cat' but pipe to tail with a massive number to avoid GUI freeze if files are GBs.
            # 200,000 lines is safe for "All History" in a GUI context.
            cmd = f"cat {cowrie_path} {dionaea_path} | tail -n 200000" 
        elif self.chk_specific_date.isChecked():
            q_date = self.date_picker.date().toString("yyyy-MM-dd")
            cmd = f"grep '{q_date}' {cowrie_path} {dionaea_path} | tail -n 20000"
        else:
            unit = self.combo_unit.currentText()
            line_count = 5000
            if unit == "Seconds": line_count = 5000 
            elif unit == "Minutes": line_count = 10000
            elif unit == "Hours": line_count = 20000
            elif unit == "Days": line_count = 50000
            cmd = f"tail -n {line_count} -q {cowrie_path} {dionaea_path}"

        worker = SSHWorker(self.mw.host, self.mw.port, self.mw.user, self.mw.password, command=cmd, task_type="fetch_full_analysis")
        worker.data_signal.connect(self.process_fetched_logs)
        self.mw.start_worker(worker)

    def process_fetched_logs(self, raw_data):
        self.mw.status_bar.showMessage("Processing log data...")
        self.raw_logs_data = []
        
        time_limit = None
        if not self.chk_all_history.isChecked() and not self.chk_specific_date.isChecked():
            val = self.spin_value.value()
            unit = self.combo_unit.currentText()
            delta = timedelta(hours=24)
            if unit == "Minutes": delta = timedelta(minutes=val)
            elif unit == "Seconds": delta = timedelta(seconds=val)
            elif unit == "Days": delta = timedelta(days=val)
            else: delta = timedelta(hours=val)
            time_limit = datetime.now() - delta

        for line in raw_data.splitlines():
            parsed_data = self.mw.parse_log_line(line)
            
            if parsed_data:
                # Apply time filtering ONLY if time_limit is set (All History ignores this)
                if time_limit:
                    try:
                        log_dt_str = f"{datetime.now().strftime('%Y-%m-%d')} {parsed_data['time']}"
                        if len(parsed_data['time']) > 10: 
                             log_dt = datetime.strptime(parsed_data['time'], "%Y-%m-%d %H:%M:%S")
                        else:
                             log_dt = datetime.strptime(log_dt_str, "%Y-%m-%d %H:%M:%S")
                             if log_dt > datetime.now() + timedelta(hours=1): log_dt -= timedelta(days=1)
                        
                        if log_dt < time_limit: continue
                    except: pass
                
                self.raw_logs_data.append(parsed_data)
                
        self.update_visuals()
        self.mw.status_bar.showMessage(f"Analysis complete. Loaded {len(self.raw_logs_data)} logs.")

    def update_visuals(self):
        logs = self.raw_logs_data
        search_ip = self.filter_ip.text().lower()
        search_event = self.filter_event.text().lower()
        
        attack_counts = {}
        ip_counts = {}
        
        # 3. USE CENTRALIZED COLORS
        for log in logs:
            if search_ip and search_ip not in log['ip'].lower(): continue
            evt_class = log.get('classification', log.get('event', 'Unknown'))
            if search_event and search_event not in evt_class.lower(): continue
            
            if evt_class not in attack_counts: attack_counts[evt_class] = 0
            attack_counts[evt_class] += 1
            
            ip = log['ip']
            if ip != "-":
                if ip not in ip_counts: ip_counts[ip] = 0
                ip_counts[ip] += 1
        
        # Assign colors using main window's centralized method
        current_map = {}
        for ip in ip_counts.keys():
            current_map[ip] = self.mw.get_color_for_key(ip)
        for evt in attack_counts.keys():
            current_map[evt] = self.mw.get_color_for_key(evt)

        sorted_ips_for_chart = dict(sorted(ip_counts.items(), key=lambda item: item[1], reverse=True)[:15])
        self.donut_source.set_data(sorted_ips_for_chart, dynamic_colors=current_map)
        self.donut_attacks.set_data(attack_counts, dynamic_colors=current_map)
        self.legend_source.setWidget(self.donut_source.get_legend_widget())
        self.legend_attacks.setWidget(self.donut_attacks.get_legend_widget())

        self.ip_list.clear()
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        for ip, count in sorted_ips:
            item = QListWidgetItem(f"🔴 {ip}  —  {count} Events")
            item.setData(Qt.ItemDataRole.UserRole, ip) 
            item.setForeground(QBrush(current_map.get(ip, QColor("white"))))
            self.ip_list.addItem(item)

        self.event_list.clear()
        sorted_events = sorted(attack_counts.items(), key=lambda x: x[1], reverse=True)
        for event, count in sorted_events:
            item = QListWidgetItem(f"📝 {event}  —  {count} Occurrences")
            item.setData(Qt.ItemDataRole.UserRole, event) 
            color = current_map.get(event, QColor("#e0e0e0"))
            item.setForeground(QBrush(color))
            self.event_list.addItem(item)

    def drill_down_ip(self, item):
        ip = item.data(Qt.ItemDataRole.UserRole)
        self.show_details_view(filter_key="ip", filter_val=ip)

    def drill_down_event(self, item):
        event = item.data(Qt.ItemDataRole.UserRole)
        self.show_details_view(filter_key="classification", filter_val=event)

    def show_details_view(self, filter_key, filter_val):
        self.lbl_detail_title.setText(f"Details for: {filter_val}")
        self.local_search.clear()
        self.stack.setCurrentIndex(1)
        
        logs = self.raw_logs_data
        filtered = []
        for l in logs:
            if filter_key == "ip" and l['ip'] == filter_val: 
                filtered.append(l)
            elif filter_key == "classification" and l.get('classification', l.get('event')) == filter_val:
               filtered.append(l)
            
        self.current_detailed_logs = filtered
        self.populate_details_table(filtered)

    def populate_details_table(self, data_list):
        self.details_table.setSortingEnabled(False)
        self.details_table.setRowCount(0)
        self.details_table.setRowCount(len(data_list))
        search_term = self.local_search.text().lower()

        for i, data in enumerate(data_list):
            if search_term:
                full_text = f"{data['ip']} {data['event']} {data['details']} {data['source']}".lower()
                if search_term not in full_text:
                   self.details_table.setRowHidden(i, True)
                else:
                    self.details_table.setRowHidden(i, False)

            self.details_table.setItem(i, 0, QTableWidgetItem(data['time']))
            self.details_table.setItem(i, 1, QTableWidgetItem(data['source']))
            self.details_table.setItem(i, 2, QTableWidgetItem(self.mw.highlight_text(data['ip'], search_term)))
            self.details_table.setItem(i, 3, QTableWidgetItem(self.mw.highlight_text(data['event'], search_term)))
            self.details_table.setItem(i, 4, QTableWidgetItem(data['auth']))
            highlighted_details = self.mw.highlight_text(data['details'], search_term)
            self.details_table.setItem(i, 5, QTableWidgetItem(highlighted_details))
            
            btn_view = QPushButton("🔍")
            btn_view.setStyleSheet("background-color: #333; color: white;")
            btn_view.clicked.connect(lambda _, d=data: self.open_log_popup(d))
            self.details_table.setCellWidget(i, 6, btn_view)
            
        self.details_table.setSortingEnabled(True)

    def apply_local_filter(self, text):
        self.populate_details_table(self.current_detailed_logs)

    def open_log_popup(self, data):
        dlg = LogDetailsPopup(data, self.mw)
        dlg.exec()

# -------------------------------------------------------------------------
# 🛡️ DEEP ANALYSIS DASHBOARD (SOC MODE) - UPDATED
# -------------------------------------------------------------------------
class DeepAnalysisDashboard(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        self.layout = QGridLayout(self)
        self.current_ip_filter = None
        
        # 1. Top Left: Logs Activity (Donut)
        self.chart_activity = DonutChart(title="Activity Share")
        self.layout.addWidget(self.create_panel("🟠 Attack Activity Distribution", self.chart_activity), 0, 0)
        
        # 5. Updated Right Panel: IP Intelligence + Dionaea + Monitor
        splitter_right = QSplitter(Qt.Orientation.Vertical)
        
        # Top Right: IP List
        self.ip_panel = QListWidget()
        self.ip_panel.setStyleSheet("QListWidget { background: #252526; border: none; } QListWidget::item { padding: 8px; border-bottom: 1px solid #333; }")
        self.ip_panel.itemClicked.connect(self.on_ip_clicked)
        splitter_right.addWidget(self.create_panel("🟦 IP Intelligence", self.ip_panel))

        # Middle Right: Dionaea Specific Attacks
        self.dionaea_list = QListWidget()
        self.dionaea_list.setStyleSheet("QListWidget { background: #252526; border: none; }")
        splitter_right.addWidget(self.create_panel("🐌 Dionaea / Malware Events", self.dionaea_list))

        # Bottom Right: Dedicated Monitor (Fixed & Expanded)
        monitor_widget = QWidget()
        m_lay = QVBoxLayout(monitor_widget)
        
        m_controls = QHBoxLayout()
        self.monitor_combo = QComboBox()
        # 4. Added more Monitor Options
        self.monitor_combo.addItems([
            "Monitor Focus (Selected IP)", 
            "All Dionaea Events", 
            "All Cowrie Events", 
            "Auth Attempts (Logins)", 
            "Malware Downloads Only",
            "Command Execution"
        ])
        m_controls.addWidget(self.monitor_combo)
        
        btn_clear_mon = QPushButton("Clear")
        btn_clear_mon.setFixedSize(60, 25)
        btn_clear_mon.setStyleSheet("background: #444; color: white;")
        btn_clear_mon.clicked.connect(lambda: self.independent_monitor_text.clear())
        m_controls.addWidget(btn_clear_mon)
        
        m_lay.addLayout(m_controls)
        
        self.independent_monitor_text = QTextEdit()
        self.independent_monitor_text.setReadOnly(True)
        self.independent_monitor_text.setStyleSheet("font-family: Consolas; font-size: 11px; color: #00ff00; background-color: #000;")
        m_lay.addWidget(self.independent_monitor_text)
        
        self.chk_autoscroll = QCheckBox("Auto-scroll")
        self.chk_autoscroll.setChecked(True)
        m_lay.addWidget(self.chk_autoscroll)
        
        splitter_right.addWidget(self.create_panel("🖥️ Dedicated Live Monitor", monitor_widget))
        
        self.layout.addWidget(splitter_right, 0, 2, 2, 1) # Occupy right column

        # 3. Bottom Left: Risk & Threat Level (Clickable)
        self.risk_table = QTableWidget()
        self.risk_table.setColumnCount(3)
        self.risk_table.setHorizontalHeaderLabels(["Threat Type", "Count (Click for logs)", "Risk Level (Click to Edit)"])
        self.risk_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.risk_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.risk_table.cellClicked.connect(self.on_risk_table_clicked)
        
        self.layout.addWidget(self.create_panel("🟡 Threat Classification & Risk", self.risk_table), 1, 0)

        # 4. Center: Timeline Analysis
        splitter_center = QSplitter(Qt.Orientation.Vertical)
        
        self.timeline_list = QListWidget()
        self.timeline_list.setStyleSheet("font-family: Consolas; font-size: 12px;")
        self.timeline_list.itemDoubleClicked.connect(self.show_timeline_log_details)
        splitter_center.addWidget(self.timeline_list)
        
        self.timeline_summary = QTextEdit()
        self.timeline_summary.setReadOnly(True)
        self.timeline_summary.setPlaceholderText("Select an IP or wait for data to see summary...")
        self.timeline_summary.setStyleSheet("font-family: Consolas; font-size: 13px; color: #00e676; background-color: #1e1e1e;")
        splitter_center.addWidget(self.timeline_summary)
        
        self.layout.addWidget(self.create_panel("🟢 Attack Timeline (Double Click for Full Log)", splitter_center), 0, 1, 2, 1)

        # 5. Bottom: Controls
        control_frame = QFrame()
        cf_layout = QHBoxLayout(control_frame)
        
        btn_ban = QPushButton("🚫 BAN IP")
        btn_ban.setStyleSheet("background-color: #b71c1c; padding: 10px; font-weight: bold;")
        btn_ban.clicked.connect(self.action_ban_ip)
        
        btn_term = QPushButton("💻 TERMINAL")
        btn_term.setStyleSheet("background-color: #0e639c; padding: 10px;")
        btn_term.clicked.connect(lambda: self.mw.tabs.setCurrentIndex(5))
        
        btn_start = QPushButton("▶ START ALL")
        btn_start.setStyleSheet("background-color: #2e7d32; padding: 10px;")
        btn_start.clicked.connect(lambda: self.mw.batch_action("start"))
        
        btn_stop = QPushButton("🛑 EMERGENCY STOP")
        btn_stop.setStyleSheet("background-color: #ff9800; color: black; padding: 10px;")
        btn_stop.clicked.connect(lambda: self.mw.batch_action("stop"))

        cf_layout.addWidget(QLabel("🛠️ SOC Actions:"))
        cf_layout.addWidget(btn_ban)
        cf_layout.addWidget(btn_term)
        cf_layout.addWidget(btn_start)
        cf_layout.addWidget(btn_stop)
        
        self.live_monitor_label = QLabel("🔴 Live Events: Waiting...")
        self.live_monitor_label.setStyleSheet("color: #ff5252; font-weight: bold; margin-left: 20px;")
        
        cf_layout.addStretch()
        cf_layout.addWidget(self.live_monitor_label)
        
        self.layout.addWidget(self.create_panel("🔴 Live Monitoring & Controls", control_frame), 2, 0, 1, 3)

        self.all_logs = []
        
    def create_panel(self, title, widget):
        box = QGroupBox(title)
        box.setStyleSheet("QGroupBox { border: 1px solid #444; border-radius: 6px; margin-top: 20px; font-weight: bold; color: #ddd; } QGroupBox::title { subcontrol-origin: margin; subcontrol-position: top center; padding: 0 5px; }")
        l = QVBoxLayout(box)
        l.addWidget(widget)
        return box

    def refresh_data(self, logs):
        self.all_logs = logs
        self.process_ip_intelligence()
        self.update_charts()
        self.update_timeline()
        self.update_dionaea_panel()

    def process_ip_intelligence(self):
        self.ip_panel.clear()
        ip_stats = {}
        risk_rules = ConfigManager.load_risk_rules()
     
        for log in self.all_logs:
            ip = log['ip']
            if ip == "-": continue
            
            if ip not in ip_stats:
                ip_stats[ip] = {'count': 0, 'risk': 0, 'events': set()}
         
            ip_stats[ip]['count'] += 1
            
            evt_name = log.get('classification', log.get('event', 'Unknown'))
            base_risk = risk_rules.get(evt_name, log.get('risk', 1))
            ip_stats[ip]['risk'] += base_risk

        sorted_ips = sorted(ip_stats.items(), key=lambda x: x[1]['risk'], reverse=True)

        for ip, data in sorted_ips:
            risk_score = data['risk']
            # 3. COLOR DISTINCTION IN IP LIST
            item_color = self.mw.get_color_for_key(ip)
            
            item = QListWidgetItem(f"█ {ip} | Events: {data['count']} | Risk: {risk_score}")
            item.setForeground(QBrush(item_color))
            item.setData(Qt.ItemDataRole.UserRole, ip)
            self.ip_panel.addItem(item)
            
            if self.current_ip_filter == ip:
                item.setSelected(True)

    def update_dionaea_panel(self):
        # 1. FIX: FILTER DIONAEA LIST BY SELECTED IP
        self.dionaea_list.clear()
        
        # Base filter: Dionaea logs
        d_logs = [l for l in self.all_logs if l['source'] == 'Dionaea']
        
        # Second filter: Specific IP if selected
        if self.current_ip_filter:
            d_logs = [l for l in d_logs if l['ip'] == self.current_ip_filter]
        
        for log in reversed(d_logs[-50:]):
            # Use color map here too
            color = self.mw.get_color_for_key(log['classification'])
            item = QListWidgetItem(f"{log['time']} - {log['ip']} - {log['classification']}")
            item.setForeground(QBrush(color))
            self.dionaea_list.addItem(item)

    def on_ip_clicked(self, item):
        selected_ip = item.data(Qt.ItemDataRole.UserRole)
        
        if self.current_ip_filter == selected_ip:
            self.current_ip_filter = None
            self.ip_panel.clearSelection()
            self.live_monitor_label.setText(f"🔴 Live Events: Monitoring All")
        else:
            self.current_ip_filter = selected_ip
            self.live_monitor_label.setText(f"🔴 Focused on: {self.current_ip_filter}")
            
        self.update_charts()
        self.update_timeline()
        self.update_dionaea_panel() # Refresh Dionaea panel too

    def on_risk_table_clicked(self, row, col):
        threat_item = self.risk_table.item(row, 0)
        if not threat_item: return
        threat_name = threat_item.text()

        if col == 1: 
            filtered_logs = [l for l in self.all_logs if l.get('classification') == threat_name or l.get('event') == threat_name]
            self.show_filtered_logs_popup(threat_name, filtered_logs)
            
        elif col == 2: 
            dlg = RiskConfigDialog(self, threat_name)
            if dlg.exec():
                self.process_ip_intelligence() 
                self.update_charts()

    def show_filtered_logs_popup(self, title, logs):
        dlg = QDialog(self)
        dlg.setWindowTitle(f"Logs for: {title}")
        dlg.setFixedSize(600, 400)
        dlg.setStyleSheet(STYLE_SHEET)
        l = QVBoxLayout(dlg)
        
        table = QTableWidget()
        table.setColumnCount(3)
        table.setHorizontalHeaderLabels(["Time", "IP", "Details"])
        table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        table.setRowCount(len(logs))
        
        for i, log in enumerate(reversed(logs)):
            table.setItem(i, 0, QTableWidgetItem(log['time']))
            table.setItem(i, 1, QTableWidgetItem(log['ip']))
            table.setItem(i, 2, QTableWidgetItem(log['details'][:80]))
            
        l.addWidget(table)
        dlg.exec()

    def update_charts(self):
        active_logs = [l for l in self.all_logs if l['ip'] == self.current_ip_filter] if self.current_ip_filter else self.all_logs
        
        stats = {}
        risk_rules = ConfigManager.load_risk_rules()
        
        for log in active_logs:
            cls = log['classification']
            stats[cls] = stats.get(cls, 0) + 1

        # Use centralized colors for chart
        chart_colors = {}
        for key in stats:
            chart_colors[key] = self.mw.get_color_for_key(key)

        self.chart_activity.set_data(stats, dynamic_colors=chart_colors)
        
        self.risk_table.setRowCount(0)
        for i, (threat, count) in enumerate(stats.items()):
            self.risk_table.insertRow(i)
            self.risk_table.setItem(i, 0, QTableWidgetItem(threat))
            
            count_item = QTableWidgetItem(str(count))
            count_item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            count_item.setForeground(QColor("#00bcd4"))
            self.risk_table.setItem(i, 1, count_item)
            
            risk_val = risk_rules.get(threat, 1) 
            
            risk_str = "LOW"
            color = QColor("#00e676") 
            
            if risk_val == 2:
                risk_str = "MEDIUM"
                color = QColor("#ffea00")
            elif risk_val == 3:
                risk_str = "HIGH"
                color = QColor("#ff5252")
            elif risk_val >= 4: 
                risk_str = "CRITICAL"
                color = QColor("#b71c1c")
            
            item = QTableWidgetItem(risk_str)
            item.setForeground(color)
            item.setFont(QFont("Segoe UI", 10, QFont.Weight.Bold))
            self.risk_table.setItem(i, 2, item)

    def update_timeline(self):
        self.timeline_list.clear()
        self.timeline_summary.clear()
        
        active_logs = [l for l in self.all_logs if l['ip'] == self.current_ip_filter] if self.current_ip_filter else self.all_logs
        active_logs.sort(key=lambda x: x['time'], reverse=True) 
        
        for log in active_logs[:100]:
            time_str = log['time'].split(' ')[1] if ' ' in log['time'] else log['time']
            msg = f"[{time_str}] {log['source']} > {log['classification']} ({log['details'][:40]}...)"
            item = QListWidgetItem(msg)
            item.setData(Qt.ItemDataRole.UserRole, log)
            
            # Use centralized colors for source/text to match
            src_color = self.mw.get_color_for_key(log['source'])
            item.setForeground(QBrush(src_color))
            self.timeline_list.addItem(item)
             
        summary_txt = f"=== ATTACK SUMMARY ===\n"
        if self.current_ip_filter:
            summary_txt += f"Target IP: {self.current_ip_filter}\n"
        summary_txt += f"Total Events Analyzed: {len(active_logs)}\n"
        
        cmds = set()
        users = set()
        passwords = set()
        
        for l in active_logs:
            det = l.get('details', '')
            auth = l.get('auth', '')
            if "CMD:" in det: cmds.add(det.replace("CMD:", "").strip())
            if "U:" in auth:
                try:
                    parts = auth.split("|")
                    u = parts[0].replace("U:", "").strip()
                    p = parts[1].replace("P:", "").strip()
                    if u: users.add(u)
                    if p: passwords.add(p)
                except: pass
                
        summary_txt += f"\n[Credential Theft Attempted]\n"
        summary_txt += f"Usernames ({len(users)}): {', '.join(list(users)[:10])}\n"
        summary_txt += f"Passwords ({len(passwords)}): {', '.join(list(passwords)[:10])}\n"
        
        summary_txt += f"\n[Commands Executed]\n"
        for c in list(cmds)[:20]:
            summary_txt += f"  $ {c}\n"
            
        self.timeline_summary.setText(summary_txt)

    def show_timeline_log_details(self, item):
        data = item.data(Qt.ItemDataRole.UserRole)
        if data:
            dlg = LogDetailsPopup(data, self.mw)
            dlg.exec()

    def action_ban_ip(self):
        if self.current_ip_filter:
            self.mw.go_to_firewall_and_ban(self.current_ip_filter)
        else:
            QMessageBox.warning(self, "No IP Selected", "Select an IP from the list first.")

    def ingest_live_log(self, log_data):
        self.live_monitor_label.setText(f"🔴 LIVE: {log_data['ip']} -> {log_data['classification']}")
        self.all_logs.append(log_data)
        if len(self.all_logs) > 5000: self.all_logs.pop(0)
        
        # 4. MONITOR SCREEN LOGIC FIX
        mode = self.monitor_combo.currentIndex()
        should_show = False
        
        # 0: Monitor Focus (Selected IP)
        if mode == 0 and self.current_ip_filter and log_data['ip'] == self.current_ip_filter:
            should_show = True
        # 1: All Dionaea
        elif mode == 1 and log_data['source'] == "Dionaea":
            should_show = True
        # 2: All Cowrie
        elif mode == 2 and log_data['source'] == "Cowrie":
            should_show = True
        # 3: Auth Attempts
        elif mode == 3 and ("Login" in log_data['classification'] or "Auth" in log_data['classification']):
            should_show = True
        # 4: Malware Downloads
        elif mode == 4 and "Download" in log_data['classification']:
            should_show = True
        # 5: Command Execution
        elif mode == 5 and "Command" in log_data['classification']:
            should_show = True
            
        if should_show:
            c = self.mw.get_color_for_key(log_data['classification']).name()
            self.independent_monitor_text.append(f"<span style='color:{c}'>[{log_data['time']}] {log_data['ip']} : {log_data['classification']}</span>")
            
            if self.chk_autoscroll.isChecked():
                sb = self.independent_monitor_text.verticalScrollBar()
                sb.setValue(sb.maximum())

        if len(self.all_logs) % 5 == 0:
            self.process_ip_intelligence()
            if self.current_ip_filter == log_data['ip'] or self.current_ip_filter is None:
                self.update_timeline()
            self.update_dionaea_panel() 

# -------------------------------------------------------------------------
# FULL LOG VIEWER
# -------------------------------------------------------------------------
class FullLogViewer(QWidget):
    def __init__(self, main_window):
        super().__init__()
        self.mw = main_window
        layout = QVBoxLayout(self)
        
        ctrl_frame = QFrame()
        ctrl_frame.setObjectName("SectionHeader")
        cl = QGridLayout(ctrl_frame)
        
        self.log_type = QComboBox()
        self.log_type.addItems(["All Mixed Logs", "Cowrie Logs Only", "Dionaea Logs Only"])
        cl.addWidget(QLabel("Source:"), 0, 0)
        cl.addWidget(self.log_type, 0, 1)
        
        self.filter_mode = QComboBox()
        self.filter_mode.addItems(["Last 1000 Lines", "Last 5000 Lines", "Custom Grep (Text/IP)"])
        self.filter_mode.currentIndexChanged.connect(self.toggle_inputs)
        cl.addWidget(QLabel("Fetch Mode:"), 0, 2)
        cl.addWidget(self.filter_mode, 0, 3)
        
        self.custom_input = QLineEdit()
        self.custom_input.setPlaceholderText("Grep text (e.g. IP or Command)...")
        self.custom_input.setEnabled(False)
        cl.addWidget(self.custom_input, 0, 4)
        
        btn_adv = QPushButton("🔍 Advanced Filter")
        btn_adv.clicked.connect(self.show_advanced_filter)
        cl.addWidget(btn_adv, 0, 5)

        self.chk_auto = QCheckBox("Auto-Live (New logs)")
        self.chk_auto.toggled.connect(self.toggle_auto_refresh)
        cl.addWidget(self.chk_auto, 1, 0, 1, 2)
        
        self.loading_lbl = QLabel("⚫ Idle")
        cl.addWidget(self.loading_lbl, 1, 2)
        
        btn_fetch = QPushButton("📥 Fetch/Refresh")
        btn_fetch.setStyleSheet("background-color: #007acc; font-weight: bold;")
        btn_fetch.clicked.connect(self.fetch_logs)
        cl.addWidget(btn_fetch, 1, 5)

        layout.addWidget(ctrl_frame)
        
        filter_layout = QHBoxLayout()
        filter_layout.addWidget(QLabel("Filter Table Results:"))
        self.table_filter = QLineEdit()
        self.table_filter.setPlaceholderText("Type to filter displayed rows...")
        self.table_filter.textChanged.connect(self.apply_table_filter)
        filter_layout.addWidget(self.table_filter)
        layout.addLayout(filter_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Select", "Time", "Source", "Content / Raw", "View"])
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.setColumnWidth(0, 40)
        self.table.setColumnWidth(1, 140)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(4, 50)
        self.table.setItemDelegateForColumn(3, HTMLDelegate(self.table)) 
        layout.addWidget(self.table)
        
        self.auto_timer = QTimer(self)
        self.auto_timer.timeout.connect(self.fetch_logs)

    def toggle_inputs(self):
        self.custom_input.setEnabled(self.filter_mode.currentIndex() == 2)

    def toggle_auto_refresh(self, checked):
        if checked:
            self.auto_timer.start(5000) 
            self.loading_lbl.setText("🟢 Live")
        else:
            self.auto_timer.stop()
            self.loading_lbl.setText("⚫ Idle")

    def show_advanced_filter(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Advanced Log Filter")
        l = QFormLayout(dlg)
        
        ip_edit = QLineEdit()
        ip_edit.setPlaceholderText("e.g. 192.168.1.50")
        l.addRow("Specific IP:", ip_edit)
        
        txt_edit = QLineEdit()
        txt_edit.setPlaceholderText("Command or Event name...")
        l.addRow("Contains Text:", txt_edit)
        
        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        btns.accepted.connect(dlg.accept)
        l.addRow(btns)
        
        if dlg.exec():
            term = ""
            if ip_edit.text(): term += f"{ip_edit.text()} "
            if txt_edit.text(): term += f"{txt_edit.text()}"
            
            self.filter_mode.setCurrentIndex(2) 
            self.custom_input.setText(term.strip())
            self.fetch_logs()

    def fetch_logs(self):
        self.loading_lbl.setText("🟡 Fetching...")
        source_idx = self.log_type.currentIndex()
        mode_idx = self.filter_mode.currentIndex()
        
        cowrie_path = COWRIE_LOG_PATH
        dionaea_path = DIONAEA_LOG_PATH
        
        files = []
        if source_idx == 0: files = [cowrie_path, dionaea_path] 
        elif source_idx == 1: files = [cowrie_path]
        else: files = [dionaea_path]
        
        cmd_files = " ".join(files)
        
        if mode_idx == 0: 
            cmd = f"tail -n 1000 -q {cmd_files}"
        elif mode_idx == 1: 
            cmd = f"tail -n 5000 -q {cmd_files}"
        else: 
            grep_val = self.custom_input.text()
            if not grep_val: grep_val = "."
            cmd = f"grep -i '.*{grep_val}.*' {cmd_files} | tail -n 2000"
            
        worker = SSHWorker(self.mw.host, self.mw.port, self.mw.user, self.mw.password, command=cmd, task_type="fetch_logs")
        worker.data_signal.connect(self.populate_table)
        self.mw.start_worker(worker)

    def populate_table(self, data):
        self.loading_lbl.setText("🟢 Ready" if self.chk_auto.isChecked() else "⚫ Idle")
        lines = data.splitlines()
        
        parsed_rows = []
        for line in lines:
            t_str, src = "-", "System"
            if line.strip().startswith("{"):
                src = "Cowrie"
                try: 
                    j = json.loads(line)
                    t_str = j.get('timestamp', '').replace('T', ' ').split('.')[0]
                except: pass
            elif line.startswith("["):
                src = "Dionaea"
                m = re.search(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}', line)
                if m: t_str = m.group(0)
            
            parsed_rows.append({"time": t_str, "source": src, "raw": line})
            
        if self.log_type.currentIndex() == 0:
            parsed_rows.sort(key=lambda x: x['time'], reverse=True) 
        else:
            parsed_rows.reverse() 

        self.table.setSortingEnabled(False) 
        self.table.setRowCount(0)
        self.table.setRowCount(len(parsed_rows))
        
        self.cached_rows = parsed_rows # For filtering
        self.apply_table_filter(self.table_filter.text())

    def apply_table_filter(self, text):
        search_term = text.lower()
        if not hasattr(self, 'cached_rows'): return
        
        self.table.setSortingEnabled(False)
        self.table.setUpdatesEnabled(False)
        
        for i, row_data in enumerate(self.cached_rows):
            is_match = True
            if search_term and search_term not in row_data['raw'].lower():
                is_match = False
            
            if not is_match:
                self.table.setRowHidden(i, True)
            else:
                self.table.setRowHidden(i, False)
                chk = QTableWidgetItem()
                chk.setFlags(Qt.ItemFlag.ItemIsUserCheckable | Qt.ItemFlag.ItemIsEnabled)
                chk.setCheckState(Qt.CheckState.Unchecked)
                self.table.setItem(i, 0, chk)
                
                self.table.setItem(i, 1, QTableWidgetItem(row_data['time']))
                
                src_item = QTableWidgetItem(row_data['source'])
                if row_data['source'] == "Cowrie": src_item.setForeground(QColor("#00bcd4"))
                elif row_data['source'] == "Dionaea": src_item.setForeground(QColor("#ff9800"))
                self.table.setItem(i, 2, src_item)
                
                highlighted_content = self.mw.highlight_text(row_data['raw'], search_term)
                self.table.setItem(i, 3, QTableWidgetItem(highlighted_content))
                
                btn_view = QPushButton("🔍")
                btn_view.setFixedSize(30, 20)
                btn_view.setStyleSheet("background-color: #444;")
                btn_view.clicked.connect(lambda _, l=row_data['raw']: self.show_details(l))
                self.table.setCellWidget(i, 4, btn_view)
        
        self.table.setUpdatesEnabled(True)
        self.table.setSortingEnabled(True)

    def show_details(self, line):
        data = self.mw.parse_log_line(line)
        dlg = LogDetailsPopup(data, self.mw)
        dlg.exec()


# -------------------------------------------------------------------------
# GUI CLASSES
# -------------------------------------------------------------------------
class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Honeypot Manager - Login")
        self.setFixedSize(400, 550)
        self.setStyleSheet(STYLE_SHEET)
        
        self.layout = QVBoxLayout()
        self.layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setLayout(self.layout)
        self.show_ssh_login()

    def show_ssh_login(self):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget(): item.widget().deleteLater()

        brand_title = QLabel("HONEYPOT MANAGER")
        brand_title.setObjectName("BrandTitle")
        brand_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        brand_sub = QLabel("MADE BY CTRL X")
        brand_sub.setObjectName("BrandSubtitle")
        brand_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        self.layout.addWidget(brand_title)
        self.layout.addWidget(brand_sub)
    
        self.layout.addWidget(QLabel("Select Saved VM:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("➕ Add New VM...")
        self.profile_combo.currentIndexChanged.connect(self.load_profile_data)
        self.layout.addWidget(self.profile_combo)
        
        self.host_input = QLineEdit()
        self.host_input.setPlaceholderText("IP Address")
        self.port_input = QLineEdit("22")
        self.port_input.setPlaceholderText("SSH Port")
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("Username")
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Password")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.layout.addSpacing(10)
        self.layout.addWidget(QLabel("Host IP:"))
        self.layout.addWidget(self.host_input)
        self.layout.addWidget(QLabel("SSH Port:"))
        self.layout.addWidget(self.port_input)
        self.layout.addWidget(QLabel("Username:"))
        self.layout.addWidget(self.user_input)
        self.layout.addWidget(QLabel("Password:"))
        self.layout.addWidget(self.pass_input)
        
        self.connect_btn = QPushButton("Connect & Save")
        self.connect_btn.setFixedHeight(40)
        self.connect_btn.clicked.connect(self.start_connection)
        self.layout.addSpacing(20)
        self.layout.addWidget(self.connect_btn)
        
        self.progress = QProgressBar()
        self.progress.setRange(0, 0)
        self.progress.hide()
        self.layout.addWidget(self.progress)
        
        self.sessions = {}
        self.refresh_profiles()

    def refresh_profiles(self):
        self.sessions = ConfigManager.load_sessions()
        self.profile_combo.blockSignals(True)
        self.profile_combo.clear()
        self.profile_combo.addItem("➕ Add New VM...")
        for key in self.sessions:
            self.profile_combo.addItem(key)
        self.profile_combo.blockSignals(False)

    def load_profile_data(self):
        idx = self.profile_combo.currentIndex()
        if idx == 0:
            self.host_input.clear()
            self.port_input.setText("22")
            self.user_input.clear()
            self.pass_input.clear()
        else:
            key = self.profile_combo.currentText()
            data = self.sessions.get(key, {})
            self.host_input.setText(data.get("host", ""))
            self.port_input.setText(str(data.get("port", "22")))
            self.user_input.setText(data.get("user", ""))
            self.pass_input.setText(data.get("password", ""))

    def start_connection(self):
        self.connect_btn.setEnabled(False)
        self.progress.show()
        try:
            port = int(self.port_input.text())
        except ValueError:
            QMessageBox.warning(self, "Error", "Port must be a number.")
            self.connect_btn.setEnabled(True)
            self.progress.hide()
            return
            
        host, user, pwd = self.host_input.text(), self.user_input.text(), self.pass_input.text()
        self.worker = SSHWorker(host, port, user, pwd, task_type="connect")
        self.worker.result_signal.connect(lambda s, m: self.handle_login_result(s, m, host, port, user, pwd))
        self.worker.start()

    def handle_login_result(self, status, msg, host, port, user, pwd):
        self.progress.hide()
        self.connect_btn.setEnabled(True)
        if status == "success":
            ConfigManager.save_session(host, port, user, pwd)
            self.main_window = MainWindow(host, port, user, pwd)
            self.main_window.show()
            self.close()
        else:
            QMessageBox.critical(self, "Connection Failed", f"Could not connect: {msg}")

class MainWindow(QMainWindow):
    def __init__(self, host, port, user, password):
        super().__init__()
        self.host, self.port, self.user, self.password = host, port, user, password
        
        self.active_workers = []
        
        self.alerts_enabled = True 
        self.is_alert_open = False 
        
        self.last_alert_time = 0
        self.snooze_until = 0
        
        self.alert_rules = ConfigManager.load_rules()
        self.saved_filters = ConfigManager.load_filters()
        self.collected_logs_data = [] 
        
        # Central Color Cache
        self.dynamic_color_cache = {}
        
        self.setWindowTitle(f"CTRL X | Honeypot Manager | {self.host}")
        self.resize(1300, 900)
        self.setStyleSheet(STYLE_SHEET)
        
        self.tray_icon = QSystemTrayIcon(self)
        self.tray_icon.setIcon(self.style().standardIcon(QStyle.StandardPixmap.SP_ComputerIcon))
        self.tray_icon.show()
        
        self.log_update_timer = QTimer(self)
        self.log_update_timer.timeout.connect(self.process_log_queue)
        self.log_queue = []
        self.log_update_timer.start(100)

        self.log_monitor = LogMonitorWorker(self.host, self.port, self.user, self.password)
        self.log_monitor.log_batch_signal.connect(self.queue_logs)
        self.log_monitor.start()
        
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)
        
        header_layout = QHBoxLayout()
        title = QLabel("HONEYPOT MANAGER")
        title.setObjectName("HeaderTitle")
        header_layout.addWidget(title)
        
        header_layout.addStretch()
        
        self.alert_toggle_btn = QPushButton("🔔 Alerts: ON")
        self.alert_toggle_btn.setCheckable(True)
        self.alert_toggle_btn.setChecked(True)
        self.alert_toggle_btn.clicked.connect(self.toggle_alerts)
        self.alert_toggle_btn.setStyleSheet("background-color: #2e7d32; min-width: 100px;")
        header_layout.addWidget(self.alert_toggle_btn)
        
        self.refresh_btn = QPushButton("♻ Refresh Status")
        self.refresh_btn.clicked.connect(self.refresh_services)
        header_layout.addWidget(self.refresh_btn)
        
        settings_btn = QPushButton("⚙ Settings")
        settings_btn.clicked.connect(self.show_settings_dialog)
        header_layout.addWidget(settings_btn)
        main_layout.addLayout(header_layout)
        
        self.conn_label = QLabel(f"Connected to: {self.host}")
        main_layout.addWidget(self.conn_label)
        
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)
        
        # --- TAB INIT (Consolidated) ---
        self.init_dashboard_tab()       # Index 0
        self.init_deep_analysis_tab()   # Index 1
        self.init_analytics_tab()       # Index 2
        self.init_firewall_tab()        # Index 3
        self.init_ports_tab()           # Index 4
        self.init_terminal_tab()        # Index 5 (With Quick Tools)
        self.init_structured_logs_tab() # Index 6 (With Full Log Viewer)
        
        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Ready")
        self.refresh_services()

    # 3. COLOR DISTINCTION SYSTEM
    def get_color_for_key(self, key):
        """Returns a consistent color for any IP or String."""
        if key in self.dynamic_color_cache:
            return self.dynamic_color_cache[key]
        
        # Hash based index from DISTINCT_COLORS
        hash_val = int(hashlib.md5(key.encode()).hexdigest(), 16)
        color_idx = hash_val % len(DISTINCT_COLORS)
        color = DISTINCT_COLORS[color_idx]
        
        self.dynamic_color_cache[key] = color
        return color

    def get_attack_color_map(self):
        return {
            "Cowrie": QColor("#00FFFF"),       
            "Dionaea": QColor("#FFA500"),      
            "Brute Force Attempt": QColor("#FF0000"), 
            "Command Execution": QColor("#00FF00"),   
            "Malware Download": QColor("#800080"),    
            "Shellcode Detected": QColor("#FF00FF"),  
            "SMB Probe": QColor("#0000FF"),     
            "HTTP Probe": QColor("#FFFF00"),    
            "Connection Established": QColor("#C0C0C0"), 
            "Unknown Event": QColor("#808080"), 
            "Activity": QColor("#FFFFFF"),      
        }

    def highlight_text(self, text, search_term):
        if not search_term: return html.escape(text)
        pattern = re.compile(re.escape(search_term), re.IGNORECASE)
        highlighted = pattern.sub(
            lambda m: f"<span style='background-color: yellow; color: black;'>{m.group(0)}</span>", 
            text
        )
        return highlighted

    def activate_snooze(self):
        settings = ConfigManager.load_global_settings()
        duration = int(settings.get("snooze_duration", 60))
        self.snooze_until = time.time() + duration
        self.alert_toggle_btn.setText(f"💤 Snoozed ({duration}s)")
        self.alert_toggle_btn.setStyleSheet("background-color: #ff9800; color: #000; min-width: 100px;")
        QTimer.singleShot(duration * 1000, self.reset_alert_btn)
        self.status_bar.showMessage(f"Alerts snoozed for {duration} seconds.", 3000)

    def reset_alert_btn(self):
        if self.alerts_enabled:
            self.alert_toggle_btn.setText("🔔 Alerts: ON")
            self.alert_toggle_btn.setStyleSheet("background-color: #2e7d32; min-width: 100px;")

    def toggle_alerts(self):
        if self.alert_toggle_btn.isChecked():
            self.alerts_enabled = True
            self.alert_toggle_btn.setText("🔔 Alerts: ON")
            self.alert_toggle_btn.setStyleSheet("background-color: #2e7d32; min-width: 100px;")
        else:
            self.alerts_enabled = False
            self.alert_toggle_btn.setText("🔕 Alerts: OFF")
            self.alert_toggle_btn.setStyleSheet("background-color: #555; color: #aaa; min-width: 100px;")

    def queue_logs(self, batch):
        self.log_queue.extend(batch)

    def process_log_queue(self):
        if not self.log_queue: return
        batch = self.log_queue[:50]
        del self.log_queue[:50]
        for raw_message in batch:
            try:
                self.process_single_log(raw_message)
            except Exception as e:
                print(f"Error processing log line: {e}")

    def process_single_log(self, raw_message):
        data = self.parse_log_line(raw_message)
        ignore_list = ConfigManager.load_ignore_list()
        for ignored in ignore_list:
            if ignored in raw_message: return
            if data and ignored in data.get('details', ''): return

        if data:
            if hasattr(self, 'deep_dashboard'):
                self.deep_dashboard.ingest_live_log(data)

            if self.collected_logs_data:
                last_log = self.collected_logs_data[-1]
                if last_log['raw'] == data['raw']:
                     pass 
                else:
                    self.collected_logs_data.append(data)
                    self.update_structured_log(data)
            else:
                 self.collected_logs_data.append(data)
                 self.update_structured_log(data)
            
            if len(self.collected_logs_data) > 3000: 
                self.collected_logs_data.pop(0)

            if data['source'] == "Cowrie":
                self.count_cowrie += 1
                self.lbl_cowrie_count.setText(f"Cowrie: {self.count_cowrie}")
                self.update_dashboard_list(self.list_cowrie, data)
            elif data['source'] == "Dionaea":
                self.count_dionaea += 1
                self.lbl_dionaea_count.setText(f"Dionaea: {self.count_dionaea}")
                self.update_dashboard_list(self.list_dionaea, data)

        self.update_alert_history(raw_message, data)

    def update_dashboard_list(self, list_widget, data):
        if list_widget.count() > 0:
            top_item = list_widget.item(0)
            top_data = top_item.data(Qt.ItemDataRole.UserRole)
            
            if top_data and top_data.get('ip') == data.get('ip') and top_data.get('event') == data.get('event'):
                count = top_data.get('_repeat_count', 1)
                count += 1
                top_data['_repeat_count'] = count
                
                if '_history' not in top_data:
                    top_data['_history'] = [top_data.copy()]
                top_data['_history'].append(data)
                
                display_text = f"[{count}x] [{data['time']}] {data['ip']} - {data.get('classification', 'Event')}"
                top_item.setText(display_text)
                top_item.setData(Qt.ItemDataRole.UserRole, top_data)
                return

        data['_repeat_count'] = 1
        data['_history'] = [data.copy()] 

        display_text = f"[{data['time']}] {data['ip']} - {data.get('classification', 'Event')}"
        item = QListWidgetItem(display_text)
        item.setData(Qt.ItemDataRole.UserRole, data)
        list_widget.insertItem(0, item)

    def update_alert_history(self, message, parsed_data=None):
        alert_title = "INTRUSION DETECTED!"
        should_alert = True
        
        self.alert_rules = ConfigManager.load_rules() 
        for rule in self.alert_rules:
            match = False
            if rule.get("type") == "ip" and parsed_data:
                 if parsed_data.get("ip") != "-" and rule.get("value") in parsed_data.get("ip"):
                    match = True
            else:
                key = rule.get("value", rule.get("keyword", ""))
                if key and key.lower() in message.lower():
                    match = True
            if match:
                if rule["action"] == "ignore": should_alert = False; return 
                elif rule["action"] == "rename": alert_title = rule["custom_name"]

        if not should_alert: return
        if self.alerts_enabled and not self.is_alert_open:
            self.trigger_emergency_popup(message, alert_title)

    def trigger_emergency_popup(self, message, title):
        if self.is_alert_open: return 
        if not self.alerts_enabled: return

        current_time = time.time()
        settings = ConfigManager.load_global_settings()
        delay = int(settings.get("alert_delay", 5))

        if current_time < self.snooze_until: return 
        if current_time - self.last_alert_time < delay: return
        self.last_alert_time = current_time

        attacker_ip = None
        data = self.parse_log_line(message)
        
        if data and data.get('ip') != "-": 
            attacker_ip = data.get('ip')
        else:
            source = data.get('source') if data else None
            if source:
                for past_log in reversed(self.collected_logs_data):
                    if past_log.get('source') == source and past_log.get('ip') != "-":
                        attacker_ip = past_log.get('ip')
                        break

        self.is_alert_open = True
        self.tray_icon.showMessage(title, message, QSystemTrayIcon.MessageIcon.Warning, 5000)
        
        dlg = EmergencyDialog(message, title, self, attacker_ip=attacker_ip)
        dlg.exec()
        
        self.is_alert_open = False

    def update_structured_log(self, data):
        if not data: return
        
        row_data = [
            data['time'], 
            data['source'], 
            data['ip'], 
            data['event'], 
            data['auth'], 
            data['details']
        ]

        source_filter = self.log_filter_source.currentText()
        text_filter = self.log_filter_text.text().lower()
        
        match_source = (source_filter == "All Sources") or (source_filter in data['source'])
        match_text = True
        if text_filter:
            full_str = f"{data['ip']} {data['event']} {data['details']}".lower()
            if text_filter not in full_str: match_text = False
            
        row = self.parsed_table.rowCount()
        self.parsed_table.insertRow(row)

        for i, item_text in enumerate(row_data):
            item = QTableWidgetItem(self.highlight_text(item_text, text_filter))
            if i == 1: 
                item.setForeground(QColor("#00bcd4") if data['source']=="Cowrie" else QColor("#ff9800"))
            elif i == 3 and ("login" in data['event'] or "attack" in data['event']):
                item.setForeground(QColor("#ff5252"))
                item.setFont(QFont("Segoe UI", 9, QFont.Weight.Bold))
            self.parsed_table.setItem(row, i, item)
            
        btn_details = QPushButton("🔍")
        btn_details.setStyleSheet("background-color: #333; color: white; padding: 2px;")
        btn_details.clicked.connect(lambda _, d=data: self.open_log_details(d))
        self.parsed_table.setCellWidget(row, 6, btn_details)
        
        if not (match_source and match_text):
            self.parsed_table.setRowHidden(row, True)
            
        self.parsed_table.scrollToBottom()

    def open_log_details(self, data):
        dlg = LogDetailsPopup(data, self)
        dlg.exec()

    def classify_attack_painless(self, msg):
        msg = str(msg)
        if not msg: return "Unknown Event"
        if "dionaea.download.complete" in msg: return "Malware Download"
        if "connection_stats_accounting_limit_exceeded" in msg: return "Connection Limit Exceeded"
        if "connection established" in msg: return "Connection Established"
        if "shellcode" in msg: return "Shellcode Detected"
        if "smb" in msg: return "SMB Probe"
        if "http" in msg: return "HTTP Probe"
        if "rtsp" in msg: return "RTSP Scan"
        if "sip" in msg: return "VoIP Attack"
        if "ftp" in msg: return "FTP Scan/Bruteforce"
        if "login attempt" in msg: return "Brute Force Attempt"
        if "CMD:" in msg: return "Command Execution"
        if "New channel" in msg: return "SSH Session Start"
        if "incident" in msg: return "Incident Reported"
        if "emu" in msg: return "Emulator Event"
        if "reject" in msg: return "Connection Rejected"
        return "Activity"

    def parse_log_line(self, line):
        IGNORED_IPS = ["127.0.0.1", "0.0.0.0", "::1", "localhost", "fe80::", "::ffff:127.0.0.1"]
        
        res = {
            "time": QDateTime.currentDateTime().toString("yyyy-MM-dd HH:mm:ss"),
            "source": "System",
            "ip": "-",
            "event": "Log",
            "auth": "-",
            "details": line[:150],
            "raw": line,
            "classification": "Activity",
            "risk": 0, # 0=Low, 1=Med, 2=High, 3=Critical
            "session": "unknown"
        }

        try:
            if line.strip().startswith("{"):
                j = json.loads(line)
                res['source'] = "Cowrie"
                res['session'] = j.get('session', 'unknown')
                
                ts_str = j.get('timestamp', '')
                if ts_str:
                    try:
                        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                        res['time'] = dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")
                    except: pass

                res['event'] = j.get('eventid', 'Unknown')
                
                ip_candidate = j.get('src_ip', '-')
                if ip_candidate in IGNORED_IPS: ip_candidate = "-"
                res['ip'] = ip_candidate

                msg = j.get('message', '')
                
                if 'login' in res['event']:
                    res['auth'] = f"U: {j.get('username','')} | P: {j.get('password','')}"
                    res['classification'] = "Brute Force Attempt"
                    res['risk'] = 2
                elif 'command' in res['event']:
                    res['details'] = f"CMD: {j.get('input', '')}"
                    res['classification'] = "Command Execution"
                    res['risk'] = 3
                elif 'file_upload' in res['event']:
                    res['classification'] = "Malware Upload"
                    res['risk'] = 3
                elif 'client.version' in res['event']:
                     res['classification'] = "Scanner Detection"
                     res['risk'] = 1
                else:
                     res['classification'] = self.classify_attack_painless(msg)

                return res

            if "dionaea" in line.lower() or line.startswith("["):
                res['source'] = "Dionaea"
                
                time_match = re.search(r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', line)
                if time_match:
                    res['time'] = time_match.group(1)

                clean_line = line.replace("::ffff:", "") 
                ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', clean_line)
                
                valid_ip = "-"
                for ip in ips:
                     if ip not in IGNORED_IPS and not ip.startswith("192.168.") and not ip.startswith("172.") and not ip.startswith("10."):
                        valid_ip = ip
                        break 
                
                res['ip'] = valid_ip
                res['classification'] = self.classify_attack_painless(line)
                
                if "reject" in line: res['risk'] = 0
                elif "download" in line or "smb" in line: res['risk'] = 3
                elif "mqtt" in line or "sip" in line: res['risk'] = 2
                else: res['risk'] = 1
                
                return res

        except Exception as e:
            pass 
            
        return res

    def start_worker(self, worker):
        self.active_workers.append(worker)
        worker.finished.connect(lambda: self.cleanup_worker(worker))
        worker.start()
    
    def cleanup_worker(self, worker):
        if worker in self.active_workers: self.active_workers.remove(worker)
        worker.deleteLater()

    def closeEvent(self, event):
        if self.log_monitor.isRunning(): self.log_monitor.stop()
        event.accept()

    def logout(self):
        self.close()
        self.login_window = LoginWindow()
        self.login_window.show()

    # ------------------ TABS ------------------
    def init_dashboard_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        controls_frame = QFrame()
        controls_frame.setObjectName("Card")
        c_layout = QHBoxLayout(controls_frame)
        
        start_all = QPushButton("▶ START ALL SYSTEM")
        start_all.setStyleSheet("background-color: #2e7d32; font-weight: bold; padding: 10px;")
        start_all.clicked.connect(lambda: self.batch_action("start"))
        
        stop_all = QPushButton("⏹ STOP ALL SYSTEM")
        stop_all.setObjectName("StopBtn")
        stop_all.setStyleSheet("padding: 10px;")
        stop_all.clicked.connect(lambda: self.batch_action("stop"))

        c_layout.addWidget(start_all)
        c_layout.addWidget(stop_all)
        layout.addWidget(controls_frame)

        monitor_frame = QFrame()
        monitor_frame.setObjectName("Card")
        monitor_frame.setStyleSheet("#Card { border: 1px solid #444; background: #222; }")
        m_layout = QVBoxLayout(monitor_frame)
        
        header_mon = QHBoxLayout()
        self.lbl_cowrie_count = QLabel("Cowrie: 0")
        self.lbl_cowrie_count.setStyleSheet("color: #00bcd4; font-size: 16px; font-weight: bold;")
        self.lbl_dionaea_count = QLabel("Dionaea: 0")
        self.lbl_dionaea_count.setStyleSheet("color: #ff9800; font-size: 16px; font-weight: bold;")
        
        btn_clear_mon = QPushButton("🗑 Clear Monitor")
        btn_clear_mon.setFixedSize(140, 30)
        btn_clear_mon.clicked.connect(self.clear_dashboard_monitor)

        header_mon.addWidget(self.lbl_cowrie_count)
        header_mon.addStretch()
        header_mon.addWidget(btn_clear_mon)
        header_mon.addStretch()
        header_mon.addWidget(self.lbl_dionaea_count)
        m_layout.addLayout(header_mon)

        split_layout = QHBoxLayout()
        self.list_cowrie = QListWidget()
        self.list_cowrie.setStyleSheet("background-color: #1e1e1e; border: 1px solid #00bcd4; color: #eee;")
        self.list_cowrie.itemDoubleClicked.connect(lambda item: self.open_log_details(item.data(Qt.ItemDataRole.UserRole)))

        self.list_dionaea = QListWidget()
        self.list_dionaea.setStyleSheet("background-color: #1e1e1e; border: 1px solid #ff9800; color: #eee;")
        self.list_dionaea.itemDoubleClicked.connect(lambda item: self.open_log_details(item.data(Qt.ItemDataRole.UserRole)))

        split_layout.addWidget(self.list_cowrie)
        split_layout.addWidget(self.list_dionaea)
        m_layout.addLayout(split_layout)
        
        layout.addWidget(QLabel("<h3>🛡 Live Monitor</h3>"))
        layout.addWidget(monitor_frame)

        grid = QGridLayout()
        self.cowrie_card = self.create_service_card("Cowrie SSH", "cowrie", "docker")
        self.dionaea_card = self.create_service_card("Dionaea Server", "dionaea", "docker")
        self.filebeat_card = self.create_service_card("Filebeat Shipper", "filebeat", "systemd")
        
        grid.addWidget(self.cowrie_card, 0, 0)
        grid.addWidget(self.dionaea_card, 0, 1)
        grid.addWidget(self.filebeat_card, 0, 2)
        layout.addLayout(grid)
        
        self.tabs.addTab(tab, "📊 Dashboard")
        self.count_cowrie = 0
        self.count_dionaea = 0

    def init_deep_analysis_tab(self):
        self.deep_dashboard = DeepAnalysisDashboard(self)
        self.tabs.addTab(self.deep_dashboard, "🚀 Deep Analysis SOC")

    def init_analytics_tab(self):
        self.analytics_dash = AnalyticsDashboard(self)
        self.tabs.addTab(self.analytics_dash, "📈 Analytics & Analysis")

    def clear_dashboard_monitor(self):
        self.list_cowrie.clear()
        self.list_dionaea.clear()
        self.count_cowrie = 0
        self.count_dionaea = 0
        self.lbl_cowrie_count.setText("Cowrie: 0")
        self.lbl_dionaea_count.setText("Dionaea: 0")

    def create_service_card(self, name, service_name, service_type):
        frame = QFrame()
        frame.setObjectName("Card")
        layout = QVBoxLayout(frame)
        
        lbl_name = QLabel(name)
        lbl_name.setStyleSheet("font-weight: bold; font-size: 18px;")
        lbl_status = QLabel("Checking...")
        lbl_status.setStyleSheet("color: gray;")
        
        btn_start = QPushButton("Start")
        btn_stop = QPushButton("Stop")
        btn_stop.setObjectName("StopBtn")
        
        if service_type == "docker":
            btn_start.clicked.connect(lambda: self.run_command(f"docker start {service_name}"))
            btn_stop.clicked.connect(lambda: self.run_command(f"docker stop {service_name}"))
        else: 
            start_cmd = f"echo {self.password} | sudo -S systemctl start {service_name}"
            stop_cmd = f"echo {self.password} | sudo -S systemctl stop {service_name}"
            btn_start.clicked.connect(lambda: self.run_command(start_cmd))
            btn_stop.clicked.connect(lambda: self.run_command(stop_cmd))
            
        layout.addWidget(lbl_name)
        layout.addWidget(lbl_status)
        btn_layout = QHBoxLayout()
        btn_layout.addWidget(btn_start)
        btn_layout.addWidget(btn_stop)
        layout.addLayout(btn_layout)
        return frame

    def init_firewall_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        block_frame = QFrame()
        block_frame.setObjectName("Card")
        bf_layout = QVBoxLayout(block_frame)
        bf_layout.addWidget(QLabel("🚫 Advanced Blocking System"))
        
        form = QGridLayout()
        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Attacker IP")
        
        self.target_service = QComboBox()
        self.target_service.addItems(["Block All Traffic", "Block Cowrie (2222)", "Block Dionaea (All)", "Block FTP (21)", "Block HTTP (80/443)", "Block SIP (5060)"])
        
        btn_block = QPushButton("🔨 EXECUTE BAN")
        btn_block.setStyleSheet("background-color: #d32f2f;")
        btn_block.clicked.connect(self.check_and_execute_ban_ui) 
        
        form.addWidget(QLabel("Target IP:"), 0, 0)
        form.addWidget(self.ip_input, 0, 1)
        form.addWidget(QLabel("Action:"), 1, 0)
        form.addWidget(self.target_service, 1, 1)
        form.addWidget(btn_block, 2, 0, 1, 2)
        bf_layout.addLayout(form)
        layout.addWidget(block_frame)
        
        layout.addWidget(QLabel("📜 Active Bans (DOCKER-USER Chain):"))
        self.ban_table = QTableWidget()
        self.ban_table.setColumnCount(4) # Added Detail Column
        self.ban_table.setHorizontalHeaderLabels(["Line", "Source IP", "Ban Type / Port", "Action"])
        self.ban_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.ban_table)
        
        btn_refresh_bans = QPushButton("Refresh Ban List")
        btn_refresh_bans.clicked.connect(self.refresh_ban_list)
        layout.addWidget(btn_refresh_bans)
        self.tabs.addTab(tab, "🛡 Firewall & Bans")

    def check_and_execute_ban_ui(self):
        ip = self.ip_input.text().strip()
        service_idx = self.target_service.currentIndex()
        if not ip:
            QMessageBox.warning(self, "Error", "Please enter a valid IP.")
            return
        self.check_and_execute_ban(ip, service_idx, show_feedback=True)
    
    def check_and_execute_ban_ui_direct(self, ip):
        reply = QMessageBox.question(self, "Confirm Ban", f"Are you sure you want to BAN IP: {ip}?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.check_and_execute_ban(ip, service_idx=0, show_feedback=True)

    def check_and_execute_ban(self, ip, service_idx=0, silent=False, show_feedback=False):
        worker = SSHWorker(self.host, self.port, self.user, self.password, task_type="check_ip_ban")
        worker.data_signal.connect(lambda output: self._continue_ban_process(output, ip, service_idx, silent, show_feedback))
        self.start_worker(worker)

    def _continue_ban_process(self, output, ip, service_idx, silent, show_feedback):
        is_banned = False
        for line in output.splitlines():
            if f"source {ip}" in line and "DROP" in line:
                is_banned = True
                break
            if ip == "0.0.0.0/0" and "DROP" in line:
                is_banned = True
                break
        
        if is_banned:
            msg = f"Already Banned! IP: {ip} is already in the blocklist."
            if not silent:
                QMessageBox.information(self, "Ban Status", msg)
                self.status_bar.showMessage(msg, 5000)
            self.refresh_ban_list() 
            return

        if show_feedback:
            self.status_bar.showMessage(f"Executing Ban for: {ip}...", 5000)

        base = f"echo {self.password} | sudo -S iptables -I DOCKER-USER -s {ip}"
        
        if service_idx == 0: cmd = f"{base} -j DROP"
        elif service_idx == 1: cmd = f"{base} -p tcp --dport 2222 -j DROP"
        elif service_idx == 2: cmd = f"{base} -p tcp -m multiport --dports 21,42,80,443,445,1433,5060 -j DROP"
        elif service_idx == 3: cmd = f"{base} -p tcp --dport 21 -j DROP"
        elif service_idx == 4: cmd = f"{base} -p tcp -m multiport --dports 80,443 -j DROP"
        elif service_idx == 5: cmd = f"{base} -p tcp --dport 5060 -j DROP"
        else: cmd = f"{base} -j DROP"

        self.run_command(cmd, post_message=f"IP Banned Successfully: {ip}")
        QTimer.singleShot(1000, self.refresh_ban_list)

    def execute_auto_defense(self, ip):
        self.check_and_execute_ban(ip, silent=True) 

        settings = ConfigManager.load_global_settings()
        if settings.get("auto_close_port", False):
            cmd_close = f"echo {self.password} | sudo -S iptables -I DOCKER-USER 1 -p tcp -m multiport --dports 2222,21,445 -j DROP"
            self.run_command(cmd_close)

        if settings.get("auto_stop_service", False):
            cmd_stop = f"docker stop cowrie dionaea"
            self.run_command(cmd_stop)

    def go_to_firewall_and_ban(self, ip):
        self.tabs.setCurrentIndex(3) # Firewall Tab Index
        self.ip_input.setText(ip)
        self.check_and_execute_ban_ui_direct(ip)
     
    def init_ports_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        top_bar = QHBoxLayout()
        self.port_search = QLineEdit()
        self.port_search.setPlaceholderText("🔍 Search Ports...")
        self.port_search.textChanged.connect(self.filter_ports)
        refresh_ports_btn = QPushButton("Refresh Status")
        refresh_ports_btn.setFixedWidth(120)
        refresh_ports_btn.clicked.connect(self.check_ports_status)
        
        top_bar.addWidget(self.port_search)
        top_bar.addWidget(refresh_ports_btn)
        layout.addLayout(top_bar)
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        self.ports_grid = QGridLayout(content)
        
        self.port_lamps = {} 
        self.port_cards = [] 
        
        categories = {
            "🍯 Honeypots": [
                ("Cowrie SSH", "2222", "tcp"),
                ("Dionaea FTP", "21", "tcp"),
                ("Dionaea HTTP", "80", "tcp"),
                ("Dionaea HTTPS", "443", "tcp"),
                ("Dionaea SMB", "445", "tcp"),
                ("Dionaea MSSQL", "1433", "tcp"),
                ("Dionaea SIP", "5060", "tcp"),
                ("Dionaea SIP-TLS", "5061", "tcp"),
                ("Dionaea MySQL", "3306", "tcp"),
                ("Dionaea TFTP", "69", "udp")
            ],
            "🖥️ System Services": [
                ("DNS Stub", "53", "tcp"),
                ("mDNS", "5353", "udp"),
                ("IPP (Printing)", "631", "tcp")
            ]
        }
        
        row = 0
        for cat_name, ports in categories.items():
            header = QLabel(cat_name)
            header.setStyleSheet("font-size: 16px; font-weight: bold; color: #007acc; margin-top: 10px;")
            self.ports_grid.addWidget(header, row, 0)
            row += 1
            
            for name, port, proto in ports:
                card = QFrame()
                card.setObjectName("Card")
                c_layout = QHBoxLayout(card)
                
                lamp = QLabel()
                lamp.setObjectName("StatusLampOff")
                lamp.setFixedSize(16, 16)
                self.port_lamps[port] = lamp 

                info_box = QWidget()
                info_layout = QVBoxLayout(info_box)
                info_layout.setContentsMargins(0,0,0,0)
                lbl_n = QLabel(f"<b>{name}</b>")
                lbl_p = QLabel(f"{port}/{proto}")
                info_layout.addWidget(lbl_n)
                info_layout.addWidget(lbl_p)
                
                c_layout.addWidget(lamp)
                c_layout.addWidget(info_box)
                c_layout.addStretch()

                cmd_open = f"echo {self.password} | sudo -S iptables -D DOCKER-USER -p {proto} --dport {port} -j DROP || true"
                btn_open = QPushButton("Open")
                btn_open.setStyleSheet("background-color: #2e7d32;")
                btn_open.clicked.connect(lambda checked, c=cmd_open: self.run_command(c))
                
                cmd_close = f"echo {self.password} | sudo -S iptables -I DOCKER-USER 1 -p {proto} --dport {port} -j DROP"
                btn_close = QPushButton("Close")
                btn_close.setObjectName("StopBtn")
                btn_close.clicked.connect(lambda checked, c=cmd_close: self.run_command(c))
                
                c_layout.addWidget(btn_open)
                c_layout.addWidget(btn_close)
                
                self.ports_grid.addWidget(card, row, 0)
                self.port_cards.append((card, f"{name} {port} {proto}".lower()))
                row += 1
        
        scroll.setWidget(content)
        layout.addWidget(scroll)
        self.tabs.addTab(tab, "🔌 Port Manager")

    def filter_ports(self, text):
        search_text = text.lower()
        for card, card_text in self.port_cards:
            if search_text in card_text: card.setVisible(True)
            else: card.setVisible(False)

    # --- MERGED: TERMINAL & QUICK TOOLS ---
    def init_terminal_tab(self):
        tab = QWidget()
        main_layout = QHBoxLayout(tab) # Split view
        
        # LEFT: TERMINAL
        term_container = QWidget()
        t_layout = QVBoxLayout(term_container)
        
        self.term_output = QTextEdit()
        self.term_output.setStyleSheet("background-color: #000; color: #0f0; font-family: Consolas;")
        self.term_output.setReadOnly(True)
        
        input_layout = QHBoxLayout()
        self.term_input = QLineEdit()
        self.term_input.setStyleSheet("background-color: #222; color: #fff; font-family: Consolas;")
        self.term_input.returnPressed.connect(self.execute_terminal_command)
        
        btn_send = QPushButton("Send")
        btn_send.clicked.connect(self.execute_terminal_command)
        
        btn_clear = QPushButton("Clear Screen")
        btn_clear.setObjectName("ClearBtn")
        btn_clear.clicked.connect(self.term_output.clear)
        
        input_layout.addWidget(QLabel("user@vm:~$"))
        input_layout.addWidget(self.term_input)
        input_layout.addWidget(btn_send)
        input_layout.addWidget(btn_clear)
        
        t_layout.addWidget(QLabel("<h3>🖥️ Live Shell</h3>"))
        t_layout.addWidget(self.term_output)
        t_layout.addLayout(input_layout)
        
        # RIGHT: QUICK TOOLS
        tools_container = QFrame()
        tools_container.setFixedWidth(300)
        tools_container.setObjectName("Card")
        q_layout = QVBoxLayout(tools_container)
        
        q_layout.addWidget(QLabel("<h3>⚡ Quick Tools</h3>"))
        
        tools = [
            ("🔍 Check IP Address", "ip addr show"),
            ("🐳 Docker Status", "docker ps -a"),
            ("💾 Disk Usage", "df -h"),
            ("🧠 Memory Usage", "free -m"),
            ("🌐 Network Connections", "netstat -tuln"),
            ("📊 Filebeat Status", "systemctl status filebeat --no-pager -l"),
            ("👤 Who is logged in", "who"),
            ("⏱️ Uptime", "uptime"),
            ("📈 Top Processes", "top -b -n 1 | head -n 15"),
            ("🔥 IPTables Rules", f"echo {self.password} | sudo -S iptables -L -n")
        ]
        
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll_content = QWidget()
        sc_layout = QVBoxLayout(scroll_content)
        
        for label, cmd in tools:
            btn = QPushButton(label)
            btn.setFixedHeight(40)
            btn.clicked.connect(lambda ch, cm=cmd: self.run_in_terminal_direct(cm))
            sc_layout.addWidget(btn)
        
        sc_layout.addStretch()
        scroll.setWidget(scroll_content)
        q_layout.addWidget(scroll)

        main_layout.addWidget(term_container)
        main_layout.addWidget(tools_container)
        
        self.tabs.addTab(tab, "💻 Live Terminal & Tools")

    def run_in_terminal_direct(self, cmd):
        self.term_input.setText(cmd)
        self.execute_terminal_command()

    # --- MERGED: STRUCTURED LOGS & FULL LOGS ---
    def init_structured_logs_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        self.logs_sub_tabs = QTabWidget()
        layout.addWidget(self.logs_sub_tabs)
        
        # --- SUB TAB 1: LIVE DATA ---
        live_tab = QWidget()
        lt_layout = QVBoxLayout(live_tab)
        
        filter_box = QFrame()
        filter_box.setObjectName("SectionHeader")
        fb_layout = QHBoxLayout(filter_box)
        
        fb_layout.addWidget(QLabel("Filter:"))
        self.log_filter_source = QComboBox()
        self.log_filter_source.addItems(["All Sources", "Cowrie", "Dionaea"])
        self.log_filter_source.currentIndexChanged.connect(lambda: self.filter_structured_logs(self.log_filter_text.text()))
        fb_layout.addWidget(self.log_filter_source)
        
        self.log_filter_text = QLineEdit()
        self.log_filter_text.setPlaceholderText("Search IP, Event, or Text (Hides non-matching rows)...")
        self.log_filter_text.textChanged.connect(self.filter_structured_logs)
        fb_layout.addWidget(self.log_filter_text)
        
        btn_undo = QPushButton("↺ Restore Last 15m")
        btn_undo.setToolTip("Recover logs if cleared by mistake")
        btn_undo.clicked.connect(lambda: self.restore_logs_time(15))
        fb_layout.addWidget(btn_undo)
        
        btn_clear = QPushButton("🗑 Clear Live Logs")
        btn_clear.clicked.connect(self.clear_live_logs)
        fb_layout.addWidget(btn_clear)
        
        lt_layout.addWidget(filter_box)

        self.parsed_table = QTableWidget()
        self.parsed_table.setColumnCount(7) 
        self.parsed_table.setHorizontalHeaderLabels(["Time", "Source", "Attacker IP", "Event Type", "Auth Info", "Details", "View"])
        
        h = self.parsed_table.horizontalHeader()
        h.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch) 
        h.setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch) 
        h.setSectionResizeMode(6, QHeaderView.ResizeMode.Fixed) 
        self.parsed_table.setColumnWidth(6, 50)
        self.parsed_table.setStyleSheet("QTableWidget { background-color: #1e1e1e; color: #e0e0e0; gridline-color: #333; }")
        self.parsed_table.setWordWrap(True)
        self.parsed_table.setItemDelegateForColumn(5, HTMLDelegate(self.parsed_table)) 
        lt_layout.addWidget(self.parsed_table)
        
        # --- SUB TAB 2: FULL HISTORY ---
        self.full_log_viewer = FullLogViewer(self)
        
        self.logs_sub_tabs.addTab(live_tab, "Live Last Logs")
        self.logs_sub_tabs.addTab(self.full_log_viewer, "📚 Full Log Archive")

        self.tabs.addTab(tab, "🗂 Logs & Data Center")

    def clear_live_logs(self):
        self.collected_logs_data.clear()
        self.parsed_table.setRowCount(0)
        self.clear_dashboard_monitor()

    def filter_structured_logs(self, text):
        search = text.lower()
        source_filter = self.log_filter_source.currentText()
        
        self.parsed_table.setUpdatesEnabled(False)
        for i in range(self.parsed_table.rowCount()):
            match_text = False
            match_source = True
            
            item_src = self.parsed_table.item(i, 1)
            if item_src and source_filter != "All Sources" and source_filter != item_src.text():
                match_source = False

            raw_content = ""
            if i < len(self.collected_logs_data):
                raw_content = self.collected_logs_data[i]['raw']
            else:
                 for j in range(6):
                     it = self.parsed_table.item(i, j)
                     if it: raw_content += it.text() + " "
            
            if search in raw_content.lower():
                match_text = True
            
            if match_source and match_text:
                self.parsed_table.setRowHidden(i, False)
                for j in range(6):
                    item = self.parsed_table.item(i, j)
                    if item:
                        plain = QTextDocument()
                        plain.setHtml(item.text()) 
                        if i < len(self.collected_logs_data):
                            vals = [
                                self.collected_logs_data[i]['time'], 
                                self.collected_logs_data[i]['source'], 
                                self.collected_logs_data[i]['ip'], 
                                self.collected_logs_data[i]['event'], 
                                self.collected_logs_data[i]['auth'], 
                                self.collected_logs_data[i]['details']
                            ]
                            if j < len(vals):
                                 new_html = self.highlight_text(vals[j], search)
                                 item.setText(new_html)
            else:
                self.parsed_table.setRowHidden(i, True)

        self.parsed_table.setUpdatesEnabled(True)

    def restore_logs_time(self, minutes):
        self.status_bar.showMessage(f"Restoring logs from last {minutes} minutes...")
        cmd = f"tail -n 2000 -q {COWRIE_LOG_PATH} {DIONAEA_LOG_PATH}"
        worker = SSHWorker(self.host, self.port, self.user, self.password, command=cmd, task_type="fetch_logs")
        worker.data_signal.connect(self.populate_restored_logs)
        self.start_worker(worker)

    def populate_restored_logs(self, data):
        self.parsed_table.setSortingEnabled(False) 
        self.parsed_table.setUpdatesEnabled(False) 
        
        self.collected_logs_data.clear()
        self.parsed_table.setRowCount(0)
        
        lines = data.splitlines()
        count = 0
        for line in lines:
            parsed = self.parse_log_line(line)
            if parsed:
                self.process_single_log(line) 
                count += 1
        
        self.parsed_table.setUpdatesEnabled(True)
        self.parsed_table.setSortingEnabled(True)
        QMessageBox.information(self, "Restored", f"Restored {count} log entries.")

    # ---------------------------------------------------------
    # LOGIC
    # ---------------------------------------------------------
    def refresh_services(self):
        self.status_bar.showMessage("Refreshing System Status...")
        worker = SSHWorker(self.host, self.port, self.user, self.password, task_type="check_full_status")
        worker.data_signal.connect(self.update_indicators)
        self.start_worker(worker)
        self.check_ports_status()

    def update_indicators(self, status_data):
        d_list = " ".join(status_data['containers'])
        fb_status = status_data['filebeat']
        
        on = "color: #4caf50; font-weight: bold;"
        off = "color: #ff5252; font-weight: bold;"
        
        sl = self.cowrie_card.layout().itemAt(1).widget()
        sl.setText("ONLINE" if "cowrie" in d_list else "OFFLINE")
        sl.setStyleSheet(on if "cowrie" in d_list else off)
        
        sl = self.dionaea_card.layout().itemAt(1).widget()
        sl.setText("ONLINE" if "dionaea" in d_list else "OFFLINE")
        sl.setStyleSheet(on if "dionaea" in d_list else off)
        
        sl = self.filebeat_card.layout().itemAt(1).widget()
        sl.setText("ACTIVE" if "active" == fb_status else "INACTIVE")
        sl.setStyleSheet(on if "active" == fb_status else off)

    def check_ports_status(self):
        worker = SSHWorker(self.host, self.port, self.user, self.password, task_type="check_ports_security")
        worker.data_signal.connect(self.update_port_lamps)
        self.start_worker(worker)

    def update_port_lamps(self, full_output):
        try:
            parts = full_output.split("|||")
            netstat_out = parts[0]
            iptables_out = parts[1] if len(parts) > 1 else ""
            
            for port, lamp in self.port_lamps.items():
                is_listening = f":{port} " in netstat_out
                is_blocked = False
                for line in iptables_out.splitlines():
                    if "DROP" in line:
                        if f"dpt:{port}" in line or f"dports {port}" in line:
                             if "source" in line and "0.0.0.0/0" not in line:
                                continue 
                             is_blocked = True
                             break
                
                lamp.style().unpolish(lamp)
                if is_listening and not is_blocked: lamp.setObjectName("StatusLampOn")
                elif is_listening and is_blocked: lamp.setObjectName("StatusLampBlocked")
                else: lamp.setObjectName("StatusLampOff")
                lamp.style().polish(lamp)
        except Exception as e:
            print(f"Error parsing ports: {e}")

    def run_command(self, cmd, show_in_term=False, post_message="Action Completed"):
        self.status_bar.showMessage(f"Executing: {cmd}...")
        worker = SSHWorker(self.host, self.port, self.user, self.password, command=cmd, task_type="execute")
        if show_in_term:
            self.tabs.setCurrentIndex(5) # Terminal Tab
            worker.result_signal.connect(self.append_terminal_output)
        else:
            worker.result_signal.connect(lambda s, o: self.show_popup_result(s, o, post_message))
        self.start_worker(worker)

    def execute_terminal_command(self):
        cmd = self.term_input.text()
        if not cmd: return
        self.term_output.append(f"<span style='color:#fff'>$ {cmd}</span>")
        self.term_input.clear()
        self.run_command(cmd, show_in_term=True)

    def append_terminal_output(self, status, output):
        self.term_output.append(output)
        self.term_output.append("-" * 30)
        self.status_bar.showMessage("Done")

    def show_popup_result(self, status, output, custom_message="Action Completed"):
        if status == "error":
            QMessageBox.warning(self, "Error", output)
        else:
            self.status_bar.showMessage(custom_message, 5000)
            if ("iptables" in output and ("-D" in output or "-I" in output)):
                self.refresh_ban_list()
                self.check_ports_status()
            else:
                self.refresh_services()

    def batch_action(self, action):
        docker_cmd = f"docker {action} cowrie dionaea"
        sys_act = "start" if action == "start" else "stop"
        sys_cmd = f"echo {self.password} | sudo -S systemctl {sys_act} filebeat"
        self.run_command(f"{docker_cmd} && {sys_cmd}")

    def refresh_ban_list(self):
        worker = SSHWorker(self.host, self.port, self.user, self.password, task_type="get_bans")
        worker.data_signal.connect(self.populate_ban_table)
        self.start_worker(worker)

    def populate_ban_table(self, output):
        self.ban_table.setRowCount(0)
        row_idx = 0
        for line in output.splitlines():
            if "Chain" in line or "target" in line: continue
            if "DROP" in line:
                parts = line.split()
                if len(parts) >= 5:
                    try:
                        line_num = parts[0]
                        target = parts[1] 
                        source_ip = parts[4] 
                        
                        if target != "DROP": continue 
                        
                        ban_type = "All Traffic"
                        if "dpt:" in line:
                            match = re.search(r'dpt:(\d+)', line)
                            if match: ban_type = f"Port {match.group(1)}"
                        elif "dports" in line:
                             match = re.search(r'dports\s([\d,]+)', line)
                             if match: ban_type = f"Ports {match.group(1)}"
                        
                        if source_ip == "0.0.0.0/0": source_ip = "Anywhere"
                        
                        self.ban_table.insertRow(row_idx)
                        self.ban_table.setItem(row_idx, 0, QTableWidgetItem(line_num))
                        self.ban_table.setItem(row_idx, 1, QTableWidgetItem(source_ip))
                        self.ban_table.setItem(row_idx, 2, QTableWidgetItem(ban_type))
                        
                        btn_unban = QPushButton("✅ Unban")
                        btn_unban.setObjectName("UnbanBtn")
                        
                        cmd_unban = f"echo {self.password} | sudo -S iptables -D DOCKER-USER {line_num}" 
                        
                        def unban_handler(ch, cmd=cmd_unban):
                            self.run_command(cmd, post_message=f"Ban Rule #{line_num} removed.")
                            QTimer.singleShot(1000, self.refresh_ban_list)
                            
                        btn_unban.clicked.connect(unban_handler)
                        self.ban_table.setCellWidget(row_idx, 3, btn_unban)
                        row_idx += 1
                    except Exception as e: print(f"Error parsing line: {e}")

    def show_settings_dialog(self):
        dlg = GlobalSettingsDialog(self, self.host, self.port, self.user, self.password)
        dlg.logout_signal.connect(self.logout)
        if dlg.exec():
            self.host, self.port, self.user, self.password = dlg.get_ssh_data()
            self.conn_label.setText(f"Connected to: {self.host}")
            self.refresh_services()
            QMessageBox.information(self, "Settings", "Settings updated.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    settings = ConfigManager.load_global_settings()
    sound = settings.get("audio_path", DEFAULT_ALARM_FILE)
    
    login = LoginWindow()
    login.show()
    sys.exit(app.exec())