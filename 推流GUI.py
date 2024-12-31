import base64
import os
import sys
import subprocess
import tempfile
import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, Raw, conf
import re


# ---------------------------- 工具函数 ----------------------------

def resource_path(relative_path):
    """获取资源文件路径"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)


def check_winpcap_installed():
    """检查 WinPcap 是否已安装"""
    possible_paths = [
        "C:\\Windows\\System32\\wpcap.dll",
        "C:\\Windows\\SysWOW64\\wpcap.dll"
    ]
    return any(os.path.exists(path) for path in possible_paths)


def get_base64_from_file(base64_file):
    """从文件中读取 Base64 编码内容"""
    with open(base64_file, "rb") as f:
        return f.read()


def save_winpcap_installer():
    """保存嵌入的安装程序到临时文件"""
    base64_data = get_base64_from_file(resource_path("winpcap_base64.txt"))
    installer_path = os.path.join(tempfile.gettempdir(), "winpcap-4.13.exe")
    with open(installer_path, "wb") as installer_file:
        installer_file.write(base64.b64decode(base64_data))
    return installer_path


def install_winpcap():
    """安装 WinPcap"""
    winpcap_installer = save_winpcap_installer()
    try:
        subprocess.run([winpcap_installer, "/S"], check=True)
    except subprocess.CalledProcessError as e:
        log_message(f"WinPcap 安装失败: {e}", "error")
    finally:
        if os.path.exists(winpcap_installer):
            os.remove(winpcap_installer)


def get_all_interfaces():
    """获取所有网卡名称"""
    try:
        return [iface.name for iface in conf.ifaces.values()]
    except Exception:
        return []


# ---------------------------- UI 相关函数 ----------------------------

def ico_option():
    """设置窗口图标"""
    try:
        icon_path = resource_path("tuiliu.ico")
        root.iconbitmap(icon_path)
    except Exception as e:
        log_message(f"无法加载图标: {e}", "error")


def log_message(message, tag="info"):
    """在输出框中显示消息"""
    output_text.config(state=tk.NORMAL)
    if tag == "error":
        output_text.insert(tk.END, f"{message}\n", ("red",))
        output_text.tag_config("red", foreground="red", font=("Consolas", 12, "bold"))
    else:
        output_text.insert(tk.END, f"{message}\n")
    output_text.see(tk.END)  # 自动滚动到最新消息
    output_text.config(state=tk.DISABLED)


def show_initialization_message():
    """显示初始化完成消息"""
    log_message("首次打开该软件需要初始化！", "error")
    log_message("初始化已完成，请手动重启该软件！", "error")


def show_description():
    """显示使用说明"""
    log_message("\n使用说明:")
    log_message("1. 首先打开该软件，再打开直播伴侣。")
    log_message("2. 点击直播伴侣中开始直播按钮。")
    log_message("3. 软件会显示地址和密钥，将它们复制到OBS中。")
    log_message("4. 在OBS中点击开始直播即可。")


def copy_to_clipboard(text, description):
    """复制内容到剪贴板"""
    if not text:
        log_message(f"{description} 为空，无法复制！", "error")
        return
    if "stream-" == text:
        log_message(f"{description} 为空，无法复制！", "error")
        return
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()
    log_message(f"{description} 已复制到剪贴板！")


# ---------------------------- 网络包捕获 ----------------------------

class StopCaptureException(Exception):
    """自定义异常用于停止捕获"""
    pass


def process_packet(packet):
    """处理捕获到的网络包"""
    global stop_capture, rtmp_url, key

    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        if not hasattr(process_packet, 'rtmp_urls'):
            process_packet.rtmp_urls = set()

        rtmp_match = re.search(r"rtmp://[\w.-]+(/\w+)*", payload)
        if rtmp_match:
            rtmp_url = rtmp_match.group(0)
            if rtmp_url not in process_packet.rtmp_urls:
                process_packet.rtmp_urls.add(rtmp_url)
                log_message(f"地址: {rtmp_url}")

        if 'stream-' in payload:
            key = payload.split('stream-')[1].split(' ')[0]
            log_message(f"密钥: stream-{key}")
            stop_capture = True
            raise StopCaptureException


def capture_rtmp_on_iface(iface):
    """捕获指定网卡上的RTMP流"""
    try:
        sniff(filter='tcp port 1935', iface=iface, prn=process_packet, store=False)
    # except StopCaptureException:
    #     log_message(f"捕获已完成，网卡 {iface} 停止捕获。")
    except Exception as e:
        return []
        # log_message(f"网卡 {iface} 捕获停止: {e}", "error")


def start_capture():
    """开始捕获RTMP流"""
    interfaces = get_all_interfaces()
    if not interfaces:
        log_message("无法获取网卡列表！", "error")
        return

    log_message("正在尝试捕获RTMP地址和密钥，请稍候...")
    for iface in interfaces:
        capture_thread = threading.Thread(target=capture_rtmp_on_iface, args=(iface,))
        capture_thread.daemon = True
        capture_thread.start()


# ---------------------------- 主程序 ----------------------------

# 初始化变量
stop_capture = False
rtmp_url = ""
key = ""

# 创建主窗口
root = tk.Tk()
root.title("推流地址捕获    Author: 浅梦")
root.geometry("650x450")
root.resizable(False, False)
root.configure(bg="#f7f7fa")

# 设置窗口图标
ico_option()

# 创建顶部标签
header_label = tk.Label(root, text="推流地址捕获工具", font=("Arial", 18, "bold"), bg="#f7f7fa", fg="#333333")
header_label.pack(pady=15)

# 创建文本框用于显示捕获结果
output_frame = tk.Frame(root, bg="#f7f7fa")
output_frame.pack(pady=10, padx=10, fill=tk.BOTH, expand=True)

output_text = tk.Text(output_frame, height=15, width=80, state=tk.DISABLED, bg="#ffffff", fg="#333333",
                      font=("Consolas", 10), wrap=tk.WORD)
output_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

# 创建滚动条
scrollbar = ttk.Scrollbar(output_frame, command=output_text.yview)
output_text.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# 创建按钮框架
button_frame = tk.Frame(root, bg="#f7f7fa")
button_frame.pack(pady=15)

# 创建按钮
style = ttk.Style()
style.configure("TButton", font=("Consolas", 10), padding=5)

description_button = ttk.Button(button_frame, text="使用说明", command=show_description)
description_button.grid(row=0, column=0, padx=15, pady=5)

copy_rtmp_button = ttk.Button(button_frame, text="复制地址", command=lambda: copy_to_clipboard(rtmp_url, "RTMP 地址"))
copy_rtmp_button.grid(row=0, column=1, padx=15, pady=5)

copy_key_button = ttk.Button(button_frame, text="复制密钥", command=lambda: copy_to_clipboard(f"stream-{key}", "密钥"))
copy_key_button.grid(row=0, column=2, padx=15, pady=5)

# 检查并安装 WinPcap
if not check_winpcap_installed():
    install_winpcap()
    show_initialization_message()
else:
    log_message("欢迎使用推流地址捕获工具！\n请打开直播伴侣，获取的地址或密钥会自动显示在下方。")
    start_capture()

# 运行主循环
root.mainloop()
