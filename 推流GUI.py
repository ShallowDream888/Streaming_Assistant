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


# 设置窗口图标
def ico_option():
    try:
        # 动态加载图标
        icon_path = resource_path("tuiliu.ico")
        try:
            root.iconbitmap(icon_path)
        except Exception as e:
            print(f"无法加载图标: {e}")
    except:
        pass

def show_initialization_message():
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, "首次打开该软件需要初始化！\n\n", ("red",))
    output_text.insert(tk.END, "初始化已完成，请手动重启该软件！\n", ("red",))
    output_text.tag_config("red", foreground="red", font=("Consolas", 12, "bold"))
    output_text.config(state=tk.DISABLED)


def resource_path(relative_path):
    """获取资源文件路径"""
    # 如果是 PyInstaller 打包的程序，资源会在 _MEIPASS 中
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    # 否则使用脚本运行目录的资源路径
    return os.path.join(os.path.abspath("."), relative_path)


# 检查 WinPcap 是否已安装
def check_winpcap_installed():
    # 常见的 WinPcap DLL 文件路径
    possible_paths = [
        "C:\\Windows\\System32\\wpcap.dll",
        "C:\\Windows\\SysWOW64\\wpcap.dll"
    ]

    for path in possible_paths:
        if os.path.exists(path):
            return True
    return False


# 从文件中读取 Base64 编码内容
def get_base64_from_file(base64_file):
    with open(base64_file, "rb") as f:
        return f.read()


# 保存嵌入的安装程序到临时文件
def save_winpcap_installer():
    base64_data = get_base64_from_file(resource_path("winpcap_base64.txt"))
    temp_dir = tempfile.gettempdir()
    installer_path = os.path.join(temp_dir, "winpcap-4.13.exe")
    with open(installer_path, "wb") as installer_file:
        installer_file.write(base64.b64decode(base64_data))
    return installer_path


# 安装 WinPcap
def install_winpcap():
    winpcap_installer = save_winpcap_installer()
    try:
        # 使用静默模式安装 WinPcap
        subprocess.run([winpcap_installer, "/S"], check=True)
    except subprocess.CalledProcessError as e:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"WinPcap 安装失败: {e}\n")
        output_text.config(state=tk.DISABLED)
    finally:
        # 安装完成后删除临时文件
        if os.path.exists(winpcap_installer):
            os.remove(winpcap_installer)


# 获取所有网卡名称
def get_all_interfaces():
    try:
        return [iface.name for iface in conf.ifaces.values()]
    except Exception as e:
        return []


class StopCaptureException(Exception):
    pass


stop_capture = False
output_text = None  # 用于显示结果的文本框
rtmp_url = ""  # 用于存储捕获的rtmp地址
key = ""  # 用于存储捕获的密钥


# 显示使用说明
def show_description():
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, "\n使用说明:\n")
    output_text.insert(tk.END, "1. 首先打开该软件，再打开直播伴侣。\n")
    output_text.insert(tk.END, "2. 点击直播伴侣中开始直播按钮。\n")
    output_text.insert(tk.END, "3. 软件会显示地址和密钥，将它们复制到OBS中。\n")
    output_text.insert(tk.END, "4. 在obs中点击开始直播即可。\n")
    output_text.config(state=tk.DISABLED)


# 复制内容到剪贴板
def copy_to_clipboard(text, description):
    if not text:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"{description} 为空，无法复制！\n")
        output_text.config(state=tk.DISABLED)
        return
    root.clipboard_clear()
    root.clipboard_append(text)
    root.update()  # 更新剪贴板内容
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, f"{description} 已复制到剪贴板！\n")
    output_text.config(state=tk.DISABLED)


# 处理捕获到的网络包
def process_packet(packet):
    global stop_capture, rtmp_url, key
    if packet.haslayer(Raw):
        payload = packet[Raw].load.decode('utf-8', errors='ignore')

        # 使用集合存储已捕获的 RTMP 地址，避免重复
        if not hasattr(process_packet, 'rtmp_urls'):
            process_packet.rtmp_urls = set()

        rtmp_match = re.search(r"rtmp://[\w\.-]+(/[\w\.-]*)*", payload)
        if rtmp_match:
            rtmp_url = rtmp_match.group(0)
            if rtmp_url not in process_packet.rtmp_urls:
                process_packet.rtmp_urls.add(rtmp_url)
                output_text.config(state=tk.NORMAL)
                output_text.insert(tk.END, f"地址: {rtmp_url}\n")
                output_text.config(state=tk.DISABLED)

        if 'stream-' in payload:
            key = payload.split('stream-')[1].split(' ')[0]
            output_text.config(state=tk.NORMAL)
            output_text.insert(tk.END, f"密钥: stream-{key}\n")
            output_text.config(state=tk.DISABLED)
            stop_capture = True
            raise StopCaptureException


# 捕获指定网卡上的RTMP流
def capture_rtmp_on_iface(iface):
    try:
        sniff(filter='tcp port 1935', iface=iface, prn=process_packet, store=False)
    except StopCaptureException:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"捕获已完成，网卡 {iface} 停止捕获。\n")
        output_text.config(state=tk.DISABLED)
    except Exception as e:
        return []
        # output_text.config(state=tk.NORMAL)
        # output_text.insert(tk.END, f"网卡 {iface} 捕获停止: {e}\n")
        # output_text.config(state=tk.DISABLED)


# 开始捕获
def start_capture():
    interfaces = get_all_interfaces()
    if not interfaces:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, "无法获取网卡列表！\n")
        output_text.config(state=tk.DISABLED)
        return

    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, "正在尝试捕获RTMP地址和密钥，请稍候...\n")
    output_text.config(state=tk.DISABLED)

    for iface in interfaces:
        capture_thread = threading.Thread(target=capture_rtmp_on_iface, args=(iface,))
        capture_thread.daemon = True
        capture_thread.start()


# 创建主窗口
root = tk.Tk()
root.title("推流地址捕获    Author: 浅梦")
root.geometry("650x450")
root.resizable(False, False)

# 设置主窗口背景颜色
root.configure(bg="#f7f7fa")

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
    ico_option()
    install_winpcap()
    # 在程序启动时显示提示信息
    show_initialization_message()
else:
    ico_option()
    # 在程序启动时显示提示信息
    output_text.config(state=tk.NORMAL)
    output_text.insert(tk.END, "欢迎使用推流地址捕获工具！\n请打开直播伴侣，获取的地址或密钥会自动显示在下方。\n")
    output_text.config(state=tk.DISABLED)
    # 自动开始捕获
    start_capture()

# 运行主循环
root.mainloop()
