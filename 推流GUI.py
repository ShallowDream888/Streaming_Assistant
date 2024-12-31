import threading
import tkinter as tk
from tkinter import ttk
from scapy.all import sniff, Raw, conf
import re

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
    output_text.insert(tk.END, "4. 关闭直播伴侣，再点击OBS中的开始直播按钮。如需弹幕功能，可再次打开直播伴侣。\n")
    output_text.config(state=tk.DISABLED)

# 复制内容到剪贴板
def copy_to_clipboard(text, description):
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
        rtmp_match = re.search(r"rtmp://[\w\.-]+(/[\w\.-]*)*", payload)
        if rtmp_match:
            rtmp_url = rtmp_match.group(0)
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
    except Exception as e:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, f"网卡 {iface} 捕获停止: {e}\n")
        output_text.config(state=tk.DISABLED)

# 开始捕获
def start_capture():
    interfaces = get_all_interfaces()
    if not interfaces:
        output_text.config(state=tk.NORMAL)
        output_text.insert(tk.END, "无法获取网卡列表！\n")
        output_text.config(state=tk.DISABLED)
        return

    for iface in interfaces:
        capture_thread = threading.Thread(target=capture_rtmp_on_iface, args=(iface,))
        capture_thread.daemon = True
        capture_thread.start()

# 创建主窗口
root = tk.Tk()
root.title("推流地址捕获    Author: 浅梦")
root.geometry("600x400")
root.resizable(False, False)

# 设置窗口图标
try:
    root.iconbitmap('icon.ico')  # 确保当前目录下有icon.ico文件
except:
    pass

# 设置主窗口背景颜色
root.configure(bg="#f0f0f5")

# 创建顶部标签
header_label = tk.Label(root, text="推流地址捕获工具", font=("Arial", 16, "bold"), bg="#f0f0f5", fg="#333333")
header_label.pack(pady=10)

# 创建文本框用于显示捕获结果
output_text = tk.Text(root, height=12, width=70, state=tk.DISABLED, bg="#ffffff", fg="#333333", font=("Consolas", 10))
output_text.pack(pady=10)

# 创建滚动条
scrollbar = ttk.Scrollbar(root, command=output_text.yview)
output_text.configure(yscrollcommand=scrollbar.set)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

# 创建按钮框架
button_frame = tk.Frame(root, bg="#f0f0f5")
button_frame.pack(pady=10)

# 创建按钮
style = ttk.Style()
style.configure("TButton", font=("Arial", 10), padding=5)

description_button = ttk.Button(button_frame, text="使用说明", command=show_description)
description_button.grid(row=0, column=0, padx=10)

copy_rtmp_button = ttk.Button(button_frame, text="复制地址", command=lambda: copy_to_clipboard(rtmp_url, "RTMP 地址"))
copy_rtmp_button.grid(row=0, column=1, padx=10)

copy_key_button = ttk.Button(button_frame, text="复制密钥", command=lambda: copy_to_clipboard(f"stream-{key}", "密钥"))
copy_key_button.grid(row=0, column=2, padx=10)

# 在程序启动时显示提示信息
output_text.config(state=tk.NORMAL)
output_text.insert(tk.END, "请打开直播伴侣，获取的地址或密钥会自动显示在下方\n")
output_text.config(state=tk.DISABLED)

# 自动开始捕获
start_capture()

# 运行主循环
root.mainloop()
