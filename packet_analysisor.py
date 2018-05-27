#!/usr/bin/env Python 3.6.4
# -*- coding: utf-8 -*-
# @Software: PyCharm


import tkinter
from tkinter import font
from tkinter.filedialog import *
from tkinter.scrolledtext import ScrolledText
from tkinter.ttk import Treeview

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

# 暂停捕获线程事件标志
pause_sniff = threading.Event()
# 停止捕获线程事件标志
stop_sniff = threading.Event()
# 所捕获到的包方数量
captured_packet_count = 0
# 保存所有捕获到的数据包
captured_packet = []


# 状态栏类
class StatusBar(Frame):
    def __init__(self, master):
        Frame.__init__(self, master)
        self.label = Label(self, bd=1, relief=SUNKEN, anchor=W)
        self.label.pack(fill=X)

    def set(self, fmt, *args):
        self.label.config(text=fmt % args)
        self.label.update_idletasks()

    def clear(self):
        self.label.config(text="")
        self.label.update_idletasks()


def timestamp2time(timestamp):
    """
    时间戳转为格式化的时间字符串
    :param timestamp:
    :return: 格式化的时间字符串
    """
    time_array = time.localtime(timestamp)
    mytime = time.strftime("%Y-%m-%d %H:%M:%S", time_array)
    return mytime


def on_click_packet_list_tree(event):
    """
    数据包列表单击事件响应函数，在数据包列表单击某数据包时，在协议解析区解析此数据包，
    并在hexdump区显示此数据包的十六进制内容
    :param event: TreeView单击事件
    :return: None
    """
    global captured_packet_count
    global captured_packet
    # event.widget获取Treeview对象，调用selection获取选择对象名称
    selected_item = event.widget.selection()
    # 清空packet_dissect_tree上现有的内容
    packet_dissect_tree.delete(*packet_dissect_tree.get_children())
    # 设置协议解析区的宽度
    packet_dissect_tree.column('Dissect', width=packet_list_frame.winfo_width())
    # 获取点击选择到的数据包
    packet = captured_packet[int(selected_item[0]) - 1]
    # dump=True作用返回是一个字符串，不显示在屏幕上
    lines = (packet.show(dump=True)).split('\n')
    last_tree_entry = None  # 根节点
    Ether_packet = Ether(raw(packet))

    for line in lines:
        if line.startswith('#'):
            line = line.strip('# ')
            # 第一个参数为null代表根节点
            last_tree_entry = packet_dissect_tree.insert('', 'end', text=line)
            # 检查数据包校验包是否正确，包括TCP/UPD/IP包的校验和
        if 'chksum' in line and IP in packet:
            if Ether_packet[IP].chksum == packet[IP].chksum:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[correct]')
            else:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[incorrect]')
        elif 'chksum' in line and UDP in packet:
            if Ether_packet[UDP].chksum == packet[UDP].chksum:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[correct]')
            else:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[incorrect]')
        elif 'chksum' in line and TCP in packet:
            if Ether_packet[TCP].chksum == packet[TCP].chksum:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[correct]')
            else:
                packet_dissect_tree.insert(last_tree_entry, 'end', text=line + '[incorrect]')
        else:
            packet_dissect_tree.insert(last_tree_entry, 'end', text=line)
        col_width = font.Font().measure(line)
        # 根据新插入数据项的长度动态调整协议解析区的宽度
        if packet_dissect_tree.column('Dissect', width=None) < col_width:
            packet_dissect_tree.column('Dissect', width=col_width)

    # 在hexdump区显示此数据包的十六进制内容
    hexdump_scrolledtext['state'] = 'normal'
    hexdump_scrolledtext.delete(1.0, END)
    hexdump_scrolledtext.insert(END, hexdump(packet, dump=True))
    hexdump_scrolledtext['state'] = 'disabled'


def display_packet(packet):
    """
    显示捕获到的数据包的内容
    :param packet: 捕获到的数据包
    :return: None
    """
    global captured_packet_count
    global captured_packet

    # 如果捕获没有被暂停
    if not pause_sniff.is_set():
        # 改变捕获全局记录变量
        captured_packet_count += 1
        captured_packet.append(packet)
        packet_time = timestamp2time(packet.time)
        # 数据包的协议类型
        proto_list = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether']
        proto = ''
        src = ''
        dst = ''
        for proto_name in proto_list:
            if proto_name in packet:
                proto = proto_name
                break
        if proto == 'ARP' or proto == 'Ether':
            src = packet.src
            dst = packet.dst
        elif 'IP' in packet:
            src = packet[IP].src
            dst = packet[IP].dst
        length = len(packet)
        info = packet.summary()
        packet_list_tree.insert("", 'end', captured_packet_count, text=captured_packet_count,
                                values=(captured_packet_count, packet_time, str(src), str(dst), proto, length, info))
        packet_list_tree.update_idletasks()


def save_captured_data_to_file():
    """
    将抓到的数据包保存为pcap格式的文件
    :return: None
    """
    # 打开tk文件另存为对话框
    file_name = asksaveasfilename(defaultextension='*.pcap', filetypes=[('PCAP File', '*.pcap'), ('All types', '*.*')],
                                  title='另存为')
    if file_name != '':
        # 利用scapy中的函数保存pcap文件
        wrpcap(file_name, captured_packet)


def start_capture():
    """
    开始按钮单击响应函数，如果是停止后再次开始捕获，要提示用户保存已经捕获的数据
    :return: None
    """
    # 判断捕获线程是否停止
    global captured_packet_count
    global captured_packet
    # 如果是停止捕获后再开始捕获，需要提示是否保存已经捕获到的文件
    if stop_sniff.is_set():  # 返回stop_sniff线程事件的状态值
        save_captured_data_to_file()
        # 重置捕获记录变量
        captured_packet = []
        captured_packet_count = 0
        # 更新界面
        packet_dissect_tree.delete(*packet_dissect_tree.get_children())
        packet_list_tree.delete(*packet_list_tree.get_children())
        # 恢复线程事件的标志位false
        stop_sniff.clear()
        pause_sniff.clear()
    else:  # 如果前面没有捕获数据
        # 重置捕获记录变量
        captured_packet = []
        captured_packet_count = 0
    # 开启报文捕获线程
    captured_thread = threading.Thread(target=sniff_packet)
    captured_thread.setDaemon(True)
    captured_thread.start()

    # 改变按钮状态
    start_button['state'] = 'disabled'
    pause_button['state'] = 'normal'
    stop_button['state'] = 'normal'
    save_button['state'] = 'disabled'
    open_button['state'] = 'disabled'


def on_stop_sniff(packet):
    """
    :return:返回捕获停止线程标志位
    """
    return stop_sniff.is_set() == True


def sniff_packet():
    """
    开始捕获报文
    :return: None
    """
    sniff(filter=fitler_entry.get(), prn=lambda x: display_packet(x), stop_filter=lambda x: on_stop_sniff(x))


def open_capture():
    """
    读取pcap文件
    :return: None
    """
    filename = askopenfilename(filetypes=[('PCAP Files', '*.pcap')], title="打开文件")
    global captured_packet_count
    global captured_packet
    if filename != '':
        # 如果是停止状态再打开文件，要提示保存当前捕获到的文件
        if captured_packet_count != 0:
            save_captured_data_to_file()
            # 重置捕获全局记录变量
            captured_packet_count = 0
            captured_packet = []
            # 更新界面
            packet_list_tree.delete(*packet_list_tree.get_children())
            packet_dissect_tree.delete(*packet_dissect_tree.get_children())
            stop_sniff.clear()
            pause_sniff.clear()
        else:
            # 打开本地保存的pcap文件，在界面上展示出来
            sniff(prn=lambda x: display_packet(x), offline=filename)


def pause_capture():
    """
    为暂停按钮添加事件响应代码
    :return: None
    """
    if pause_button['text'] == '暂停':
        # 修改捕获线程事件标志为TRUE
        pause_sniff.set()
        pause_button['text'] = '继续'
    elif pause_button['text'] == '继续':
        pause_sniff.clear()
        pause_button['text'] = '暂停'


def stop_capture():
    """
    为停止按钮添加事件响应代码
    :return: None
    """
    # 将停止捕获线程事件标志设为TRUE
    stop_sniff.set()
    # 修改界面按钮的状态
    start_button['state'] = 'normal'
    pause_button['state'] = 'disabled'
    pause_button['text'] = '暂停'
    stop_button['state'] = 'disabled'
    save_button['state'] = 'normal'
    open_button['state'] = 'normal'


# 退出按钮单击响应函数,退出程序前要提示用户保存已经捕获的数据
def quit_program():
    """
    为退出按钮添加事件响应代码
    :return:
    """
    if captured_packet_count != 0:
        save_captured_data_to_file()
    exit(0)


# ---------------------以下代码负责绘制GUI界面---------------------
tk = tkinter.Tk()
tk.title("协议分析器")
# tk.resizable(0, 0)
# 带水平分割条的主窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5, orient=VERTICAL)

# 顶部的按钮及过滤器区
toolbar = Frame(tk)
start_button = Button(toolbar, width=8, text="开始", command=start_capture)
pause_button = Button(toolbar, width=8, text="暂停", command=pause_capture)
stop_button = Button(toolbar, width=8, text="停止", command=stop_capture)
save_button = Button(toolbar, width=8, text="保存数据", command=save_captured_data_to_file)
quit_button = Button(toolbar, width=8, text="退出", command=quit_program)
open_button = Button(toolbar, width=8, text="打开", command=open_capture)
start_button['state'] = 'normal'
pause_button['state'] = 'disabled'
stop_button['state'] = 'disabled'
save_button['state'] = 'disabled'
quit_button['state'] = 'normal'
open_button['state'] = 'normal'
filter_label = Label(toolbar, width=10, text="BPF过滤器：")
fitler_entry = Entry(toolbar)
start_button.pack(side=LEFT, padx=5)
pause_button.pack(side=LEFT, after=start_button, padx=10, pady=10)
stop_button.pack(side=LEFT, after=pause_button, padx=10, pady=10)
save_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
open_button.pack(side=LEFT, after=stop_button, padx=10, pady=10)
quit_button.pack(side=LEFT, after=save_button, padx=10, pady=10)
filter_label.pack(side=LEFT, after=quit_button, padx=0, pady=10)
fitler_entry.pack(side=LEFT, after=filter_label, padx=20, pady=10, fill=X, expand=YES)
toolbar.pack(side=TOP, fill=X)

# 数据包列表区
packet_list_frame = Frame()
packet_list_sub_frame = Frame(packet_list_frame)
packet_list_tree = Treeview(packet_list_sub_frame, selectmode='browse')
packet_list_tree.bind('<<TreeviewSelect>>', on_click_packet_list_tree)
# 数据包列表垂直滚动条
packet_list_vscrollbar = Scrollbar(packet_list_sub_frame, orient="vertical", command=packet_list_tree.yview)
packet_list_vscrollbar.pack(side=RIGHT, fill=Y, expand=YES)
packet_list_tree.configure(yscrollcommand=packet_list_vscrollbar.set)
packet_list_sub_frame.pack(side=TOP, fill=BOTH, expand=YES)
# 数据包列表水平滚动条
packet_list_hscrollbar = Scrollbar(packet_list_frame, orient="horizontal", command=packet_list_tree.xview)
packet_list_hscrollbar.pack(side=BOTTOM, fill=X, expand=YES)
packet_list_tree.configure(xscrollcommand=packet_list_hscrollbar.set)
# 数据包列表区列标题
packet_list_tree["columns"] = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")
packet_list_column_width = [100, 180, 160, 160, 100, 100, 800]
packet_list_tree['show'] = 'headings'
for column_name, column_width in zip(packet_list_tree["columns"], packet_list_column_width):
    packet_list_tree.column(column_name, width=column_width, anchor='w')
    packet_list_tree.heading(column_name, text=column_name)
packet_list_tree.pack(side=LEFT, fill=X, expand=YES)
packet_list_frame.pack(side=TOP, fill=X, padx=5, pady=5, expand=YES, anchor='n')
# 将数据包列表区加入到主窗体
main_panedwindow.add(packet_list_frame)

# 协议解析区
packet_dissect_frame = Frame()
packet_dissect_sub_frame = Frame(packet_dissect_frame)
packet_dissect_tree = Treeview(packet_dissect_sub_frame, selectmode='browse')
packet_dissect_tree["columns"] = ("Dissect",)
packet_dissect_tree.column('Dissect', anchor='w')
packet_dissect_tree.heading('#0', text='Packet Dissection', anchor='w')
packet_dissect_tree.pack(side=LEFT, fill=BOTH, expand=YES)
# 协议解析区垂直滚动条
packet_dissect_vscrollbar = Scrollbar(packet_dissect_sub_frame, orient="vertical", command=packet_dissect_tree.yview)
packet_dissect_vscrollbar.pack(side=RIGHT, fill=Y)
packet_dissect_tree.configure(yscrollcommand=packet_dissect_vscrollbar.set)
packet_dissect_sub_frame.pack(side=TOP, fill=X, expand=YES)
# 协议解析区水平滚动条
packet_dissect_hscrollbar = Scrollbar(packet_dissect_frame, orient="horizontal", command=packet_dissect_tree.xview)
packet_dissect_hscrollbar.pack(side=BOTTOM, fill=X)
packet_dissect_tree.configure(xscrollcommand=packet_dissect_hscrollbar.set)
packet_dissect_frame.pack(side=LEFT, fill=X, padx=5, pady=5, expand=YES)
# 将协议解析区加入到主窗体
main_panedwindow.add(packet_dissect_frame)

# hexdump区
hexdump_scrolledtext = ScrolledText(height=10)
hexdump_scrolledtext['state'] = 'disabled'
# 将hexdump区区加入到主窗体
main_panedwindow.add(hexdump_scrolledtext)
main_panedwindow.pack(fill=BOTH, expand=1)

# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
tk.mainloop()
