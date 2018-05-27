#!/usr/bin/env Python 3.6.4
# -*- coding: utf-8 -*-
# @Software: PyCharm


import datetime
import tkinter
from tkinter import *
from tkinter.constants import *
from tkinter.ttk import Treeview, Style

from scapy.all import *
from scapy.layers.inet import *
from scapy.layers.l2 import *

tk = tkinter.Tk()
tk.title("协议编辑器")
# tk.geometry("1000x700")
# 使窗体最大化
tk.state("zoomed")
# 左右分隔窗体
main_panedwindow = PanedWindow(tk, sashrelief=RAISED, sashwidth=5)
# 协议编辑区窗体
protocol_editor_panedwindow = PanedWindow(orient=VERTICAL, sashrelief=RAISED, sashwidth=5)
# 协议导航树
protocols_tree = Treeview()
# 当前网卡的默认网关
default_gateway = [a for a in os.popen('route print').readlines() if ' 0.0.0.0 ' in a][0].split()[-3]
# 用来终止数据包发送线程的线程事件
stop_sending = threading.Event()


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


# 状态栏
status_bar = StatusBar(tk)
status_bar.pack(side=BOTTOM, fill=X)
status_bar.set("%s", '开始')


def create_protocols_tree():
    """
    创建协议导航树
    :return: 协议导航树
    """
    protocols_tree.heading('#0', text='选择网络协议', anchor='w')
    # 参数:parent, index, iid=None, **kw (父节点，插入的位置，id，显示出的文本)
    # 应用层
    applicatoin_layer_tree_entry = protocols_tree.insert("", 0, "应用层", text="应用层")  # ""表示父节点是根
    http_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "HTTP包", text="HTTP包")
    #  dns_packet_tree_entry = protocols_tree.insert(applicatoin_layer_tree_entry, 1, "DNS包", text="DNS包")
    # 传输层
    transfer_layer_tree_entry = protocols_tree.insert("", 1, "传输层", text="传输层")
    tcp_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 0, "TCP包", text="TCP包")
    upd_packet_tree_entry = protocols_tree.insert(transfer_layer_tree_entry, 1, "UDP包", text="UDP包")
    # 网络层
    ip_layer_tree_entry = protocols_tree.insert("", 2, "网络层", text="网络层")
    ip_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 0, "IP包", text="IP包")
    icmp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 1, "ICMP包", text="ICMP包")
    arp_packet_tree_entry = protocols_tree.insert(ip_layer_tree_entry, 2, "ARP包", text="ARP包")
    # 网络接入层
    ether_layer_tree_entry = protocols_tree.insert("", 3, "网络接入层", text="网络接入层")
    mac_frame_tree_entry = protocols_tree.insert(ether_layer_tree_entry, 1, "MAC帧", text="MAC帧")
    protocols_tree.bind('<<TreeviewSelect>>', on_click_protocols_tree)
    style = Style(tk)
    # get disabled entry colors
    disabled_bg = style.lookup("TEntry", "fieldbackground", ("disabled",))
    style.map("Treeview",
              fieldbackground=[("disabled", disabled_bg)],
              foreground=[("disabled", "gray")],
              background=[("disabled", disabled_bg)])
    protocols_tree.pack()
    return protocols_tree


def toggle_protocols_tree_state():
    """
    使protocols_tree失效
    :rtype: None
    """
    if "disabled" in protocols_tree.state():
        protocols_tree.state(("!disabled",))
        # re-enable item opening on click
        protocols_tree.unbind('<Button-1>')
    else:
        protocols_tree.state(("disabled",))
        # disable item opening on click
        protocols_tree.bind('<Button-1>', lambda event: 'break')


def on_click_protocols_tree(event):
    """
    协议导航树单击事件响应函数
    :param event: TreeView单击事件
    :return: None
    """
    selected_item = event.widget.selection()  # event.widget获取Treeview对象，调用selection获取选择对象名称
    # 清空protocol_editor_panedwindow上现有的控件
    for widget in protocol_editor_panedwindow.winfo_children():
        widget.destroy()
    # 设置状态栏
    status_bar.set("%s", selected_item[0])

    if selected_item[0] == "MAC帧":
        create_mac_sender()
    elif selected_item[0] == "ARP包":
        create_arp_sender()
    elif selected_item[0] == "IP包":
        create_ip_sender()
    elif selected_item[0] == "ICMP包":
        create_icmp_sender()
    elif selected_item[0] == "TCP包":
        create_tcp_sender()
    elif selected_item[0] == "UDP包":
        create_udp_sender()
    elif selected_item[0] == "HTTP包":
        create_http_sender()


def create_protocol_editor(root, field_names):
    """
    创建协议字段编辑区
    :param root: 协议编辑区
    :param field_names: 协议字段名列表
    :return: 协议字段编辑框列表
    """
    entries = []
    for field in field_names:
        row = Frame(root)
        label = Label(row, width=15, text=field, anchor='e')
        entry = Entry(row, font=('Courier', '12', 'bold'), state='normal')  # 设置编辑框为等宽字体
        row.pack(side=TOP, fill=X, padx=5, pady=5)
        label.pack(side=LEFT)
        entry.pack(side=RIGHT, expand=YES, fill=X)
        entries.append(entry)
    return entries


def clear_protocol_editor(entries):
    """
    清空协议编辑器的当前值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    for entry in entries:
        # 如果有只读Entry，也要清空它的当前值
        state = entry['state']
        entry['state'] = 'normal'
        entry.delete(0, END)
        entry['state'] = state


def create_bottom_buttons(root):
    """
    创建发送按钮和重置按钮
    :param root: 编辑编辑区
    :return: 发送按钮和清空按钮
    """
    bottom_buttons = Frame(root)
    send_packet_button = Button(bottom_buttons, width=20, text="发送")
    default_packet_button = Button(bottom_buttons, width=20, text="默认值")
    reset_button = Button(bottom_buttons, width=20, text="重置")
    bottom_buttons.pack(side=BOTTOM, fill=X, padx=5, pady=5)
    send_packet_button.grid(row=0, column=0, padx=5, pady=5)
    default_packet_button.grid(row=0, column=1, padx=2, pady=5)
    reset_button.grid(row=0, column=2, padx=5, pady=5)
    bottom_buttons.columnconfigure(0, weight=1)
    bottom_buttons.columnconfigure(1, weight=1)
    bottom_buttons.columnconfigure(2, weight=1)
    return send_packet_button, reset_button, default_packet_button


def create_mac_sender():
    """
    创建MAC帧编辑器
    :return: None
    """
    # MAC帧编辑区
    mac_fields = '源MAC地址：', '目标MAC地址：', '协议类型：'
    entries = create_protocol_editor(protocol_editor_panedwindow, mac_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送MAC帧
    tk.bind('<Return>', (lambda event: send_mac_frame(entries, send_packet_button)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送MAC帧
    send_packet_button.bind('<Button-1>', (
        lambda event: send_mac_frame(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入MAC帧字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_mac_frame(entries)))


def create_default_mac_frame(entries):
    """
    在协议字段编辑框中填入默认MAC帧的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_mac_frame = Ether()
    entries[0].insert(0, default_mac_frame.src)
    entries[1].insert(0, default_mac_frame.dst)
    entries[2].insert(0, hex(default_mac_frame.type))


def send_mac_frame(entries, send_packet_button):
    """
    发送MAC帧
    :param send_packet_button: MAC帧发送按钮
    :param entries:协议字段编辑框列表
    :return: None
    """
    if send_packet_button['text'] == '发送':
        mac_src = entries[0].get()
        mac_dst = entries[1].get()
        mac_type = int(entries[2].get(), 16)
        packet_to_send = Ether(src=mac_src, dst=mac_dst, type=mac_type)
        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))  # 参数为元组
        t.setDaemon(True)  # 设为后台线程
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def create_arp_sender():
    """
    创建ARP包编辑器
    :return: None
    """
    # ARP包编辑区
    mac_fields = '硬件类型：', '协议类型：', '硬件地址长度：', '协议地址长度：', '操作码：', '源硬件地址：', \
                 '源逻辑地址：', '目标硬件地址：', '目标逻辑地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, mac_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送ARP包
    tk.bind('<Return>', (lambda event: send_arp_packet(entries, send_packet_button)))  # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送ARP包
    send_packet_button.bind('<Button-1>',
                            (lambda event: send_arp_packet(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入ARP包字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_arp_packet(entries)))


def create_default_arp_packet(entries):
    """
    在协议字段编辑框中填入默认ARP包的字段值
    :param entries: 协议字段编辑框列表
    :return: None
    """
    clear_protocol_editor(entries)
    default_arp_packet = ARP()
    entries[0].insert(0, default_arp_packet.hwtype)
    entries[1].insert(0, hex(default_arp_packet.ptype))
    entries[2].insert(0, default_arp_packet.hwlen)
    entries[3].insert(0, default_arp_packet.plen)
    entries[4].insert(0, default_arp_packet.op)
    entries[5].insert(0, default_arp_packet.hwsrc)
    entries[6].insert(0, default_arp_packet.psrc)
    entries[7].insert(0, default_arp_packet.hwdst)
    # 目标IP地址设成本地默认网关
    entries[8].insert(0, default_gateway)


def send_arp_packet(entries, send_packet_button):
    """
    发送ARP包
    :param send_packet_button: ARP包发送按钮
    :param entries:协议字段编辑框列表
    :return: None
    """
    if send_packet_button['text'] == '发送':
        arp_hwtype = int(entries[0].get())  # 硬件地址类型，1表示以太网
        arp_ptype = int(entries[1].get(), 16)  # 要映射的协议类型，0x0800即表示IP地址
        arp_hwlen = int(entries[2].get())  # 硬件地址长度
        arp_plen = int(entries[3].get())  # 协议地址长度，对于以太网上IP地址的ARP请求或应答来说，它们的值分别为6和4
        arp_op = int(entries[4].get())  # 操作类型，1表示ARP请求，2表示ARP应答
        arp_hwsrc = entries[5].get()  # 发送方设备的硬件地址
        arp_psrc = entries[6].get()  # 发送方设备的IP地址
        arp_hwdst = entries[7].get()  # 接收方设备的硬件地址
        arp_pdst = entries[8].get()  # 接收方设备的IP地址
        packet_to_send = ARP(hwtype=arp_hwtype, ptype=arp_ptype, hwlen=arp_hwlen, plen=arp_plen,
                             op=arp_op, hwsrc=arp_hwsrc, psrc=arp_psrc, hwdst=arp_hwdst, pdst=arp_pdst)

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def create_ip_sender():
    """
    创建IP包编辑器
    :return:
    """
    # IP包编辑区
    ip_fields = '版本(4bit)', '首部长度(4bit)', '服务类型(8bit)', '总长度(16bit)', '标识(16bit)', '标志(3bit)', '偏移量(13bit)', \
                '生存时间(8bit)', '协议(8bit)', '首部校验和(16bit)', '源地址(32bit)', '目的地址(32bit)',
    entries = create_protocol_editor(protocol_editor_panedwindow, ip_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送iP包
    tk.bind('<Return>', (lambda event: send_ip_packet(entries, send_packet_button)))
    # 为“发送”按钮的单击事件编写事件响应代码，发送ip包,
    send_packet_button.bind('<Button-1>', (lambda event: send_ip_packet(entries, send_packet_button)))
    # 为“清空按钮”单击事件编写事件响应代码，发送ip包
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为“默认值”按钮的单击事件编写事件响应代码，在协议字段编辑框中填入ip包默认字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_ip_packet(entries)))


def create_default_ip_packet(entries):
    """
    在协议字段编辑框中填入默认ip包的字段值
    :param entries:协议字段编辑框列表
    :return:None
    """
    clear_protocol_editor(entries)
    default_ip_packet = IP()
    entries[0].insert(0, int(default_ip_packet.version))  # 版本
    entries[1].insert(0, 5)  # 首部长度
    entries[2].insert(0, int(default_ip_packet.tos))  # 服务类型
    entries[3].insert(0, 20)  # 总长度
    entries[4].insert(0, int(default_ip_packet.id))  # 标识，用于数据包的重组
    entries[5].insert(0, int(default_ip_packet.flags))  # 标志，分片标志
    entries[6].insert(0, int(default_ip_packet.frag))  # 片偏移
    entries[7].insert(0, int(default_ip_packet.ttl))  # 生存时间
    entries[8].insert(0, int(default_ip_packet.proto))  # 协议
    entries[9].insert(0, "单击发送按钮自动计算")  # 首部校验和
    entries[10].insert(0, default_ip_packet.src)  # 将源ip地址设为本地ip
    entries[11].insert(0, default_gateway)  # 将目的ip设为默认网关


def send_ip_packet(entries, send_packet_button):
    """
    发送ip包
    :param entries:协议字段编辑框列表
    :param send_packet_button:ip包发送按钮
    :return:None
    """
    if send_packet_button['text'] == '发送':
        ip_version = int(entries[0].get())  # 版本
        ip_ihl = int(entries[1].get())  # 标识
        ip_tos = int(entries[2].get())  # 标志
        ip_len = int(entries[3].get())  # 片偏移
        ip_id = int(entries[4].get())  # 生存时间
        ip_flags = int(entries[5].get())  # 协议
        ip_frag = int(entries[6].get())
        ip_ttl = int(entries[7].get())
        ip_proto = int(entries[8].get())
        # ip_chksum = int(entries[9].get())
        ip_src = entries[10].get()  # 源IP地址
        ip_dst = entries[11].get()  # 目的IP地址
        pack_to_send = IP(version=ip_version, ihl=ip_ihl, tos=ip_tos, len=ip_len, id=ip_id, flags=ip_flags,
                          frag=ip_frag, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst,)
        pack_to_send = IP(raw(pack_to_send))
        entries[9].delete(0, END)  # 删除索引值为0的函数
        entries[9].insert(0, hex(pack_to_send.chksum))
        pack_to_send.show()

        # 开启一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=pack_to_send)
        t.setDaemon(True)
        t.start()
        # 使协议导函数不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 回复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def create_icmp_sender():
    """
    ICMP数据包编辑函数
    :return: NULL
    """
    icmp_fields = '类型：', 'icmp校验和：', '协议版本：', '标识：', \
                  '标志：', '片偏移：', '生存时间：', 'ip校验和：', '源ip：', '目的ip：'
    entries = create_protocol_editor(protocol_editor_panedwindow, icmp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为回车键的Press事件编写事件响应代码，发送ICMP报文
    tk.bind('<Return>', (lambda event: send_icmp_packet(entries, send_packet_button)))
    # 为发送按钮的单击响应事件编写响应代码，发送ICMP报文
    send_packet_button.bind('<Button-1>', (lambda event: send_icmp_packet(entries, send_packet_button)))
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入ARP报文字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_icmp_packet(entries)))


def send_icmp_packet(entries, send_packet_button):
    """
    为发送按钮的单击事件或回车键的Press事件编写响应代码
    :param entries:协议字段编辑框列表
    :param send_packet_button:
    :return:ICMP报文发送按钮
    """
    if send_packet_button['text'] == '发送':
        icmp_type = int(entries[0].get())
        ip_version = int(entries[2].get())
        ip_id = int(entries[3].get())
        ip_flags = int(entries[4].get())
        ip_frag = int(entries[5].get())
        ip_ttl = int(entries[6].get())
        ip_src = entries[8].get()  # 源IP地址
        ip_dst = entries[9].get()  # 目的IP地址
        # 构造要发送的icmp报文
        packet_to_send = IP() / ICMP()

        packet_to_send.type = icmp_type
        packet_to_send.version = ip_version
        packet_to_send.id = ip_id
        packet_to_send.flags = ip_flags
        packet_to_send.frag = ip_frag
        packet_to_send.ttl = ip_ttl
        packet_to_send.src = ip_src
        packet_to_send.dst = ip_dst

        # 自动计算ip首部校验和
        packet_to_send = IP(raw(packet_to_send))
        # 获取icmp对象，计算icmp校验和
        packet_icmp = (raw(packet_to_send))[20:]
        packet_icmp = ICMP(packet_icmp)

        entries[1].delete(0, END)
        entries[1].insert(0, hex(packet_icmp.chksum))
        entries[7].delete(0, END)
        entries[7].insert(0, hex(packet_to_send.chksum))

        packet_to_send.show()

        # 开启线程，发送数据包
        t = threading.Thread(target=send_packet, args=packet_to_send)
        t.setDaemon(True)
        t.start()
        # 使协议导函数不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 回复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def create_default_icmp_packet(entries):
    """
    创建默认的icmp包
    :param entries:
    :return: None
    """
    clear_protocol_editor(entries)
    default_icmp_packet = IP() / ICMP()
    entries[0].insert(0, int(default_icmp_packet.type))  # 协议类型
    #  entries[1].insert(0, str(default_icmp_packet[ICMP].chksum))  # icmp校验和
    entries[1].insert(0, '单击发送自动计算')  # icmp校验和
    entries[2].insert(0, int(default_icmp_packet.version))  # 协议版本
    entries[3].insert(0, int(default_icmp_packet.id))  # 分片标识
    entries[4].insert(0, int(default_icmp_packet.flags))  # 分片标志位
    entries[5].insert(0, int(default_icmp_packet.frag))  # 片偏移
    entries[6].insert(0, int(default_icmp_packet.ttl))  # 生存时间
    entries[7].insert(0, '单击发送自动计算')  # ip校验和
    entries[8].insert(0, default_icmp_packet.src)  # 源ip地址
    entries[9].insert(0, default_gateway)  # 目的地址


def create_tcp_sender():
    """
    TCP报文编辑函数
    :return: None
    """
    tcp_fields = '源端口(16bit)：', '目的端口(16bit)：', '序列号(32bit)：', '确认号(32bit)：', \
                 '数据偏移(4bit)：', '窗口(16bit)：', 'TCP校验和(16bit)：', '紧急指针(16bit)：', '数据负载：', \
                 '版本(4bit)', '服务类型(8bit)', '标识(16bit)', '标志(3bit)', '偏移量(13bit)', 'TTL(8bit)', \
                 '协议(8bit)', '首部校验和(16bit)', '源地址(32bit)', '目的地址(32bit)'
    entries = create_protocol_editor(protocol_editor_panedwindow, tcp_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送TCP报文
    tk.bind('<Return>', (lambda event: send_tcp_packet(entries, send_packet_button)))
    # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送TCP报文
    send_packet_button.bind('<Button-1>',
                            (lambda event: send_tcp_packet(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入TCP报文字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_tcp_packet(entries)))


def create_default_tcp_packet(entries):
    """
    构造默认的tcp数据包
    :param entries:协议字段列表
    :return:
    """
    clear_protocol_editor(entries)
    default_tcp_packet = IP() / TCP()
    entries[0].insert(0, int(default_tcp_packet.sport))  # 源端口
    entries[1].insert(0, int(default_tcp_packet.dport))  # 目的端口
    entries[2].insert(0, int(default_tcp_packet.seq))  # 序列号
    entries[3].insert(0, int(default_tcp_packet.ack))  # 确认号
    entries[4].insert(0, '5')  # 数据偏移
    entries[5].insert(0, int(default_tcp_packet.window))  # 窗口大小
    entries[6].insert(0, '单击发送自动计算')  # tcp校验和
    entries[7].insert(0, int(default_tcp_packet.urgptr))  # 紧急指针
    entries[8].insert(0, '')  # 数据负载
    entries[9].insert(0, int(default_tcp_packet.version))  # 版本
    entries[10].insert(0, int(default_tcp_packet.tos))  # 服务类型
    entries[11].insert(0, int(default_tcp_packet.id))  # 标识
    entries[12].insert(0, int(default_tcp_packet.flags))  # 标志
    entries[13].insert(0, int(default_tcp_packet.frag))  # 偏移量
    entries[14].insert(0, int(default_tcp_packet.ttl))  # 生存时间
    entries[15].insert(0, int(default_tcp_packet.proto))  # 协议
    entries[16].insert(0, '单击发送自动计算')  # 首部校验和
    entries[17].insert(0, default_tcp_packet.src)  # 源IP地址
    entries[18].insert(0, default_gateway)  # 目的IP地址


def send_tcp_packet(entries, send_packet_button):
    """
    发送tcp报文函数
    :param entries: tcp协议字段
    :param send_packet_button: 报文发送按钮
    :return:
    """
    if send_packet_button['text'] == '发送':
        tcp_sport = int(entries[0].get())  # 源端口
        tcp_dport = int(entries[1].get())  # 目的端口
        tcp_seq = int(entries[2].get())  # 序列号
        tcp_ack = int(entries[3].get())  # 确认号
        tcp_dataofs = int(entries[4].get())  # 数据偏移
        tcp_window = int(entries[5].get())  # 窗口大小
        #  tcp_chksum = int(entries[6].get())  # tcp校验和
        tcp_urgptr = int(entries[7].get())  # 紧急指针
        tcp_payload = entries[8].get()  # 数据负载

        ip_version = int(entries[9].get())  # 版本
        ip_tos = int(entries[10].get())  # 服务类型
        ip_id = int(entries[11].get())  # 标识
        ip_flags = int(entries[12].get())  # 标志
        ip_frag = int(entries[13].get())  # 偏移量
        ip_ttl = int(entries[14].get())  # 生存时间
        ip_proto = int(entries[15].get())  # 协议
        #  ip_chksum = int(entries[16].get())  # ip校验和
        ip_src = entries[17].get()  # 源IP地址
        ip_dst = entries[18].get()  # 目的IP地址

        tcp = TCP(sport=tcp_sport, dport=tcp_dport, seq=tcp_seq, ack=tcp_ack,
                  dataofs=tcp_dataofs, flags='S', window=tcp_window, urgptr=tcp_urgptr)

        ip = IP(version=ip_version, tos=ip_tos, id=ip_id, flags=ip_flags,
                frag=ip_frag, ttl=ip_ttl, proto=ip_proto, src=ip_src, dst=ip_dst)

        # 获得待发送数据包的二进制，并构建发送数据报
        packet_to_send = ip / tcp / tcp_payload
        packet_to_send = IP(raw(packet_to_send))
        # 去除ip数据报ip首部，构建tcp数据包对象，求校验和
        tcp_raw = (raw(ip / tcp))[20:]
        packet_tcp = TCP(tcp_raw)

        # 填写tcp校验和
        entries[6].delete(0, END)
        entries[6].insert(0, hex(packet_tcp.chksum))
        # 填写IP校验和
        entries[16].delete(0, END)
        entries[16].insert(0, hex(packet_to_send.chksum))

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def create_udp_sender():
    """
    UDP包编辑函数
    :return:None
    """
    UDP_fields = '源端口：', '目的端口：', 'UDP长度：', 'UDP校验和：', '数据负载：', \
                 '版本：', 'ip首部长度：', '服务类型：', '总长度：', \
                 '标识：', '标志：', '片偏移：', '生存时间：', '协议：', \
                 'ip首部校验和：', '源IP地址：', '目的ip地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, UDP_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送UDP报文
    tk.bind('<Return>', (lambda event: send_udp_packet(entries, send_packet_button)))
    # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送UDP报文
    send_packet_button.bind('<Button-1>',
                            (lambda event: send_udp_packet(entries, send_packet_button)))  # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入UDP报文字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_udp_packet(entries)))


def create_default_udp_packet(entries):
    """
    udp协议默认字段编辑函数
    :param entries: udp协议字段
    :return:None
    """
    default_udp_packet = IP() / UDP()
    entries[0].insert(0, int(default_udp_packet.sport))
    entries[1].insert(0, int(default_udp_packet.dport))
    entries[2].insert(0, '单击发送自动计算')
    entries[3].insert(0, '单击发送自动计算')
    entries[4].insert(0, '0000')

    entries[5].insert(0, int(default_udp_packet.version))
    entries[6].insert(0, '单击发送自动计算')
    entries[7].insert(0, int(default_udp_packet.tos))
    entries[8].insert(0, '单击发送自动计算')
    entries[9].insert(0, int(default_udp_packet.id))
    entries[10].insert(0, int(default_udp_packet.flags))
    entries[11].insert(0, int(default_udp_packet.frag))
    entries[12].insert(0, int(default_udp_packet.ttl))
    entries[13].insert(0, int(default_udp_packet.proto))
    entries[14].insert(0, '单击发送自动计算')
    entries[15].insert(0, default_udp_packet.src)  # 源IP地址
    entries[16].insert(0, default_gateway)  # 目的IP地址


def send_udp_packet(entries, send_packet_button):
    """
    udp发送按钮事件响应代码
    :param entries: udp协议字段
    :param send_packet_button: 发送报文按钮
    :return: None
    """
    if send_packet_button['text'] == '发送':
        udp_sport = int(entries[0].get())
        udp_dport = int(entries[1].get())
        #  udp_len = int(entries[2].get())
        #  udp_chksum = int(entries[3].get())
        udp_payload = entries[4].get()
        ip_version = int(entries[5].get())
        #  ip_ihl = int(entries[6].get())
        ip_tos = int(entries[7].get())
        #  ip_len = int(entries[8].get())
        ip_id = int(entries[9].get())
        ip_flags = int(entries[10].get())
        ip_frag = int(entries[11].get())
        ip_ttl = int(entries[12].get())
        ip_proto = int(entries[13].get())
        #  ip_chksum = int(entries[14].get())
        ip_src = entries[15].get()
        ip_dst = entries[16].get()

        packet_to_send = IP() / UDP()/udp_payload
        packet_to_send.sport = udp_sport
        packet_to_send.dport = udp_dport
        packet_to_send.version = ip_version
        packet_to_send.tos = ip_tos
        packet_to_send.id = ip_id
        packet_to_send.flags = ip_flags
        packet_to_send.frag = ip_frag
        packet_to_send.ttl = ip_ttl
        packet_to_send.proto = ip_proto
        packet_to_send.src = ip_src
        packet_to_send.dst = ip_dst
        packet_raw = raw(packet_to_send)
        packet_to_send = IP(packet_raw)
        print('ip校验和：'+hex(packet_to_send.chksum))
        # 去除数据包的IP首部，构建UDP数据包以下获得UDP的长度，校验和
        packet_udp_raw = packet_raw[20:]
        packet_udp_raw = UDP(packet_udp_raw)

        # 获取udp数据包长度
        entries[2].delete(0, END)
        entries[2].insert(0, int(packet_udp_raw.len))
        # 获取udp校验和
        entries[3].delete(0, END)
        entries[3].insert(0, hex(packet_udp_raw.chksum))
        # 获取ip数据包首部长度
        entries[6].delete(0, END)
        entries[6].insert(0, int(packet_to_send.ihl))
        # 获取ip包总长度
        entries[8].delete(0, END)
        entries[8].insert(0, int(packet_to_send.len))
        # 获取ip包校验和
        entries[14].delete(0, END)
        entries[14].insert(0, hex(packet_to_send.chksum))

        # 开一个线程用于连续发送数据包
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def create_http_sender():
    """
    http协议编辑函数
    :return:None
    """
    http_fields = 'HTTP包头：', '源端口：', '目的端口：', '源IP地址：', '目的IP地址：'
    entries = create_protocol_editor(protocol_editor_panedwindow, http_fields)
    send_packet_button, reset_button, default_packet_button = create_bottom_buttons(protocol_editor_panedwindow)
    # 为"回车键"的Press事件编写事件响应代码，发送HTTP报文
    tk.bind('<Return>', (lambda event: send_http_packet(entries, send_packet_button)))
    # <Return>代表回车键
    # 为"发送"按钮的单击事件编写事件响应代码，发送HTTP报文
    send_packet_button.bind('<Button-1>', (lambda event: send_http_packet(entries, send_packet_button)))
    # <Button-1>代表鼠标左键单击
    # 为"清空"按钮的单击事件编写事件响应代码，清空协议字段编辑框
    reset_button.bind('<Button-1>', (lambda event: clear_protocol_editor(entries)))
    # 为"默认值"按钮的单击事件编写事件响应代码，在协议字段编辑框填入HTTP报文字段的默认值
    default_packet_button.bind('<Button-1>', (lambda event: create_default_http_packet(entries)))


def create_default_http_packet(entries):
    """
    创建http默认报文
    :param entries:
    :return:None
    """
    clear_protocol_editor(entries)
    default_http_packet = TCP() / IP()

    entries[0].insert(0, "GET / HTTP/1.1\r\n")
    entries[1].insert(0, default_http_packet.sport)
    entries[2].insert(0, default_http_packet.dport)
    entries[3].insert(0, default_http_packet.src)
    entries[4].insert(0, default_gateway)


def send_http_packet(entries, send_packet_button):
    """
    发送http报文函数
    :param entries: http报文字段
    :param send_packet_button: 报文发送按钮
    :return:None
    """
    if send_packet_button['text'] == '发送':
        http_options = entries[0].get()
        http_sport = int(entries[1].get())
        http_dport = int(entries[2].get())
        http_src = entries[3].get()
        http_dst = entries[4].get()

        tcp = TCP()
        tcp.sport = http_sport
        tcp.dport = http_dport

        ip = IP()
        ip.src = http_src
        ip.dst = http_dst
        packet_to_send = ip / tcp / http_options

        # 开一个线程用于连续发送数据报文
        t = threading.Thread(target=send_packet, args=(packet_to_send,))
        t.setDaemon(True)
        t.start()
        # 使协议导航树不可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '停止'
    else:
        # 终止数据包发送线程
        stop_sending.set()
        # 恢复协议导航树可用
        toggle_protocols_tree_state()
        send_packet_button['text'] = '发送'


def send_packet(packet_to_send):
    """
    用于发送数据包的线程函数，持续发送数据包
    :type packet_to_send: 待发送的数据包
    """
    # print(packet.show(dump=True))
    # 对发送的数据包次数进行计数，用于计算发送速度
    n = 0
    stop_sending.clear()
    # 待发送数据包的长度（用于计算发送速度）
    packet_size = len(packet_to_send)
    # 推导数据包的协议类型
    proto_names = ['TCP', 'UDP', 'ICMP', 'IP', 'ARP', 'Ether', 'Unknown']
    packet_proto = ''
    for pn in proto_names:
        if pn in packet_to_send:
            packet_proto = pn
            break
    # 开始发送时间点
    begin_time = datetime.now()
    while not stop_sending.is_set():
        if isinstance(packet_to_send, Ether):
            sendp(packet_to_send, verbose=0)  # verbose=0,不在控制回显'Sent 1 packets'.
        else:
            send(packet_to_send, verbose=0)
        n += 1
        end_time = datetime.now()
        total_bytes = packet_size * n
        bytes_per_second = total_bytes / ((end_time - begin_time).total_seconds()) / 1024
        status_bar.set('已经发送了%d个%s数据包, 已经发送了%d个字节，发送速率: %0.2fKB/秒',
                       n, packet_proto, total_bytes, bytes_per_second)


def create_welcome_page(root):
    """

    :param root:
    :return:
    """

    welcome_string = '巨丑的封面\n计算机网络课程设计\n协议编辑器\n学号：150342233\n姓名：徐晓武'
    Label(root, justify=CENTER, padx=10, pady=150, text=welcome_string,
          font=('隶书', '30', 'bold')).pack()


if __name__ == '__main__':
    # 创建协议导航树并放到左右分隔窗体的左侧
    main_panedwindow.add(create_protocols_tree())
    # 将协议编辑区窗体放到左右分隔窗体的右侧
    main_panedwindow.add(protocol_editor_panedwindow)
    # 创建欢迎界面
    create_welcome_page(protocol_editor_panedwindow)
    main_panedwindow.pack(fill=BOTH, expand=1)
    # 启动消息处理
    tk.mainloop()
