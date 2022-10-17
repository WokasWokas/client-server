from time import sleep, strftime, gmtime, time
from threading import Thread
from tkinter import (
    Button,
    Label,
    Entry,
    Menu,
    Text,
    END,
    Tk,
)
import client

timestamp = lambda: strftime("%d.%m %H:%M:%S", gmtime(time()))

class Form(Tk):
    def __init__(self, address: tuple[str, int], *args, **kwargs) -> None:
        Tk.__init__(self, *args, **kwargs)

        self.resolution = (800, 600)
        self.client = client.Client(address)
        self.listener = Thread(target=self._message_getter, args=())

        # Инициализация формы и окон ввода и вывода
        self.title('Secure messager')
        self.geometry(f"{self.resolution[0]}x{self.resolution[1]}")
        self.entry = Input(self, text='write')
        self.label = Label(self, text='Output window')
        self.output = Output(self)

        # Инициализация кнопок
        self.decode_button = Button(self, text='send', command=self.call_send)

        # Размещение виджетов на форме
        self.label.place(x=10, y=45)
        self.entry.place(x=10, y=10, width=self.resolution[0] - 60, height=25)
        self.output.place(x=10, y=65, width=self.resolution[0] - 20, height=self.resolution[1] - 100)
        self.decode_button.place(x=self.resolution[0] - 60, y=10, width=50, height=25)

    def check_thread(self) -> None:
        while True:
            sleep(1)
            print(self.listenner_thread.is_alive())

    def call_send(self) -> None:
        if self.entry.get().__len__() > 512:
            self.output.print("Message too big, max length: 512")
        elif not self.client.send(self.entry.get()):
            self.output.print(f"{self.entry.get()} [NOT SENDED]")

    def _message_getter(self) -> None:
        try:
            while True:
                data = self.client.socket.recv(1024)
                message = client.PacketManager.decode_packet(data, self.client.rsa)
                if message == "": continue
                self.output.print(message)
        except:
            exit("Connection closed!")

    def start(self) -> None:
        if not self.client.start(): exit("Connection not created!")
        self.listener.start()
        self.mainloop()
    

class Input(Entry):
    def __init__(self, parent, **kwargs):
        Entry.__init__(self, parent, **kwargs)
        self.context_menu = ContextMenu(self, tearoff = 0)

class Output(Text):
    def __init__(self, parent, **kwargs):
        Text.__init__(self, parent, **kwargs)
        self.context_menu = ContextMenu(self, tearoff = 0)
        self.configure(state='disable')
    
    def print(self, message) -> None:
        self.configure(state='normal')
        self.insert(END, f"\n{message}")
        self.configure(state='disable')

class ContextMenu(Menu):
    def __init__(self, parent: Text | Entry, *args, **kwargs) -> None:
        Menu.__init__(self, parent, *args, **kwargs)
        self.parent = parent
        self.add_command(label="Copy", accelerator="Ctrl+C", command=self.call_copy)
        self.add_command(label="Paste", accelerator="Ctrl+V", command=self.call_paste)
        self.add_command(label="Cut", accelerator="Ctrl+X", command=self.call_cut)
        self.parent.bind("<Button-3>", self.do_popup)

    def call_copy(self, event=None) -> None:
        self.parent.clipboard_clear()
        text = self.parent.get('sel.first', 'sel.last')
        self.parent.clipboard_append(text)
    
    def call_paste(self, event=None) -> None:
        text = self.parent.selection_get(selection='CLIPBOARD')
        self.parent.insert('insert', text)

    def call_cut(self, event=None) -> None:
        self.call_copy()
        self.parent.delete("sel.first", "sel.last")

    def do_popup(self, event):
        try:
            self.tk_popup(event.x_root, event.y_root)
        finally:
            self.grab_release()
        
