from time import monotonic, strftime, gmtime, time
from crypter import RSA, code
from random import randbytes
from threading import Thread
from time import monotonic
from os import system

import sqlite3, socket
import asyncio

timestamp = lambda: strftime("%d.%m.%y %H:%M:%S", gmtime(time()))
calculate_time = lambda x: round((monotonic() - x) * 1000, 2)
bytes_to_int = lambda x: int.from_bytes(x, "big")

class Log:
    class LogType:
        @property
        def INFO():
            return 'info'
        
        @property
        def WARN():
            return 'warn'
        
        @property
        def ERROR():
            return 'errn'

    def __call__(self, type: LogType, message: str, time: float = 0.0) -> None:
        print(f"{timestamp()}: {time} ms : [{type.fget()}] : {message}")

    def LogDecorator(self, func) -> None:
        def wrapper(*args, **kwargs) -> None:
            self(self.LogType.INFO, f"Calling function '{func.__name__}' with args {args, kwargs}")
            try:
                runtime = monotonic()
                result = func(*args, **kwargs)
                self(self.LogType.INFO, f"End function {func.__name__}", calculate_time(runtime))
                return result
            except Exception as error:
                self(self.LogType.WARN, error)
        return wrapper

log = Log()

class User:
    @log.LogDecorator
    def __init__(self, name: str, conn: socket.socket, addr: any, thread: Thread) -> None:
        self._name = name
        self._connection = conn
        self._address = addr
        self._listenthread = thread
        self._pubkey = ()

    @log.LogDecorator
    @property
    def address(self) -> any:
        return self._address
    
    @log.LogDecorator
    @property
    def connection(self) -> socket.socket:
        return self._connection
    
    @log.LogDecorator
    @property
    def name(self) -> str:
        return self._name
    
    @log.LogDecorator
    @property
    def listen(self) -> Thread:
        return self._pubkey
    
    @log.LogDecorator
    @property
    def pubkey(self) -> tuple[int, int]:
        return self._pubkey

class Database:
    def __init__(self, database: str) -> None:
        try:
            self._connection = sqlite3.connect(database)
            self._cursor = self._connection.cursor()
        except Exception as error:
            print(f"Database '__init__' error: {error}")
    
    def __database_check__(self) -> bool:
        print(self._cursor.rowcount)
    
    def create_table(self, name: str, values: str) -> None:
        try:
            self._cursor.execute(f"CREATE TABLE {name}({values});")
            self._connection.commit()
        except Exception as error:
            print(f"Database 'create_table' error: {error}")

    def insert(self, table: str, data: str) -> None:
        try:
            self._cursor.execute(f"INSERT INTO {table} ({data})")
            self._connection.commit()
        except Exception as error:
            print(f"Database 'insert' error: {error}")

class PacketManager:
    @log.LogDecorator
    async def keys_packet(rsa: RSA) -> bytes:
        data: bytes = (
            rsa._data['pubkey'][0].to_bytes(32, "big") + 
            rsa._data['pubkey'][1].to_bytes(32, "big")
            )
        zerosize = 1022 - data.__len__()
        return zerosize.to_bytes(2, "big") + data + randbytes(zerosize)

    async def fetch_pubkey_keys(keys: bytes) -> tuple[int, int]:
        zerosize = 1024 - bytes_to_int(keys[:2])
        data = keys[2:zerosize]
        keys = (bytes_to_int(data[:32]), bytes_to_int(data[32:64]))
        log(log.LogType.INFO, f"Public key fetched! pubkey: {keys}")
        return keys

    @log.LogDecorator
    async def encode_packet(message: str, rsa: RSA) -> bytes:
        payload = rsa.encode(code(message), rsa._data['_pubkey'])
        zerosiez = 1022 - payload.__len__()
        return zerosiez.to_bytes(2, "big") + payload + randbytes(zerosiez)
    
    async def decode_packet(message: str, rsa: RSA) -> bytes:
        zerosize = 1024 - int.from_bytes(message[:2], "big")
        return code(rsa.decode(message[2:zerosize], rsa._data['privkey']))

class Server:
    _tasks: list[asyncio.Task]        = []
    _users: dict[socket.socket, User] = {}
    _threads: dict[str, Thread]       = {}
    _starttime: float                 = monotonic()

    @log.LogDecorator
    def __init__(self, address: tuple[str, int]) -> None:
        self.socket  = socket.socket()
        self.address = address
        self.rsa     = RSA(key_length = 32)

    @log.LogDecorator
    def run(self) -> None:
        log(log.LogType.INFO, "Generating crypter keys...")
        self.rsa.generate()
        log(log.LogType.INFO, "Generated!")

        log(log.LogType.INFO, "Starting server...")
        self.socket.bind(self.address)
        self._starttime = monotonic()

        log(log.LogType.INFO, "Initing and starting accepter thread...")
        self._threads['accepter'] = Thread(target=asyncio.run, args=(self.accept(), ), daemon=True)
        self._threads['accepter'].start()
        log(log.LogType.INFO, "Inited and started!")

        clear = lambda: system('cls')
        try:
            log(log.LogType.INFO, "Server started!")
            while True:
                continue
        except Exception as error:
            log(log.LogType.ERROR, error)
            log(log.LogType.INFO, "Closing server!")
            del self._threads
            exit(0)

    @log.LogDecorator
    async def accept(self) -> tuple[socket.socket, any]:
        while True:
            self.socket.listen(1)
            conn, addr = self.socket.accept()
            self._users[conn] = User(f"user{self._users.__len__().__hash__()}", conn, addr, None)
            self._users[conn]._listenthread = Thread(target=asyncio.run, args=(self._listen_user(conn, self._users[conn]), ))
            keys_packet = await PacketManager.keys_packet(self.rsa)
            self._users[conn]._listenthread.start()
            try:
                conn.sendall(keys_packet)
                keys = conn.recv(1024)
                self._users[conn]._pubkey = await PacketManager.fetch_pubkey_keys(keys)
                await self.sendall(f"{self._users[conn]._name}:{addr} -> connected to server!")
            except:
                log(log.LogType.WARN, f"{self._users[conn].name} can't connected!")
                self._users.pop(conn)

    @log.LogDecorator
    async def _listen_user(self, conn: socket.socket, user: User) -> None:
        try:
            while True:
                data = conn.recv(1024)
                await self.getted(data, user)
        except:
            await self.on_disconnect(conn, user)

    @log.LogDecorator
    async def sendall(self, message: str) -> None:
        try:
            for conn, user in self._users.items():
                try:
                    await self.send(conn, user, message)
                except:
                    await self.on_disconnect(conn, user)
        except:
            return

    @log.LogDecorator
    async def send(self, conn: socket.socket, user: User, message: str) -> None:
        self.rsa._data['_pubkey'] = user._pubkey
        encoded = await PacketManager.encode_packet(message, self.rsa)
        conn.sendall(encoded)

    async def getted(self, message: bytes, user: User) -> None:
        decoded = await PacketManager.decode_packet(message, self.rsa)
        log(log.LogType.INFO, f"{user._name}: {decoded}")
        await self.sendall(f"{user._name}: {decoded}")

    @log.LogDecorator
    async def on_disconnect(self, conn: socket.socket, user: User) -> None:
        self._users.pop(conn)
        await self.sendall(f"{user._name} disconnected!")

if __name__ == "__main__":
    server = Server(("0.0.0.0", 3030))
    server.run()