from os import system
from time import monotonic, sleep
from crypter import RSA, code
from random import randbytes
from threading import Thread

import asyncio, concurrent.futures
import sqlite3, socket



class User:
    def __init__(self, name: str, conn: socket.socket, addr: any, thread: Thread) -> None:
        self._name = name
        self._connection = conn
        self._address = addr
        self._listenthread = thread

    @property
    def address(self) -> any:
        return self._address
    
    @property
    def connection(self) -> socket.socket:
        return self._connection
    
    @property
    def name(self) -> str:
        return self._name
    
    @property
    def listen(self) -> Thread:
        return self._listenthread

class Database:
    def __init__(self, database: str) -> None:
        """
            Create or open database:\n
            database -> path to db file to open or create them
        """
        try:
            self._connection = sqlite3.connect(database)
            self._cursor = self._connection.cursor()
        except Exception as error:
            print(f"Database '__init__' error: {error}")
    
    def __database_check__(self) -> bool:
        """
            Check database, if columns = -1, prepare new database else return True
        """
        print(self._cursor.rowcount)
    
    def create_table(self, name: str, values: str) -> None:
        """
            Create new table for database.\n
            name -> table name,\n
            values -> columns for data, example: values="userid int, exponent int, pubkey int, regtime int"
        """
        try:
            self._cursor.execute(f"CREATE TABLE {name}({values});")
            self._connection.commit()
        except Exception as error:
            print(f"Database 'create_table' error: {error}")

    def insert(self, table: str, data: str) -> None:
        """
            Insert data in exist table.\n
            name -> table name, example: users\n
            values -> columns for data, example: values="name='noname', addr=''"
        """
        try:
            self._cursor.execute(f"INSERT INTO {table} ({data})")
            self._connection.commit()
        except Exception as error:
            print(f"Database 'insert' error: {error}")

class PacketManager:
    def fetch_keys(keys: bytes) -> bytes:
        """
            Fetch keys to RSA function and return keys as dictionary.
        """
        bytes_to_int = lambda x: int.from_bytes(x, "big")
        zerosize = 1024 - bytes_to_int(keys[:2])
        data = keys[2:zerosize]
        data = {
        "pubkey": (bytes_to_int(data[:32]), bytes_to_int(data[32:64])), 
        "privkey": (bytes_to_int(data[64:]), bytes_to_int(data[32:64])),
        }
        return data

    async def check_packet(rsa: RSA) -> bytes:
        return await PacketManager.decode_packet("check", rsa)

    async def keys_packet(rsa: RSA) -> bytes:
        """
            Prepare packet with keys to RSA function and return keys as bytes.
        """
        data: bytes = (
            rsa._data['pubkey'][0].to_bytes(32, "big") + 
            rsa._data['pubkey'][1].to_bytes(32, "big") + 
            rsa._data['privkey'][0].to_bytes(32, "big")
            )
        zerosize = 1022 - data.__len__()
        return zerosize.to_bytes(2, "big") + data + randbytes(zerosize)

    async def encode_packet(message: str, rsa: RSA) -> bytes:
        """
            Encode package and return encoded bytes.
        """
        payload = rsa.encode(code(message), rsa._data['pubkey'])
        zerosiez = 1022 - payload.__len__()
        return zerosiez.to_bytes(2, "big") + payload + randbytes(zerosiez)
    
    async def decode_packet(message: str, rsa: RSA) -> bytes:
        """
            Decode package and return Decode bytes.
        """
        zerosize = 1024 - int.from_bytes(message[:2], "big")
        return code(rsa.decode(message[2:zerosize], rsa._data['privkey']))

class Server:
    _tasks: list[asyncio.Task]        = []
    _users: dict[socket.socket, User] = {}
    _threads: dict[str, Thread]       = {}
    _starttime: float                 = monotonic()

    def __init__(self, address: tuple[str, int]) -> None:
        self.socket = socket.socket()
        self.address = address
        self.rsa    = RSA(key_length = 32)
    
    def server_status(self) -> str:
        return f"""Status:
    Users count: {self._users.__len__()}
    Working time: {round((monotonic() - self._starttime) / 60, 2)} minutes
    Threads status (
        accepter_thread: {'working' if self._threads['accepter'].is_alive() else 'stopped'}
        getter_thread  : {'working' if self._threads['getter']  .is_alive() else 'stopped'}
    )
"""

    def run(self) -> None:
        self.rsa.generate()

        self.socket.bind(self.address)
        self._starttime = monotonic()

        self._threads['accepter'] = Thread(target=asyncio.run, args=(self.accept(), ), daemon=True)
        #self._threads['getter']   = Thread(target=asyncio.run, args=(self.getall(), ), daemon=True)

        self._threads['accepter'].start()
        #self._threads['getter']  .start()

        clear = lambda: system('cls')
        try:
            clear()
            while True:
                continue
        except Exception as error:
            exit("Closing server!")

    async def _listen_user(self, conn: socket.socket, user: User) -> None:
        try:
            while True:
                data = conn.recv(1024)
                await self.getted(data, user)
        except:
            print(f"{user.name} -> disconnected")
            self._users.pop(conn)
            await self.on_disconnect(user)


    async def accept(self) -> tuple[socket.socket, any]:
        while True:
            self.socket.listen(1)
            conn, addr = self.socket.accept()
            self._users[conn] = User(f"user{self._users.__len__().__hash__()}", conn, addr, None)
            self._users[conn]._listenthread = Thread(target=asyncio.run, args=(self._listen_user(conn, self._users[conn]), ))
            keys_packet = await PacketManager.keys_packet(self.rsa)
            self._users[conn].listen.start()
            try:
                conn.sendall(keys_packet)
                print(f"{self._users[conn].name} -> connected")
                await self.send(f"{self._users[conn].name}:{addr} -> connected to server!")
            except:
                self._users.pop(conn)

    async def sendall(self, message: bytes) -> None:
        try:
            for conn, user in self._users.items():
                try:
                    conn.sendall(message)
                except:
                    self._users.pop(conn)
                    await self.on_disconnect(user)    
        except:
            return

    async def send(self, message: str) -> None:
        encoded = await PacketManager.encode_packet(message, self.rsa)
        await self.sendall(encoded)

    async def getted(self, message: bytes, user: User) -> None:
        decoded = await PacketManager.decode_packet(message, self.rsa)
        print(f"{user.name}: {decoded}")
        await self.send(f"{user.name}: {decoded}")

    async def on_disconnect(self, user: User) -> None:
        await self.send(f"User {user.name} disconnected!")

if __name__ == "__main__":
    server = Server(("0.0.0.0", 3030))
    server.run()