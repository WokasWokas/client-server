from time import strftime, gmtime, time
from crypter import code, RSA
from threading import Thread
from random import randbytes
import socket

bytes_to_int = lambda x: int.from_bytes(x, "big")

class PacketManager:
    def keys_packet(rsa: RSA) -> bytes:
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

    def fetch_keys(keys: bytes) -> bytes:
        """
            Fetch keys to RSA function and return keys as dictionary.
        """
        zerosize = 1024 - bytes_to_int(keys[:2])
        data = keys[2:zerosize]
        data = {
        "pubkey": (bytes_to_int(data[:32]), bytes_to_int(data[32:64])), 
        "privkey": (bytes_to_int(data[64:]), bytes_to_int(data[32:64])),
        }
        return data

    def encode_packet(message: str, rsa: RSA) -> bytes:
        """
            Encode package and return encoded bytes.
        """
        payload = rsa.encode(code(message), rsa._data['pubkey'])
        zerosiez = 1022 - payload.__len__()
        return zerosiez.to_bytes(2, "big") + payload + randbytes(zerosiez)
    
    def decode_packet(message: str, rsa: RSA) -> bytes:
        """
            Decode package and return Decode bytes.
        """
        zerosize = 1024 - int.from_bytes(message[:2], "big")
        return code(rsa.decode(message[2:zerosize], rsa._data['privkey']))

class Client:
    def __init__(self, addr: tuple[str, int]) -> None:
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.rsa = RSA(key_length = 32)
        self.addr = addr

    def start(self) -> bool:
        if not self._connect(): return False
        return True

    def _connect(self) -> bool:
        try:
            self.socket.connect(self.addr)
            keys = self.socket.recv(1024)
            self.rsa.set_keys(PacketManager.fetch_keys(keys))
            return True
        except Exception as error:
            print(error)
            return False

    def send(self, message: str) -> bool:
        try:
            encoded = PacketManager.encode_packet(message, self.rsa)
            self.socket.sendall(encoded)
            return True
        except Exception as error:
            print(error)
            