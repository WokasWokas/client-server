from random import seed, getrandbits, randbytes
from functools import cache
from time import time

update_seed = lambda: seed(int(time() + getrandbits(64)))

def GetKeyFromDictWithValue(dict: dict[str, any], value: any) -> any:
    for key, value in dict.items():
        if value == value:
            return key

def AnyStrToInt(obj: str | list):
    if type(obj) == list:
        result = []
        for item in obj:
            result.append(int(item))
        return result
    elif type(obj) == str:
        return int(obj)

@cache
def gcd(a, b):
    while a != 0:
        a, b = b % a, a
    return b


class coding: 
    dictionary = {
        '!':b'\x01', '"':b'\x02', '#':b'\x03', '$':b'\x04', '%':b'\x05', '&':b'\x06', '\'':b'\x07', '(':b'\x08', ')':b'\x09',
        '*':b'\x0a', '+':b'\x0b', ',':b'\x0c', '-':b'\x0d', '.':b'\x0e', '/':b'\x0f', ':':b'\x10', ';':b'\x11', '<':b'\x12',
        '=':b'\x13', '>':b'\x14', '?':b'\x15', '@':b'\x16', '[':b'\x17', '\\':b'\x18', ']':b'\x19', '^':b'\x1a', '_':b'\x1b',
        '`':b'\x1c', '{':b'\x1d', '|':b'\x1e', '}':b'\x1f', '~':b'\x20', 'a':b'\x21', 'b':b'\x22', 'c':b'\x23', 'd':b'\x24',
        'e':b'\x25', 'f':b'\x26', 'g':b"\x27", 'h':b'\x28', 'i':b'\x29', 'j':b'\x2a',  'k':b'\x2b','l':b'\x2c', 'm':b'\x2d',
        'n':b'\x2e', 'o':b'\x2f', 'p':b'\x31', 'q':b'\x32', 'r':b'\x33', 's':b'\x34', 't':b'\x35', 'u':b'\x36', 'v':b'\x37',
        'w':b'\x38', 'x':b'\x39', 'y':b'\x3a', 'z':b'\x3b', 'A':b'\x3c', 'B':b'\x3d', 'C':b'\x3e', 'D':b'\x3f', 'E':b'\x41',
        'F':b'\x42', 'G':b'\x43', 'H':b'\x44', 'I':b'\x45', 'J':b'\x46', 'K':b'\x47', 'L':b'\x48', 'M':b'\x49', 'N':b'\x4a',
        'O':b'\x4b', 'P':b'\x4c', 'Q':b'\x4d', 'R':b'\x4e', 'S':b'\x4f', 'T':b'\x51', 'U':b'\x52', 'V':b'\x53', 'W':b'\x54',
        'X':b'\x55', 'Y':b'\x56', 'Z':b'\x57', '0':b'\x58', '1':b'\x59', '2':b'\x5a', '3':b'\x5b', '4':b'\x5c', '5':b'\x5d',
        '6':b'\x5e', '7':b'\x5f', '8':b'\x61', '9':b'\x62', 'ะน':b'\x63', 'ั':b'\x64', 'ั':b'\x65', 'ั':b'\x66', 'ะบ':b'\x67',
        'ะต':b'\x68', 'ะฝ':b'\x69', 'ะณ':b'\x6a', 'ั':b'\x6b', 'ั':b'\x6c', 'ะท':b'\x6d', 'ั':b'\x6e', 'ั':b'\x6f', 'ะฒ':b'\x70',
        'ะฐ':b'\x71', 'ะฟ':b'\x72', 'ั':b'\x73', 'ะพ':b'\x74', 'ะป':b'\x75', 'ะด':b'\x76', 'ั':b'\x77', 'ั':b'\x78', 'ั':b'\x79',
        'ะผ':b'\x7a', 'ะธ':b'\x7b', 'ั':b'\x7c', 'ั':b'\x7d', 'ะฑ':b'\x7e', 'ั':b'\x7f', 'ะถ':b'\x80', 'ั':b'\x81', 'ั':b'\x82',
        'ั':b'\x83', 'ะ':b'\x84', 'ะฆ':b'\x85', 'ะฃ':b'\x86', 'ะ':b'\x87', 'ะ':b'\x88', 'ะ':b'\x89', 'ะ':b'\x8a', 'ะจ':b'\x8b',
        'ะฉ':b'\x8c', 'ะ':b'\x8d', 'ะฅ':b'\x8e', 'ะช':b'\x8f', 'ะค':b'\x90', 'ะซ':b'\x91', 'ะ':b'\x92', 'ะ':b'\x93', 'ะ':b'\x94',
        'ะ?':b'\x95', 'ะ':b'\x96', 'ะ':b'\x97', 'ะ':b'\x98', 'ะ':b'\x99', 'ะญ':b'\x9a', 'ะฏ':b'\x9b', 'ะง':b'\x9c', 'ะก':b'\x9d',
        'ะ':b'\x9e', 'ะ':b'\x9f', 'ะข':b'\xa0', 'ะฌ':b'\xa1', 'ะ':b'\xa2', 'ะฎ':b'\xa3', 'โ':b'\xa4', '\n':b'\xa5', ' ':b'\xa6',
        '':b'\xa7'
    }
    
    def __init__(self) -> None:
        pass

    def __call__(self, value: str | bytes) -> str | bytes:
        if type(value) is str:
            return self.encode(value)
        elif type(value) is bytes:
            return self.decode(value)
        raise TypeError(f"In class ''coding', argument 'value' can't get {type(value)} type")

    def encode(self, value: str) -> bytes:
        result = b""
        for val in value:
            if not val in self.dictionary:
                raise ValueError(f"Value '{val}' not founded in dictionary.")
            result += self.dictionary.get(val)
        return result

    def decode(self, value: bytes) -> str:
        result = ""
        for i in range(len(value)):
            result += self.get_key_by_value(value[i])
        return result
        
    def get_key_by_value(self, val: int) -> str:
        for key, value in self.dictionary.items():
            if value == val.to_bytes(1, "big"):
                return key
        raise ValueError(f"Value '{val}' not founded in dictionary.")

class int(int):
    @cache
    def is_prime(self) -> bool:
        if (self % 2 == 0 or self % 3 == 0 or self == 1):
            return False
        i = 5
        while (i*i < self):
            if (self % i == 0 or self % (i + 2) == 0):
                return False
            i += 4
        return True

code = coding()

class RSA:
    _data: dict[str, int | list[int]] = {}

    def __init__(self, *args, **kwargs) -> None:
        self.key_length = int(kwargs.get("key_length"))
        self.block_length = self.key_length // 8 + 1

    def set_key_length(self, key_length: int = 16) -> None:
        self.key_length = key_length

    def get_prime(self) -> int:
        number = int(getrandbits(self.key_length))
        while not number.is_prime():
            number = int(getrandbits(self.key_length))
        return number

    def get_exponent(self) -> int:
        primes = self._data['primes']
        for i in range(primes[0] * primes[1] % self._data['euler'], self._data['euler'], 2):
            if gcd(i, self._data['euler']) == 1:
                return i
        return None

    def get_privkey(self):
        # Returns the modular inverse of a % m, which is
        # the number x such that a*x % m = 1

        if gcd(self._data['exponent'], self._data['euler']) != 1:
            return None # no mod inverse if a & m aren't relatively prime

        # Calculate using the Extended Euclidean Algorithm:
        u1, u2, u3 = 1, 0, self._data['exponent']
        v1, v2, v3 = 0, 1, self._data['euler']
        while v3 != 0:
            q = u3 // v3 # // is the integer division operator
            v1, v2, v3, u1, u2, u3 = (u1 - q * v1), (u2 - q * v2), (u3 - q * v3), v1, v2, v3
        return u1 % self._data['euler']

    def generate(self) -> None:
        while True:
            seed(int(time() + getrandbits(64)))

            self._data["primes"] = (
                self.get_prime(),
                self.get_prime(),
            )
            self._data["euler"] = (self._data["primes"][0] - 1) * (self._data["primes"][1] - 1)
            self._data["exponent"] = self.get_exponent()
            if self._data['exponent'] is None: continue
            self._data["pubkey"] = (
                self._data["exponent"],
                self._data["primes"][0] * self._data["primes"][1],
            )
            self._data["privkey"] = (
                self.get_privkey(),
                self._data["pubkey"][1],
            )

            if self.check_keys(): return
        
    def check_keys(self) -> bool:
        if not self._data.get("pubkey", False) and not self._data.get("privkey", False):
            raise KeyError("Generate data before use stuffs!")
        encoded = self.encode(b'test', self._data['pubkey'])
        decoded = self.decode(encoded, self._data['privkey'])
        if b"test" != decoded:
            raise KeyError("Keys is wrong!")
        return True

    def encode(self, message: bytes, pubkey: tuple[int, int]) -> bytes:
        encoded = b""
        for i in range(0, len(message), self.block_length):
            block = int.from_bytes(message[i:i + self.block_length], "big")
            value = pow(block, pubkey[0], pubkey[1])
            encoded += value.to_bytes(self.block_length * 2, "big")
        return encoded

    def decode(self, crypto_message: bytes, privkey: tuple[int, int]) -> bytes:
        decoded = b""
        for i in range(0, len(crypto_message), self.block_length * 2):
            block = int.from_bytes(crypto_message[i:i + self.block_length * 2], "big")
            value = pow(block, privkey[0], privkey[1])
            decoded += value.to_bytes(self.block_length * 2, "big").replace(b"\x00", b'')
        return decoded

    def set_keys(self, data: dict[str, int | tuple[int, int]]):
        for item, value in data.items():
            self._data[item] = value

    def import_keys(self, full_content) -> None:
        sizeof = int.from_bytes(full_content[:2], "big")
        payload =  code(full_content[2:len(full_content) - sizeof])
        for line in payload.split('\n'):
            key, value = line.split('=')
            value = value.strip('[]()\n').split(',')
            self._data[key] = AnyStrToInt(value[0] if len(value) == 1 else value)
        self.check_keys()
            
    def prepare_keys(self) -> None:
        payload = code('\n'.join([f"{key}={value}" for key, value in self._data.items()]))
        zeros = randbytes(1022 - len(payload))
        return len(zeros).to_bytes(2, "big") + payload + zeros

    def get_keys(self) -> str:
        return f"Public Key: {self._data.get('pubkey', None)}\nPrivate Key: {self._data.get('privkey', None)}"
