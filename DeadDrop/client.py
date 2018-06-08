import sys
import socket
import struct

from itertools import product

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS

from .common import Constants, Flags, send_all, recv_all

class ConnectionLostError(Exception):
    pass

class RequestError(Exception):
    pass

class UsernameError(Exception):
    pass

class KeyLenError(Exception):
    pass

def set_length(byte_string, length):
    temp = byte_string
    if len(temp) > length:
        temp = temp[:length]
    temp += b'\0' * (length - len(temp))
    return temp

'''
Takes file path and optional passphrase, returns RSA key
'''
def import_key(path, passphrase=None):
    try:
        f = open(path, 'r')
        key = RSA.importKey(f.read(), passphrase)

    except IOError:
        key = None

    except (ValueError, IndexError, TypeError):
        key = None
        f.close()

    return key

'''
Takes file path and optional passphrase, stores RSA key
'''
def export_key(key, path, passphrase=None):
    try:
        f = open(path, 'w')
        f.write(key.exportKey('PEM', passphrase).decode('utf-8'))

    except IOError:
        return False

    except ValueError:
        f.close()
        return False

    return True

class DDClient:
    def __init__(self, server, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((server, port))

    # raises ConnectionLostError, RequestError
    # returns [(int, bytes)]
    def get_manifest(self):
        data = struct.pack("!B", Flags.MAN_REQ)
        if not send_all(self.socket, data):
            raise ConnectionLostError

        flag = recv_all(self.socket, Constants.FLAG_LEN)
        
        if flag is None:
            raise ConnectionLostError

        flag = struct.unpack("!B", flag)[0]

        if flag == Flags.ERROR or flag != Flags.MAN_DATA:
            raise RequestError

        length = recv_all(self.socket, Constants.NUM_LEN)

        if length is None:
            raise ConnectionLostError

        length = struct.unpack("!I", length)[0]

        manifest_list = []
        for i in range(length):
            index = recv_all(self.socket, Constants.ID_LEN)
            manifest = recv_all(self.socket, Constants.MAN_LEN)

            if index is None or manifest is None:
                raise ConnectionLostError

            index = struct.unpack("!I", index)[0]

            manifest_list.append((index, manifest))

        return manifest_list

    # raises ConnectionLostError, RequestError
    # returns bytes
    def get_ciphertext(self, index):
        data = struct.pack("!B", Flags.MES_REQ)
        data += struct.pack("!I", index)

        if not send_all(self.socket, data):
            raise ConnectionLostError

        flag = recv_all(self.socket, Constants.FLAG_LEN)
        
        if flag is None:
            raise ConnectionLostError

        flag = struct.unpack("!B", flag)[0]

        if flag == Flags.ERROR or flag != Flags.MES_DATA:
            raise RequestError

        signature = recv_all(self.socket, Constants.SIG_LEN)
        ciphertext = recv_all(self.socket, Constants.CIPH_LEN)

        if signature is None or ciphertext is None:
            raise ConnectionLostError

        return (signature, ciphertext)

    # raises ConnectionLostError, RequestError
    # returns bool
    def put_message(self, manifest_entry, body):
        data = struct.pack("!B", Flags.MES_PUT)
        data += manifest_entry
        data += body

        if not send_all(self.socket, data):
            raise ConnectionLostError

        flag = recv_all(self.socket, Constants.FLAG_LEN)

        if flag is None:
            raise ConnectionLostError

        flag = struct.unpack("!B", flag)[0]

        if flag != Flags.ERROR and flag != Flags.PUT_SUCC:
            raise RequestError

        if flag == Flags.PUT_SUCC:
            return True
        else:
            return False

    # returns [(int, string, bytes)]
    def unpack_manifest(self, manifest, username, key):

        if len(username) > Constants.NAME_LEN:
            raise UsernameError

        if (key.size() + 1) / 8 != Constants.RSA_KEY_LEN:
            raise KeyLenError

        received = []
        cipher = PKCS1_OAEP.new(key)

        for index, entry in manifest:
            data = cipher.decrypt(entry)
            
            start = 0
            length = Constants.NAME_LEN
            r_name = data[start : start + length].decode('utf-8').strip('\0')

            if username != r_name:
                continue

            start += length
            length = Constants.NAME_LEN
            s_name = data[start : start + length].decode('utf-8').strip('\0')

            start += length
            length = Constants.AES_KEY_LEN
            aes_key = data[start : start + length]

            received.append((index, s_name, aes_key))

        return received

    # returns (bytes, bytes)
    def pack_message(self, sender, recipient, sender_key, recipient_key, plaintext):
        if len(sender) > Constants.NAME_LEN or len(recipient) > Constants.NAME_LEN:
            raise UsernameError

        if (sender_key.size() + 1) / 8 != Constants.RSA_KEY_LEN or (recipient_key.size() + 1) / 8 != Constants.RSA_KEY_LEN:
            raise KeyLenError

        sender_bytes = sender.encode('utf-8')
        sender_bytes = set_length(sender_bytes, Constants.NAME_LEN)

        recipient_bytes = recipient.encode('utf-8')
        recipient_bytes = set_length(recipient_bytes, Constants.NAME_LEN)

        plain_bytes = plaintext.encode('utf-8')
        plain_bytes = set_length(plain_bytes, Constants.PLAIN_LEN)

        # init ciphers
        s_cipher = PKCS1_OAEP.new(sender_key)
        signer = PKCS1_PSS.new(sender_key)
        r_cipher = PKCS1_OAEP.new(recipient_key)

        # generate AES key
        rand_gen = Random.new()
        aes_key = rand_gen.read(Constants.AES_KEY_LEN)

        # generate initialization vector
        iv = rand_gen.read(AES.block_size)

        # create AES cipher
        aes_cipher = AES.new(aes_key, AES.MODE_CBC, iv)

        # create and sign hash
        msg_hash = SHA256.new(aes_key + plain_bytes)
        signature = signer.sign(msg_hash)

        # compile and encrypt manifest entry
        manifest_entry = r_cipher.encrypt(recipient_bytes + sender_bytes + aes_key)

        # encrypt plaintext
        ciphertext = iv + aes_cipher.encrypt(plain_bytes)

        return (manifest_entry, signature + ciphertext)

    def unpack_message(self, sender_key, aes_key, signature, ciphertext):
        iv = ciphertext[:Constants.IV_LEN]
        recipient_cipher = AES.new(aes_key, AES.MODE_CBC, iv)
        verifier = PKCS1_PSS.new(sender_key)

        message_bytes = recipient_cipher.decrypt(ciphertext)[Constants.IV_LEN:]

        msg_hash = SHA256.new(aes_key + message_bytes)
        valid = verifier.verify(msg_hash, signature)

        plaintext = message_bytes.decode('utf-8').strip('\0')

        return (plaintext, valid)

    '''
    returns [(signature, ciphertext, sender, aes_key)]
    '''
    def gather_messages(self, received, all_indices):
        messages = []
        received_info = {r[0] : (r[1], r[2]) for r in received}

        for i in all_indices:
            try:
                message = self.get_ciphertext(i)
            except RequestError:
                continue

            if i in received_info.keys():
                data = received_info[i]
                messages.append((message[0], message[1], data[0], data[1]))

        return messages

    def close(self):
        self.socket.shutdown(socket.SHUT_RDWR)
        self.socket.close()