class Constants:
    FLAG_LEN = 1
    NUM_LEN = 4
    ID_LEN = 4
    NAME_LEN = 16
    AES_KEY_LEN = 32
    RSA_KEY_LEN = 256
    HASH_LEN = 32
    ADD_LEN = 256
    SIG_LEN = 256
    MAN_LEN = ADD_LEN
    IV_LEN = 16
    PLAIN_LEN = 1024
    CIPH_LEN = IV_LEN + PLAIN_LEN
    BODY_LEN = SIG_LEN + CIPH_LEN

class Flags:
    MAN_REQ = 1
    MES_REQ = 2
    MES_PUT = 3

    MAN_DATA = 4
    MES_DATA = 5
    PUT_SUCC = 6

    ERROR = 7

def send_all(skt, data):
    totalsent = 0
    while totalsent < len(data):
        sent = skt.send(data[totalsent:])
        if sent == 0:
            return False
        totalsent += sent
    return True

def recv_all(skt, bytes):
    totalreceived = b''
    while bytes > len(totalreceived):
        received = skt.recv(bytes - len(totalreceived))
        if len(received) == 0:
            return None
        totalreceived += received
    return totalreceived