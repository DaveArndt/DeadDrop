import sys
import time
import socket
import struct
import threading
import mysql.connector
import mysql.connector.pooling

from common import Constants, Flags, send_all, recv_all

def safe_get_connection(cpool):
    connection = None
    while not connection:
        try:
            connection = cpool.get_connection()
        except mysql.connector.errors.PoolError:
            sleep(1)
    return connection

'''
Takes time in hours, converts to sql-formatted time
'''
def sql_time(time):
    hours = int(time)
    time = (time - hours) * 60
    minutes = int(time)
    time = (time - minutes) * 60
    seconds = int(time)
    return hours * 10000 + minutes * 100 + seconds

'''
Receive client packet, store message/return requested data.
'''
class RequestHandler(threading.Thread):

    def store_data(self):
        sql = "insert into Messages (manifest, body, time_uploaded) value (%s, %s, NOW())"

        manifest = recv_all(self.skt, Constants.MAN_LEN)
        body = recv_all(self.skt, Constants.BODY_LEN)

        if manifest is None or body is None:
            return False

        params = (manifest, body)

        try:
            connection = safe_get_connection(self.cpool)
            cursor = connection.cursor()

            cursor.execute(sql, params)
            connection.commit()

            connection.close()
            cursor.close()

            data = struct.pack("!B", Flags.PUT_SUCC)

        except:
            connection.rollback()
            data = struct.pack("!B", Flags.ERROR)

        return send_all(self.skt, data)

    def serve_body(self):
        sql = "select body from Messages where id = %s"
        index = recv_all(self.skt, Constants.ID_LEN)

        if index is None:
            return False

        index = struct.unpack("!I", index)[0]
        params = (index,)
        try:
            connection = safe_get_connection(self.cpool)
            cursor = connection.cursor()

            cursor.execute(sql, params)
            body = cursor.fetchall()[0][0]

            connection.close()
            cursor.close()

            data = struct.pack("!B", Flags.MES_DATA)
            data += body

        except TypeError:
            data = struct.pack("!B", Flags.ERROR)
        
        return send_all(self.skt, data)

    def serve_manifest(self):
        sql = "select id, manifest from Messages"
        data = b''

        try:
            connection = safe_get_connection(self.cpool)
            cursor = connection.cursor()

            cursor.execute(sql)
            manifest = cursor.fetchall()

            connection.close()
            cursor.close()

            data = struct.pack("!B", Flags.MAN_DATA)
            data += struct.pack("!I", len(manifest))

            for entry in manifest:
                data += struct.pack("!I", entry[0])
                data += entry[1]
        except:
            data = struct.pack("!B", Flags.ERROR)

        return send_all(self.skt, data)

    def __init__(self, skt, cpool):
        super().__init__()
        self.skt = skt
        self.cpool = cpool

    def run(self):
        running = True
        while running:
            flag = self.skt.recv(1)
            if len(flag) == 0:
                break
            else:
                flag = flag[0]

            if flag == Flags.MAN_REQ:
                running = self.serve_manifest()
            elif flag == Flags.MES_REQ:
                running = self.serve_body()
            elif flag == Flags.MES_PUT:
                running = self.store_data()

        self.skt.shutdown(socket.SHUT_RDWR)
        self.skt.close()

class CleanupLoop(threading.Thread):
    '''
    Give duration and life in hours, converted to seconds/time
    '''
    def __init__(self, cpool, duration, life):
        super().__init__()
        self.duration = duration * 3600
        self.life = sql_time(life)
        self.parent = threading.current_thread()
        self.cpool = cpool

    '''
    Send SQL to delete messages older than life.
    '''
    def cleanup(self):
        sql = "delete from Messages where timediff(now(), time_uploaded) > %s"
        data = (self.life,)
        try:
            connection = safe_get_connection(self.cpool)
            cursor = connection.cursor()

            cursor.execute(sql, data)
            connection.commit()

            cursor.close()
            connection.close()
        except:
            connection.rollback()

    def run(self):
        while True:
            # execute 1/duration
            time.sleep(self.duration)
            # kill self if orphan
            if not self.parent.is_alive():
                break
            # delete entries with now - time_uploaded > life
            self.cleanup()

'''
Main server loop to handle connections.
'''
def serve_requests(port, cpool):
    # set up server socket
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((socket.gethostname(), port))
    server_socket.listen(5)

    # spin up request handlers
    handlers = []
    while True:
        (client_socket, client_address) = server_socket.accept()
        handlers.append(RequestHandler(client_socket, cpool))
        handlers[-1].start()

        # clean up finished children
        for h in handlers:
            h.join(0)
        handlers = [h for h in handlers if h.is_alive()]

def run_server():
    # setup runtime variables (database, optional timing stuff) ----TODO----
    # port, max_connections, duration, life, user, database, [password, dbhost, dbport]

    port = None
    max_connections = None
    duration = None
    life = None
    user = None
    database = None
    password = None
    dbhost = '127.0.0.1'
    dbport = '3306'

    args = sys.argv
    
    try:
        port = int(args[1])
        max_connections = int(args[2])
        duration = float(args[3])
        life = float(args[4])
        user = args[5]
        database = args[6]

        i = 7
        while i < len(args):
            if args[i] == '-p':
                password = args[i + 1]
                i += 2
            elif args[i] == '-h':
                dbhost = args[i + 1]
                i += 2
            elif args[i] == '-d':
                dbport = args[i + 1]
                i += 2
            else:
                i += 1

    except:
        print("Usage: python3 server.py port max_connections cleanup_loop_duration cleanup_life db_username db_name [-p db_password] [-h db_host] [-d db_port]")
        quit()

    dbconfig = {
        'user': user,
        'password': password,
        'database': database,
        'host': dbhost,
        'port': dbport
    }

    cpool = mysql.connector.pooling.MySQLConnectionPool(pool_size=max_connections+1, pool_reset_session=True, **dbconfig)

    clean_thread = CleanupLoop(cpool, duration, life)
    clean_thread.start() #--TEST--

    serve_requests(port, cpool)

if __name__ == '__main__':
    run_server()