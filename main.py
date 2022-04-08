#!/usr/bin/env python3

import argparse
import json
import socket
import sys
from threading import Thread
import time
import random


CMD_FIELD_LEN = 1
FILE_SIZE_FIELD_LEN = 8
CMD = {
    "getdir": 1,
    "makeroom": 2,
    "deleteroom": 3,
    "bye": 4,
}
MSG_ENCODING = 'utf-8'
ARG_DELIMITER = ','
EXIT_CHAT_MSG = 'exit'
BYTE_ORDER = "big"

DELETEROOM_CMD = "deleteroom"
CONNECT_CMD = "connect"
GETDIR_CMD = "getdir"
MAKEROOM_CMD = "makeroom"
CHAT_CMD = "chat"
BYE_CMD = "bye"
NAME_CMD = "name"

########################################################################
# Broadcast Server class
########################################################################


class Server:
    HOSTNAME = 'localhost'
    CDP_PORT = 50000
    BACKLOG = 5

    TIMEOUT = 2
    RECV_SIZE = 256

    def __init__(self):
        self.connected = 0
        self.chatroom_dict = {}
        self.thread_list = []
        self.create_listen_socket()
        self.process_connections_forever()

    def create_listen_socket(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.socket.bind((Server.HOSTNAME, Server.CDP_PORT))
            self.socket.listen(Server.BACKLOG)
            print('\n\n' + '❤ ' * 25)
            print(f"!!! YOU'VE CONNECTED TO CRDS !!!\n"
                  f"Listening for TCP connections on CDP Port {Server.CDP_PORT}")
            print('❤ ' * 25)
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def connection_handler(self, client):
        connection, address = client
        while True:
            cmd = int.from_bytes(connection.recv(CMD_FIELD_LEN), byteorder=BYTE_ORDER)
            if cmd not in CMD.values():
                print('<Unknown command>')
                break
            if cmd == CMD[BYE_CMD]:
                print(f'Closing {address} client connection...')
                print('❤' * 72)
                connection.close()
                break
            elif cmd == CMD[GETDIR_CMD]:
                dir_dict = json.dumps(self.chatroom_dict)
                connection.sendall(dir_dict.encode(MSG_ENCODING))
                print("Sending getdir info")
            elif cmd == CMD[MAKEROOM_CMD]:
                makeroom_bytes = connection.recv(Server.RECV_SIZE)
                makeroom_str = makeroom_bytes.decode(MSG_ENCODING)
                makeroom_args = makeroom_str.split(ARG_DELIMITER)
                room_name, ip, port = makeroom_args[0], makeroom_args[1], makeroom_args[2]
                # address/port-pair must be unique
                is_unique = True
                for existing_room in list(self.chatroom_dict.values()):
                    if existing_room == (ip, port):
                        is_unique = False
                        print(f"There is already a room at ({ip}, {port})")
                        break
                if is_unique:
                    self.chatroom_dict[room_name] = (ip, port)
                print(f"made room {room_name} at ({ip}, {port})")
            elif cmd == CMD[DELETEROOM_CMD]:
                room_bytes = connection.recv(Server.RECV_SIZE)
                room = room_bytes.decode(MSG_ENCODING)
                if room in self.chatroom_dict:
                    self.chatroom_dict.pop(room)
                    print(f"Deleted room: {room}\nDir: {self.chatroom_dict}")
            elif cmd == CMD[BYE_CMD]:
                print("CLOSING CONNECTION!")
                connection.close()
                break

    def process_connections_forever(self):
        try:
            while True:
                new_client = self.socket.accept()
                new_thread = Thread(target=self.connection_handler, args=(new_client,))
                self.thread_list.append(new_thread)
                print("Connected to the client")
                new_thread.daemon = True
                new_thread.start()
        except Exception as e:
            print(e)
        except KeyboardInterrupt:
            print()
        finally:
            print("Closing server socket...")
            self.socket.close()
            sys.exit(1)


########################################################################
# Client class
########################################################################

CMD_INDEX = 0
DEF_CHATROOM = ["", "t", "239.0.0.10", "50000"]
USERNAMES = ["🍋", "🍎", "🥑", "🍄", "🍟"]

class Client:
    RECV_SIZE = 256
    TTL = 1
    TTL_BYTE = TTL.to_bytes(1, byteorder=BYTE_ORDER)
    TIMEOUT = 2

    def __init__(self):
        self.connected = 0
        self.in_chat = False
        self.username = random.choice(USERNAMES)
        self.chatroom_name = ""
        self.chatroom_info = {}
        self.chat_text = ""
        self.thread_list = []
        self.input_text = ""

        self.get_console_input()

    def connect(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((Server.HOSTNAME, Server.CDP_PORT))
            print(f"\n🎉 YOU'VE CONNECTED TO CRDS 🎉")
        except Exception as e:
            print(e)
            exit()

    def getdir(self, input_args):
        getdir_field = CMD[GETDIR_CMD].to_bytes(CMD_FIELD_LEN, byteorder=BYTE_ORDER)
        self.socket.sendall(getdir_field)
        try:
            recvd_bytes = self.socket.recv(Client.RECV_SIZE)
            dir_dict_serialized = recvd_bytes.decode(MSG_ENCODING)
            dir_dict = json.loads(dir_dict_serialized)
            self.chatroom_info = dir_dict
            print(self.chatroom_info)  # print dir info to client
        except Exception as msg:
            print(msg)
            sys.exit(1)

    def makeroom(self, input_args):
        name, address, port = input_args[1:4]
        makeroom_field = CMD[MAKEROOM_CMD].to_bytes(CMD_FIELD_LEN, byteorder=BYTE_ORDER)
        pkt_str = name + ARG_DELIMITER + address + ARG_DELIMITER + port
        pkt = makeroom_field + pkt_str.encode(MSG_ENCODING)
        self.socket.sendall(pkt)

    def delete_room(self, input_args):
        chatroom_name = input_args[1]
        delete_field = CMD[DELETEROOM_CMD].to_bytes(CMD_FIELD_LEN, byteorder=BYTE_ORDER)
        pkt = delete_field + chatroom_name.encode(MSG_ENCODING)
        self.socket.sendall(pkt)

    def bye(self, input_args):
        bye_field = CMD[BYE_CMD].to_bytes(CMD_FIELD_LEN, byteorder=BYTE_ORDER)
        self.socket.sendall(bye_field)
        print("Closing connection to the CRDS")
        self.connected = 0
        self.socket.close()

    def chat(self, input_args):
        try:
            multicast_address, multicast_port = self.chatroom_info[self.chatroom_name]
            ''' see multicast code from `coe4dn4_python_multicast_v02` lecture '''
            # create UDP socket for SENDING multicast packets
            self.socket_udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_udp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, Client.TTL_BYTE)
            # create recv socket to RECEIVING multicast packets
            self.socket_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.socket_recv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, True)
            multicast_port = int(multicast_port)
            self.socket_recv.bind((multicast_address, multicast_port))
            # issue add group membership request to local multicast router
            multicast_group_bytes = socket.inet_aton(multicast_address)
            # use all zeros and let system choose default interface
            multicast_if_bytes = socket.inet_aton("0.0.0.0")  # default interface
            # prepare and make multicast request
            multicast_request = multicast_group_bytes + multicast_if_bytes
            self.socket_recv.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, multicast_request)
        except Exception as e:
            print(e)
        # change command prompt
        print('\n' + '🎉✨️' * 5)
        print(f"Entering chatroom as {self.username}")
        # SEND thread
        udp_thread_send = Thread(target=self.send_messages_forever, args=(multicast_address, multicast_port))
        self.thread_list.append(udp_thread_send)
        udp_thread_send.start()
        # RECV thread
        udp_thread_receive = Thread(target=self.receive_forever)
        self.thread_list.append(udp_thread_receive)
        udp_thread_receive.start()
        # synchronization
        udp_thread_send.join()
        udp_thread_receive.join()
        # close threads
        self.socket_udp.close()
        self.socket_recv.close()
        # go back to (non-chat) console
        self.in_chat = False
        self.get_console_input()

    def send_messages_forever(self, multicast_address, multicast_port):
        try:
            while True:
                self.chat_text = input("")
                # delete the prompt/user-input line printed in the console as it is printed again after multicast
                print("\033[A                             \033[A")
                multicast_address_port = (multicast_address, int(multicast_port))
                if self.chat_text == EXIT_CHAT_MSG:
                    # don't add username to msg
                    self.socket_udp.sendto(EXIT_CHAT_MSG.encode(MSG_ENCODING), multicast_address_port)
                    return
                else:
                    pkt_str = self.username + ":" + self.chat_text
                    pkt = pkt_str.encode(MSG_ENCODING)
                    self.socket_udp.sendto(pkt, multicast_address_port)
                    time.sleep(Server.TIMEOUT)
        except KeyboardInterrupt:
            return

    def receive_forever(self):
        try:
            while True:
                data, address_port = self.socket_recv.recvfrom(Client.RECV_SIZE)
                msg = data.decode(MSG_ENCODING)
                if msg == EXIT_CHAT_MSG:
                    print("\n\nLEAVING CHAT\nGOODBYE 👋\n")
                    return
                print(data.decode(MSG_ENCODING))
        except KeyboardInterrupt:
            print("exiting")
            return

    def get_console_input(self):
        while not self.in_chat:
            print('\n' + '💎🎈' * 6)
            self.input_text = input("Enter Command 🧼 ")
            input_args = self.input_text.split()
            len_input_args = len(input_args)
            # connect
            try:
                if input_args[CMD_INDEX] == CONNECT_CMD or input_args[CMD_INDEX] == "con":
                    self.connect()
                    self.makeroom(DEF_CHATROOM)
                    self.chatroom_info[DEF_CHATROOM[1]] = DEF_CHATROOM[2:4]
            except Exception as e:
                print(e)
            # name
            try:
                if input_args[CMD_INDEX] == NAME_CMD and len_input_args >= 2:
                    self.username = input_args[1]
                    print("This is the name entered", self.username)
            except Exception as e:
                print(e)
            # bye
            try:
                if input_args[CMD_INDEX] == BYE_CMD:
                    self.bye(input_args)
            except Exception as e:
                print(e)
            # getdir
            try:
                if input_args[CMD_INDEX] == GETDIR_CMD or input_args[CMD_INDEX] == "ls":
                    self.getdir(input_args)
            except Exception as e:
                print(e)
            # makeroom
            try:
                if input_args[CMD_INDEX] == MAKEROOM_CMD or input_args[CMD_INDEX] == "make":
                    if len_input_args < 2:
                        # if user is missing name, ip, port
                        input_args = DEF_CHATROOM
                    self.makeroom(input_args)
            except Exception as e:
                print(e)
            # delete room
            try:
                if input_args[CMD_INDEX] == DELETEROOM_CMD or input_args[CMD_INDEX] == "rm":
                    self.delete_room(input_args)
            except Exception as e:
                print(e)
            # chat
            try:
                if input_args[CMD_INDEX] == CHAT_CMD:
                    self.chatroom_name = input_args[1]
                    self.in_chat = True
                    print("proceeding to chat function")
                    self.chat(input_args)
            except Exception as e:
                print(e)

########################################################################
# Process command line arguments if run directly.
########################################################################


if __name__ == '__main__':
    roles = {'client': Client, 'server': Server}
    parser = argparse.ArgumentParser()

    parser.add_argument('-r', '--role',
                        choices=roles,
                        help='sender or receiver role',
                        required=True, type=str)
    args = parser.parse_args()
    roles[args.role]()

########################################################################
