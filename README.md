1. `python main.py -r server`
2. `python main.py -r client`
    1. `con` or `connect` to connect to CRDS. This automatically creates a chdatroom with default adress and port: (239.0.0.10, 50000); and assigns you a username.
    2. `ls` or `getdir` to list existing chatrooms.
    3. `chat <room name>` to enter chat.
        * type `exit` into chat to return to CRDS.
        * type and hit `enter` to send something to chat.
3. `makeroom <name> <ip address> <port>` to make a chatroom.
4. `rm <roomname>` or `deleteroom <roomname>` to delete a chatroom.
