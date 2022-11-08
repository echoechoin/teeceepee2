from src.socket.socket import socket, AF_INET, SOCK_STREAM
from src.stack import TeeceepeeStack

stack = TeeceepeeStack()
s = socket(stack, AF_INET, SOCK_STREAM, 0)
s.bind(("10.0.0.1", 80))
print("Listening on 10.0.0.1:80")
s.listen(1)
new_s = s.accept()[0]
while True:
    try:
        print("reading...")
        data = new_s.read()
        print("recv data: %s"%data.decode())

        print("writing...")
        new_s.write(data)
        print("reply data: ", data)
    except:
        import traceback
        traceback.print_exc()
        new_s.close()
        new_s = s.accept()[0]
