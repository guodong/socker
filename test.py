
import socket
import os, time
import logging
import threading
import time

def thread_function(name):
    logging.info("Thread %s: starting", name)
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print client.fileno()
    while True:
       time.sleep(1)
    logging.info("Thread %s: finishing", name)

if __name__ == "__main__":
    format = "%(asctime)s: %(message)s"
    logging.basicConfig(format=format, level=logging.INFO,
                        datefmt="%H:%M:%S")

    threads = list()
    for index in range(3):
        logging.info("Main    : create and start thread %d.", index)
        x = threading.Thread(target=thread_function, args=(index,))
        threads.append(x)
        x.start()

    for index, thread in enumerate(threads):
        logging.info("Main    : before joining thread %d.", index)
        thread.join()
        logging.info("Main    : thread %d done", index)
# print os.getpid()
 
# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print client.fileno()
# client.bind(('0.0.0.0', 31415))
# try:
#   client.connect(("172.16.189.1",80))
# except:
#   pass
# client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# print client.fileno()
# # client.bind(('0.0.0.0', 31415))
# # client.connect(("127.0.0.1",8081))
# while 1:
#   time.sleep(4)