#!/usr/bin/env python3

import argparse
import jsonlines
import socket
# from multiprocessing import Pool
import queue
from queue import Queue
import threading
# from functools import partial
# from tqdm import tqdm
import traceback
import json
import os
import sys
import signal 


def signal_handler(sig, frame):
   print("\nExiting...")
   sys.exit(1)

def create_parser():
   parser = argparse.ArgumentParser(description='Ship json file to collector.')

   parser.add_argument('file', metavar='FILE', type=str,
                       help='json file to ship')

   parser.add_argument('-H','--host', metavar='HOST', type=str,
                       default="localhost",
                       help='host to send data to (default:localhost)')

   parser.add_argument('-p','--port', metavar='PORT', type=int,
                       default=6000,
                       help='port of host (default:6000)')

   parser.add_argument('-w','--pool-size', dest='pool_size', type=int,
                       default=3, metavar='SIZE',
                       help='number of worker threads shipping data (default:3)')

   parser.add_argument('-o','--only-one', dest='only_one', 
                       default=False, action="store_true",
                       help='process only the first piece of data (default:False)')

   parser.add_argument('-j','--json-key', metavar='id', type=str, dest='filter_key',
                       default=None,
                       help='key for filtering of data, eg input:{"data":{"a":1, "b":2}} and key:"data" then {"a":1, "b":2} iss shipped instead of the whole document (default: off)')

   return parser


def load_json_file(f_name, work_queue, enqueue_done, only_one, filter_key):
   with jsonlines.open(f_name) as reader:
      print("Loading data from {}...".format(f_name))
      # dat = list()
      for line in reader:#tqdm(reader):
         # dat.append(line["data"])
         # print((line))
         # sys.exit(0)
         if filter_key:
            try:
               dat = line[filter_key]
            except:
               sys.stderr.write("\nerror: key{} not found in data".format(filter_key))
               sys.exit(1)
         else:
            dat = line
         work_queue.put(dat, block=True, timeout=None)
         print("i",end='',flush=True)
         if only_one:
            break
      enqueue_done.set()
   print("F",end='',flush=True)

   # return dat

def send_data(work_queue, h_p, enqueue_done):
   while not work_queue.empty() or not enqueue_done.is_set():
      # print(work_queue.empty(), enqueue_done.is_set(),flush=True)
      try:
         data = work_queue.get(block=True, timeout=0.5)
      except queue.Empty:
         # traceback.print_exc()
         continue
      try:
         with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
               s.connect(h_p)
            except ConnectionRefusedError:
               print("\nConnection Refused.",file=sys.stderr)
               os.kill(os.getpid(), signal.SIGINT)
               # os.exit(1)
            # print(data)
            s.sendall(json.dumps(data).encode())
            # reply = s.recv(1024)
         # work_queue.task_done()
         print(".",end='',flush=True)
      except:
         # traceback.print_exc()
         continue
   print("D",end='',flush=True)

def main():
   # print(os.getpid())
   parser = create_parser()
   args = parser.parse_args()
   
   signal.signal(signal.SIGINT, signal_handler)

   enqueue_done = threading.Event()
   work_queue = Queue()

   adder_thread = threading.Thread(target=load_json_file, args=(args.file,work_queue, enqueue_done, args.only_one, args.filter_key), daemon=False)
   adder_thread.start()

   # p = Pool(args.pool_size, send_data, (work_queue, (args.host, args.port), enqueue_done))

   worker_threads = list()
   for i in range(args.pool_size):
      wt = threading.Thread(target=send_data, args=(work_queue, (args.host, args.port), enqueue_done), daemon=False)
      worker_threads.append(wt)
      wt.start()

   adder_thread.join()
   for wt in worker_threads:
      wt.join()
   # p.join()

if __name__ == '__main__':
   main()


