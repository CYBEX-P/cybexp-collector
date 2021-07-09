#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")
from web_client import  test_auth, test_token, post_enc_data
from priv_common import load_yaml_file, get_all_keys, encrypt_as_de, encrypt_as_cpabe
from priv_common import encrypt_as_timestamp, decrypt_cpabe, match_re_to_keys, _to_bool

import pickle
# import threading
import socket
from concurrent.futures.thread import ThreadPoolExecutor
import signal
import json

from pprint import pprint
import traceback



def create_indexes(enc_record:dict, record_keys:list, record:dict, enc_policy, key, debug=False):
   # pprint(enc_policy)
   index_created = False

   record_keys = set(record_keys) # create new object and dont change original

   # create index for exact matches
   try:
      for m in enc_policy["exact"]:
         try:
            k = m["match"]
            dat = record[k]
            enc_dat = encrypt_as_de(dat, key)
            if debug:
               print("{}: {}".format(k,"DE, index"), flush=True)
            try:
               enc_record["index"].append(enc_dat)
               record_keys.discard(k)
               index_created = index_created or True
            except KeyboardInterrupt:
               raise KeyboardInterrupt
            except :
               enc_record["index"] = list()
               enc_record["index"].append(enc_dat)
               record_keys.discard(k)
               index_created = index_created or True
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            # traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass


   # create index for regex matches
   try:
      for m in enc_policy["regex"]:
         try:
            reg_k = m["match"]
            matched_keys = match_re_to_keys(reg_k, list(record_keys))
            for k in matched_keys:
               try:
                  dat = record[k]
                  enc_dat = encrypt_as_de(dat, key)
                  if debug:
                     print("{}: {}, index".format(k,"DE"), flush=True)
                  try:
                     enc_record["index"].append(enc_dat)
                     record_keys.discard(k)
                     index_created = index_created or True
                  except KeyboardInterrupt:
                     raise KeyboardInterrupt
                  except (NameError,AttributeError,KeyError):
                     enc_record["index"] = list()
                     enc_record["index"].append(enc_dat)
                     record_keys.discard(k)
                     index_created = index_created or True
               except KeyboardInterrupt:
                  raise KeyboardInterrupt
               except:
                  traceback.print_exc()
                  continue
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            # traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass

   # if we can not create index for any of the matching record return false, sefety measure
   return index_created


def timestamp_match(enc_record:dict, record_keys:list, record:dict, enc_policy, key, enc_params, debug=False):
   # pprint(enc_policy)

   record_keys = set(record_keys) # create new object and dont change original

   # create index for exact matches
   try:
      for m in enc_policy["exact"]:
         try:
            k = m
            dat = record[k]
            enc_dat = encrypt_as_timestamp(dat, key, enc_params)
            if debug:
               print("{}: {}".format(k,"TIMESTAMP"), flush=True)
            if not enc_dat:
               continue
            try:
               enc_record["timestamp"].append(enc_dat)
               record_keys.discard(k)
            except KeyboardInterrupt:
               raise KeyboardInterrupt
            except (NameError,AttributeError,KeyError):
               enc_record["timestamp"] = list()
               enc_record["timestamp"].append(enc_dat)
               record_keys.discard(k)
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            # traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass


   # create index for regex matches
   try:
      for m in enc_policy["regex"]:
         try:
            reg_k = m
            matched_keys = match_re_to_keys(reg_k, list(record_keys))
            for k in matched_keys:
               try:
                  dat = record[k]
                  enc_dat = encrypt_as_timestamp(dat, key, enc_params)
                  if debug:
                     print("{}: {}".format(k,"TIMESTAMP"), flush=True)
                  if not enc_dat:
                     continue
                  try:
                     enc_record["timestamp"].append(enc_dat)
                     record_keys.discard(k)
                  except KeyboardInterrupt:
                     raise KeyboardInterrupt
                  except:
                     enc_record["timestamp"] = list()
                     enc_record["timestamp"].append(enc_dat)
                     record_keys.discard(k)
               except KeyboardInterrupt:
                  raise KeyboardInterrupt
               except:
                  # traceback.print_exc()
                  continue
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass



def exact_match(enc_record:dict, record_keys:list, record:dict, enc_policy, de_key, cpabe_pk, debug=False):

   new_record_keys = set(record_keys) # create new object and dont change original

   try:
      for m in enc_policy:
         try:
            k = m["match"]
            dat = record[k]

            if "remove" in m:
               if _to_bool(m["remove"]):
                  new_record_keys.discard(k)
                  continue

            try:
               want_de = _to_bool(m["de_encrypt"])
            except KeyboardInterrupt:
               raise KeyboardInterrupt
            except KeyError:
               want_de = False

            if want_de:
               de_k = "de_"+k
               enc_dat_de = encrypt_as_de(dat, de_key)
               enc_record[de_k] = enc_dat_de
               new_record_keys.discard(k)

            if "abe_pol" in m:
               if debug:
                  print("{}: {}".format(k,m["abe_pol"]), flush=True)
               abe_k = "cpabe_"+k
               enc_dat_abe = encrypt_as_cpabe(dat,m["abe_pol"], cpabe_pk)
               enc_record[abe_k] = enc_dat_abe
               new_record_keys.discard(k)
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            # traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass


   record_keys.clear()
   record_keys.extend(new_record_keys)


def regex_match(enc_record:dict, record_keys:list, record:dict, enc_policy, de_key, cpabe_pk, debug=False):

   new_record_keys = set(record_keys) # create new object and dont change original

   try:
      for m in enc_policy:
         try:
            reg_k = m["match"]
            matched_keys = match_re_to_keys(reg_k, list(record_keys))
            for k in matched_keys:
               try:
                  dat = record[k]

                  if "remove" in m:
                     if _to_bool(m["remove"]):
                        new_record_keys.discard(k)
                        continue

                  try:
                     want_de = _to_bool(m["de_encrypt"])
                  except KeyboardInterrupt:
                     raise KeyboardInterrupt
                  except KeyError:
                     want_de = False

                  if want_de:
                     de_k = "de_"+k
                     enc_dat_de = encrypt_as_de(dat, de_key)
                     enc_record[de_k] = enc_dat_de
                     new_record_keys.discard(k)

                  if "abe_pol" in m:
                     if debug:
                        print("{}: {}".format(k,m["abe_pol"]), flush=True)
                     abe_k = "cpabe_"+k
                     enc_dat_abe = encrypt_as_cpabe(dat,m["abe_pol"], cpabe_pk)
                     enc_record[abe_k] = enc_dat_abe
                     new_record_keys.discard(k)
               except KeyboardInterrupt:
                  raise KeyboardInterrupt
               except:
                  # traceback.print_exc()
                  # print()
                  continue
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            # traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass


   record_keys.clear()
   record_keys.extend(new_record_keys)


def default_match(enc_record:dict, record_keys:list, record:dict, enc_policy, de_key, cpabe_pk, debug=False):
   # if we can not enc using deff policy for any field in record_keys return false, sefety measure

   new_record_keys = set(record_keys) # create new object and dont change original YET

   try:
    
      try:
         want_de = _to_bool(enc_policy["de_encrypt"])
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except KeyError:
         want_de = False
      for k in record_keys:
         try:
            dat = record[k]

            if want_de:
               de_k = "de_"+k
               enc_dat_de = encrypt_as_de(dat, de_key)
               enc_record[de_k] = enc_dat_de
               new_record_keys.discard(k)

            if "abe_pol" in enc_policy:
               abe_pol = enc_policy["abe_pol"]
               if debug:
                  print("{}: {}".format(k,abe_pol), flush=True)
               abe_k = "cpabe_"+k
               enc_dat_abe = encrypt_as_cpabe(dat,abe_pol, cpabe_pk)
               enc_record[abe_k] = enc_dat_abe
               new_record_keys.discard(k)
         except KeyboardInterrupt:
            raise KeyboardInterrupt
         except:
            traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      return False


   record_keys.clear()
   record_keys.extend(new_record_keys)

   return True


def post_record(api_url, enc_record:dict, debug=False, auth=None, post=True):
   #post data to server
   if post:
      res = post_enc_data(api_url, enc_record, debug=debug, auth=auth)
      return res
   else:
      return False

def conn_to_record(conn):
   size = 1024
   record_bytes = bytes()
   try:
      while True:
         data = conn.recv(size)
         if data:
            record_bytes += data
         else:
            break
   except:
      traceback.print_exc()
      return None

   try:
      record_str = record_bytes.decode()
      # print(record_str)
      record = json.loads(record_str)
      return record
   except:
      traceback.print_exc()
      return None

def handle_client(conn, addr, max_numb_retries_post, DEBUG,other_args, auth=None, POST_DATA=True, DEBUG_WAS_POST=False):
   print("N",end="",flush=True)

   record = conn_to_record(conn)

   if not record: 
      # print("closing")
      try:
         conn.close()
      except:
         traceback.print_exc()
         pass
      finally:
         return
   print("R",end="",flush=True)

   enc_record = encrypt_record(record, **other_args)
   print("E",end="",flush=True)

   # try:
   #    conn.close()
   # except:
   #    pass

   # if not enc_record:
   #    return

   if not enc_record:
      try:
         conn.close()
      except:
         pass
      finally:
         return

   post_succ = post_record(config_collector["backend_server"]["url"], enc_record, debug=DEBUG, auth=auth, post=POST_DATA)
   if DEBUG_WAS_POST:
         print("posted?", post_succ, flush=True)

   if POST_DATA: # only retry if we are actually posting on failed
      for i in range(max_numb_retries_post):
         if post_succ:
            print("P",end="",flush=True)
            break
         else:
            print("F",end="",flush=True)
         if DEBUG:
            print("retrying to post...", flush=True)
         post_succ = post_record(config_collector["backend_server"]["url"], enc_record, debug=DEBUG, auth=auth, post=POST_DATA)
         if DEBUG_WAS_POST:
            print("posted?", post_succ, flush=True)
   
   if not post_succ:
      print("L",end="",flush=True)
      

   try:
      conn.close()
   except:
         pass
   finally:
         return

def encrypt_record(record, keychain, config_collector, 
                  SHOW_ENC_POL, DEBUG, PRINT_LEFT_KEYS, PRINT_ENCRYPTED_RECORD,
                  PRINT_INCOMING_RECORD):

   record_keys = list(record.keys()) # will be used up
   enc_record = dict()

   if PRINT_INCOMING_RECORD:
      print()
      print("="*50, flush=True)
      pprint(record)
      print("="*50, flush=True)
      # master_key_set.update(set(record_keys))
      # print("all keys:",record_keys)

   try:
      index_policy = config_collector['policy']['index']
   except:
      sys.exit("Index policy not found. Add ['policy']['index'] to configuration.")
   succ = create_indexes(enc_record, record_keys, record, index_policy , keychain["de"], debug=SHOW_ENC_POL)
   if not succ:
      print("skiping, no index created", flush=True)
      # if ONLY_ONE:
      #    break
      return None
   
   if PRINT_LEFT_KEYS:
      print("before time match:",record_keys, flush=True)
   try:
      # print("trying timestamp", flush=True)
      timestamp_policy = config_collector['policy']['timestamp']
      timestamp_match(enc_record, record_keys, record, timestamp_policy , keychain["ore"], keychain["ore_params"], debug=SHOW_ENC_POL)
      # print("tryed timestamp", flush=True)
   except KeyError:
      pass

   if PRINT_LEFT_KEYS:
      print("before exact match:", record_keys, flush=True)
   try:
      exact_policy = config_collector['policy']['exact']
      exact_match(enc_record, record_keys, record, exact_policy, keychain["de"], keychain["pk"], debug=SHOW_ENC_POL)
   except KeyError:
      pass
   
   if PRINT_LEFT_KEYS:
      print("before regex match:", record_keys, flush=True)
   try:
      regex_policy = config_collector['policy']['regex']
      regex_match(enc_record, record_keys, record, regex_policy, keychain["de"], keychain["pk"], debug=SHOW_ENC_POL)
   except KeyError:
      pass

   if PRINT_LEFT_KEYS:
      print("left for default:", record_keys, flush=True)

   try:
      default_policy = config_collector['policy']['default']
   except KeyError:
      print("WARNING: 'ALL or PUBLIC or DEFAULT' is being used as default fallback as no default policy was provided.")
      default_policy = "ALL or PUBLIC or DEFAULT"
   default_match(enc_record, record_keys, record, default_policy, keychain["de"], keychain["pk"], debug=SHOW_ENC_POL)

   if PRINT_LEFT_KEYS:
      print("fields left (should be empty):",record_keys, flush=True)


   if PRINT_ENCRYPTED_RECORD:
      print()
      print('#'*50, flush=True)
      pprint(enc_record)
      print('#'*50, flush=True)

   return enc_record


def signal_handler(sig, frame):
   global EXIT_MAINLOOP, SIGINT_COUNT
   if sig == signal.SIGINT:
      if SIGINT_COUNT >= 1:
         sys.exit("Forced exiting now...")
      print('\nExiting: waiting for threads to finish working...(Press Ctrl+c to force)', flush=True)
      EXIT_MAINLOOP = True
      SIGINT_COUNT += 1




if __name__ == "__main__":

   # parser = create_parser()
   # args = parser.parse_args()

   config_f_name = "/config.yaml"#sys.argv[1] 

   config_collector = load_yaml_file(config_f_name)
   try:
      DEBUG = config_collector["debug"]["enabled"]
   except:
      DEBUG = False

   try:
      ONLY_ONE = config_collector["debug"]["process_only_one"]
   except:
      ONLY_ONE = False

   try:
      SHOW_ENC_POL = config_collector["debug"]["show_enc_policy"]
   except:
      SHOW_ENC_POL = False

   try:
      SHOW_POL_CONFIG = config_collector["debug"]["print_policy_config"]
   except:
      SHOW_POL_CONFIG = False
   
   try:
      POST_DATA = not config_collector["debug"]["do_not_post_data"]
   except:
      POST_DATA = True

   try:
      PRINT_LEFT_KEYS = config_collector["debug"]["print_left_keys"]
   except:
      PRINT_LEFT_KEYS = False

   try:
      PRINT_ENCRYPTED_RECORD = config_collector["debug"]["print_encrypted_record"]
   except:
      PRINT_ENCRYPTED_RECORD = False

   try:
      PRINT_INCOMING_RECORD = config_collector["debug"]["print_incoming_record"]
   except:
      PRINT_INCOMING_RECORD = False
   
   try:
      DEBUG_WAS_POST = config_collector["debug"]["print_was_posted"]
   except:
      DEBUG_WAS_POST = False

   try:
      max_numb_retries_post = config_collector["backend_server"]["max_post_retries"]
      if max_numb_retries_post < 0:
         max_numb_retries_post = 0
   except:
      max_numb_retries_post = 0


   try:
      enc_worker_threads = config_collector["enc_worker_threads"]
      if enc_worker_threads <= 0:
         enc_worker_threads = 10
   except:
      enc_worker_threads = 10

   try:
      web_conn_listen = config_collector["web_conn_listen"]
      if web_conn_listen < 0:
         web_conn_listen = 0
   except:
      web_conn_listen = 0

   basic_auth = None
   try:
      basic_auth_user = config_collector["basic_auth"]["user"]
      try:
         basic_auth_pass = config_collector["basic_auth"]["pass"]
         basic_auth = (basic_auth_user, basic_auth_pass)
         print("Basic auth: enabled")
      except:
         exit("Basic auth: no password specified. Exiting.\n")
   except:
      print("Basic auth: disabled")
      basic_auth = None



   if basic_auth != None:
      if not test_auth(config_collector["kms"]["url"], basic_auth):
         exit("Test failed: KMS basic auth. quiting.")
      if not test_auth(config_collector["backend_server"]["url"], basic_auth):
         exit("Test failed: backend basic auth. quiting.")

   if not test_token(config_collector["kms"]["url"],config_collector["kms_access_key"], basic_auth):
      exit("Test failed: bad kms_access_key, KMS server could also be down.")



   key_arguments = {
                     "kms_url": config_collector["kms"]["url"],
                     "kms_access_key": config_collector["kms_access_key"],
                     "DE_key_location": config_collector["key_files"]["de"],
                     "ORE_key_location": config_collector["key_files"]["ore"],
                     "ORE_params_location": config_collector["key_files"]["ore_params"],
                     "cpabe_pk_location": config_collector["key_files"]["cpabe_pub"],
                     # uncomment sk line to get that key, not needed here 
                     # "cpabe_sk_location": config_collector["key_files"]["cpabe_secret"],
                     "auth": basic_auth
                    }
   keychain = get_all_keys(**key_arguments)

   if SHOW_POL_CONFIG:
      print("#"*21 +" config " + "#"*21, flush=True)
      pprint(config_collector)
      print("#"*50, flush=True)

   # master_key_set = set()
   # for record in honeypot_testdata:


   enc_argument = {
                     "keychain": keychain,
                     "config_collector": config_collector,
                     "SHOW_ENC_POL": SHOW_ENC_POL,
                     "DEBUG": DEBUG ,
                     "PRINT_LEFT_KEYS": PRINT_LEFT_KEYS,
                     "PRINT_ENCRYPTED_RECORD": PRINT_ENCRYPTED_RECORD,
                     "PRINT_INCOMING_RECORD": PRINT_INCOMING_RECORD
                     # "max_numb_retries_post": max_numb_retries_post
                  }

   serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   serversocket.settimeout(0.2)
   serversocket.bind(("0.0.0.0", 8080))
   serversocket.listen(web_conn_listen)

   EXIT_MAINLOOP = False
   SIGINT_COUNT = 0
   signal.signal(signal.SIGINT, signal_handler)

   print("Ready, waiting for new connetions...",flush=True)

   with ThreadPoolExecutor(max_workers=enc_worker_threads) as executor:
      while not EXIT_MAINLOOP:
         try:
            conn, addr = serversocket.accept()
         except socket.timeout:
            continue # allow to exit loop if needed
         # threading.Thread(target = handle_client,args = (conn,addr)).start()
         executor.submit(handle_client, conn, addr,max_numb_retries_post,DEBUG, enc_argument, auth=basic_auth, POST_DATA=POST_DATA, DEBUG_WAS_POST=DEBUG_WAS_POST)
         
         if ONLY_ONE:
            break
      # exiting with will have same effects as excutor shutdown
      # will raise execption if new jobs submitted
      # will wait for all queue jobs to finish, dealocate resources
      # executor.shutdown(wait=True, cancel_futures=False)
   # will get here after all threads finish

   print("",flush=True)


# todo 
# remove de as part of policy "de_encrypt"?
# add a argument parser?



# def create_parser():
#    parser = argparse.ArgumentParser(description='Collector encryption module.')

#    parser.add_argument('--user', metavar='USER', type=str, dest='auth_user',
#                        default=None,
#                        help='Basic auth for server, user. must be used with --pass (default: off)')
#    parser.add_argument('--pass', metavar='id', type=str, dest='auth_pass',
#                        default=None,
#                     help='Basic auth for server, pass')


#    return parser
