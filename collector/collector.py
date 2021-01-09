#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")
from de import RSADOAEP
from ORE import *
from cpabew import CPABEAlg
from web_client import get_de_key, get_ore_key, get_cpabe_pub_key, get_org_cpabe_secret, post_enc_data
from priv_common import load_yaml_file

from tqdm import tqdm
import re
from dateutil import parser
from datetime import datetime
import pickle
# import threading
import socket
from concurrent.futures.thread import ThreadPoolExecutor
import signal
import json

from pprint import pprint
import traceback

DEBUG_POLICY_PARCER = False

def _to_bool(st):
   trues = ["t","true", "True"]
   try:
      if type(st) == bool :
         return st
      if type(st) == str and st in trues:
         return True
      else:
         False
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      return False

def _str_to_epoch(some_time_str, debug=False):
   # parse dates without knwoing format
   # https://stackoverflow.com/a/30468539/12044480
   t = parser.parse(some_time_str)
   unix = t.timestamp()
   if debug:
      print("Time:", t, "unix:",unix, flush=True)
   return int(unix)


def match_re_to_keys(reg: str, keys: list, debug=False):
   r = re.compile(reg)
   newlist = list(filter(r.match, keys))
   if debug and len(newlist) > 0:
      print("reg: {}".format(repr(reg)), flush=True)
      print("OG keys: {}".format(keys), flush=True)
      print("matched keys [{}]: {}".format(repr(reg),newlist), flush=True)
   return newlist


def encrypt_as_de(dat,key):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "DE_encrypted"
   else:
      try:
         enc_alg = RSADOAEP(key_sz_bits=2048, rsa_pem=key)
         dat = str(dat).encode("UTF-8")
         return enc_alg.encrypt(dat)
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         return None
def encrypt_as_timestamp(dat,key, debug=False):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "ORE_encrypted"
   else:
      try:
         if type(dat) != int:
            dat = _str_to_epoch(dat)
         if type(dat) == int and dat > 0:
            return OREComparable.from_int(dat,key).get_cipher_obj().export()
         else:
            return None
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # if debug:
         #    traceback.print_exc()
         traceback.print_exc()
         return None

def encrypt_as_cpabe(dat, policy, pk):
   global DEBUG_POLICY_PARCER
   if DEBUG_POLICY_PARCER:
      return "CPABE_encrypted_{}".format(policy.replace(' ',"_"))
   else:
      try:
         bsw07 = CPABEAlg()
         # data_to_enc = str(dat).encode("UTF-8")
         data_to_enc = pickle.dumps(dat)
         return bsw07.cpabe_encrypt_serialize(pk, data_to_enc, policy)
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         traceback.print_exc()
         return None

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
               print("{}: {}".format(k,"DE"), flush=True)
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
                     print("{}: {}".format(k,"DE"), flush=True)
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
            traceback.print_exc()
            continue
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except:
      # traceback.print_exc()
      pass

   # if we can not create index for any of the matching record return false, sefety measure
   return index_created


def timestamp_match(enc_record:dict, record_keys:list, record:dict, enc_policy, key, debug=False):
   # pprint(enc_policy)

   record_keys = set(record_keys) # create new object and dont change original

   # create index for exact matches
   try:
      for m in enc_policy["exact"]:
         try:
            k = m
            dat = record[k]
            enc_dat = encrypt_as_timestamp(dat, key)
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
                  enc_dat = encrypt_as_timestamp(dat, key)
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


def post_record(api_url, enc_record:dict, debug=False):
   if debug:
      print('#'*50, flush=True)
      pprint(enc_record)
      print('#'*50, flush=True)
   #post data to server
   return post_enc_data(api_url, enc_record, debug=debug)




# org_abac_attributes = {
#     "UNRCSE": ["UNR", "CICIAffiliate", "Research"],
#     "UNRRC": ["UNR", "ITOps", "Research"],
#     "UNRCISO": ["UNR", "SecEng", "ITOPS", "CICIAffiliate"],
#     "Public": ["Research"]
# }

# https://stackoverflow.com/questions/3640359/regular-expressions-search-in-list/39593126
def load_fetch_de_key(kms_url, DE_key_location):
   try:
      k = open(DE_key_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         de_key = get_de_key(kms_url, debug=False)
         if de_key == None:
            sys.exit("Could not fetch DE key from KMS server({})".format(kms_url))
         return de_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # traceback.print_exc()
         sys.exit("Could not fetch DE key from KMS server({})".format(kms_url))
      open(DE_key_location, "wb").write(de_key)
      return 
   sys.exit("Could not load or fetch DE key")

def load_fetch_ore_key(kms_url, ORE_key_location):
   try:
      k = open(ORE_key_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         ore_key = get_ore_key(kms_url)
         if ore_key == None:
            sys.exit("Could not fetch ORE key from KMS server({})".format(kms_url))
         return ore_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # traceback.print_exc()
         sys.exit("Could not fetch ORE key from KMS server({})".format(kms_url))
      open(ORE_key_location, "wb").write(ore_key)
      return 
   sys.exit("Could not load or fetch ORE key")

def load_fetch_cpabe_pk(kms_url, cpabe_pk_location):
   try:
      k = open(cpabe_pk_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         pk_key = get_cpabe_pub_key(kms_url,debug=True)
         if pk_key == None:
            sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
         return pk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key from KMS server({})".format(kms_url))
      open(cpabe_pk_location, "wb").write(pk_key)
      return 
   sys.exit("Could not load or fetch CPABE Public Key")

def load_fetch_cpabe_sk(kms_url, name, cpabe_sk_location):
   try:
      k = open(cpabe_sk_location, "rb").read()
      return
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except FileNotFoundError:
      try:
         sk_key = get_org_cpabe_secret(kms_url,name)
         if sk_key == None:
            sys.exit("Could not fetch CPABE Public Key({}) from KMS server({})".format(name,kms_url))
         return sk_key
      except KeyboardInterrupt:
         raise KeyboardInterrupt
      except:
         # traceback.print_exc()
         sys.exit("Could not fetch CPABE Public Key({}) from KMS server({})".format(name,kms_url))
      open(cpabe_sk_location, "wb").write(sk_key)
      return 
   sys.exit("Could not load or fetch CPABE Secret Key({})".format(name))

def get_all_keys(kms_url, name, DE_key_location, ORE_key_location, cpabe_pk_location, cpabe_sk_location):
   de = load_fetch_de_key(kms_url,DE_key_location)
   ore = load_fetch_ore_key(kms_url,ORE_key_location)
   abe_pk = load_fetch_cpabe_pk(kms_url,cpabe_pk_location)
   # abe_sk = load_fetch_cpabe_sk(kms_url,name, cpabe_sk_location)

   return {
            "de": de,
            "ore": ore,
            "pk": abe_pk#,
            # "sk": abe_sk
         }

def decrypt_cpabe(ciphertext, pk, sk):
   try:
      bsw07 = CPABEAlg()
      return bsw07.cpabe_decrypt_deserialize(pk, sk, ciphertext)
   except KeyboardInterrupt:
      raise KeyboardInterrupt
   except Exception:
      # failed to decrypt
      return None
   except:
      traceback.print_exc()
      return None


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

def handle_client(conn, addr, max_numb_retries_post, DEBUG,other_args):
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

   if not enc_record:
      try:
         conn.close()
      except:
         pass
      finally:
         return


   post_succ = post_record(config_collector["backend_server"]["url"], enc_record, debug=DEBUG)
   if DEBUG:
         print("posted?", post_succ, flush=True)
   for i in range(max_numb_retries_post):
      if post_succ:
         print("P",end="",flush=True)
         break
      if DEBUG:
         print("retrying to post...", flush=True)
      post_succ = post_record(config_collector["backend_server"]["url"], enc_record, debug=DEBUG)
      if DEBUG:
         print("posted?", post_succ, flush=True)

   try:
      conn.close()
   except:
         pass
   finally:
         return

def encrypt_record(record, keychain, config_collector, SHOW_ENC_POL, DEBUG):

   record_keys = list(record.keys()) # will be used up
   enc_record = dict()

   if DEBUG:
      print("="*50, flush=True)
      pprint(record)
      print("="*50, flush=True)
      # master_key_set.update(set(record_keys))
      # print("all keys:",record_keys)

   succ = create_indexes(enc_record, record_keys, record, config_collector['policy']['index'], keychain["de"], debug=SHOW_ENC_POL)
   if not succ:
      print("skiping, no index created", flush=True)
      # if ONLY_ONE:
      #    break
      return None
   
   if DEBUG:
      print(record_keys, flush=True)
   timestamp_match(enc_record, record_keys, record, config_collector['policy']['timestamp'], keychain["ore"], debug=SHOW_ENC_POL)
   
   if DEBUG:
      print(record_keys, flush=True)

   exact_match(enc_record, record_keys, record, config_collector['policy']['exact'], keychain["de"], keychain["pk"], debug=SHOW_ENC_POL)
   
   if DEBUG:
      print(record_keys, flush=True)

   regex_match(enc_record, record_keys, record, config_collector['policy']['regex'], keychain["de"], keychain["pk"], debug=SHOW_ENC_POL)

   if DEBUG:
      print(record_keys, flush=True)

   default_match(enc_record, record_keys, record, config_collector['policy']['default'], keychain["de"], keychain["pk"], debug=SHOW_ENC_POL)

   if DEBUG:
      print(record_keys, flush=True)


   return enc_record


def signal_handler(sig, frame):
   global EXIT_MAINLOOP, SIGINT_COUNT
   if sig == signal.SIGINT:
      if SIGINT_COUNT >= 1:
         sys.exit("Forced exiting now...")
      print('\nExiting: waiting for threads to finish working...(Press Ctrl+c to force)', flush=True)
      EXIT_MAINLOOP = True
      SIGINT_COUNT += 1


   
   # if ONLY_ONE:
   #    break

   # print(".", end="", flush=True)
# print(flush=True)
# print(decrypt_cpabe(enc_record["cpabe_offset"], keychain["pk"], keychain["sk"]))
# pprint(master_key_set)


if __name__ == "__main__":
   # todo: add arguemnt parser   
   #        force keep keys
   #     autoremove keys on exit

   config_f_name = "./config.yaml"#sys.argv[1] 

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

   key_arguments = {
                     "kms_url": config_collector["kms"]["url"],
                     "name": config_collector["name"],
                     "DE_key_location": config_collector["key_files"]["de"],
                     "ORE_key_location": config_collector["key_files"]["ore"],
                     "cpabe_pk_location": config_collector["key_files"]["cpabe_pub"],
                     "cpabe_sk_location": config_collector["key_files"]["cpabe_secret"]
                    }
   keychain = get_all_keys(**key_arguments)

   if DEBUG:
      print("#"*21 +" config " + "#"*21, flush=True)
      pprint(config_collector)
      print("#"*50, flush=True)

   # master_key_set = set()
   # for record in honeypot_testdata:


   enc_argument = {
                     "keychain": keychain,
                     "config_collector": config_collector,
                     "SHOW_ENC_POL": SHOW_ENC_POL,
                     "DEBUG": DEBUG #,
                     # "max_numb_retries_post": max_numb_retries_post
                  }

   serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
   serversocket.settimeout(0.2)
   serversocket.bind(("0.0.0.0", 8080))
   serversocket.listen(web_conn_listen)

   EXIT_MAINLOOP = False
   SIGINT_COUNT = 0
   signal.signal(signal.SIGINT, signal_handler)

   print("Waiting for new connetions...",flush=True)

   with ThreadPoolExecutor(max_workers=enc_worker_threads) as executor:
      while not EXIT_MAINLOOP:
         try:
            conn, addr = serversocket.accept()
         except socket.timeout:
            continue # allow to exit loop if needed
         # threading.Thread(target = handle_client,args = (conn,addr)).start()
         executor.submit(handle_client, conn, addr,max_numb_retries_post,DEBUG, enc_argument)
         
         if ONLY_ONE:
            break
      # exiting with will have same effects as excutor shutdown
      # will raise execption if new jobs submitted
      # will wait for all queue jobs to finish, dealocate resources
      # executor.shutdown(wait=True, cancel_futures=False)
   # will get here after all threads finish

   print("",flush=True)


# todo 
# support missing values in policy parcer
# if get attribuets, then only fetch valid attributes and display them to user
# remove de as part of policy "de_encrypt"
# add debug when removing "SHOW_ENC_POL"