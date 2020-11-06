#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")

import jsonlines
from tqdm import tqdm
import yaml
import re

from pprint import pprint
import traceback

def _to_bool(st):
   trues = ["t","true", "True"]
   try:
      if type(st) == bool :
         return st
      if type(st) == str and st in trues:
         return True
      else:
         False
   except:
      return False

def load_yaml_file(f_name:str):
   with open(f_name) as f:
      print("Loading data from {}...".format(f_name))
      data = yaml.load(f, Loader=yaml.FullLoader)
   return data

def load_json_file(f_name:str):
   with jsonlines.open(f_name) as reader:
      print("Loading data from {}...".format(f_name))
      dat = list()
      for line in tqdm(reader):
         dat.append(line["data"])
   return dat


def match_re_to_keys(reg:str, keys:list):
   r = re.compile(reg)
   newlist = list(filter(r.match, keys))
   # if len(newlist) > 0:
   #    print("reg: {}".format(repr(reg)))
   #    print("OG keys: {}".format(keys))
   #    print("matched keys [{}]: {}".format(repr(reg),newlist))
   return newlist


def encrypt_as_de(dat):
   return "DE_encrypted"
def encrypt_as_timestamp(dat):
   return "ORE_encrypted"
def encrypt_as_cpabe(dat, policy);
   return "CPABE_encrypted_{}".format(policy.replace(' ',"_"))

def create_indexes(enc_record:dict, record_keys:list, record:dict, enc_policy):
   # pprint(enc_policy)
   index_created = False

   record_keys = set(record_keys) # create new object and dont change original

   # create index for exact matches
   try:
      for m in enc_policy["exact"]:
         try:
            k = m["match"]
            dat = record[k]
            enc_dat = encrypt_as_de(dat)
            try:
               enc_record["index"].append(enc_dat)
               record_keys.discard(k)
               index_created = index_created or True
            except :
               enc_record["index"] = list()
               enc_record["index"].append(enc_dat)
               record_keys.discard(k)
               index_created = index_created or True
         except:
            # traceback.print_exc()
            continue
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
                  enc_dat = encrypt_as_de(dat)
                  try:
                     enc_record["index"].append(enc_dat)
                     record_keys.discard(k)
                     index_created = index_created or True
                  except:
                     enc_record["index"] = list()
                     enc_record["index"].append(enc_dat)
                     record_keys.discard(k)
                     index_created = index_created or True
               except:
                  continue
         except:
            traceback.print_exc()
            continue
   except:
      # traceback.print_exc()
      pass

   # if we can not create index for any of the matching record return false, sefety measure
   return index_created


def timestamp_match(enc_record:dict, record_keys:list, record:dict, enc_policy):
   # pprint(enc_policy)

   record_keys = set(record_keys) # create new object and dont change original

   # create index for exact matches
   try:
      for m in enc_policy["exact"]:
         try:
            k = m
            dat = record[k]
            enc_dat = encrypt_as_timestamp(dat)
            try:
               enc_record["timestamp"].append(enc_dat)
               record_keys.discard(k)
            except :
               enc_record["timestamp"] = list()
               enc_record["timestamp"].append(enc_dat)
               record_keys.discard(k)
         except:
            # traceback.print_exc()
            continue
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
                  enc_dat = encrypt_as_timestamp(dat)
                  try:
                     enc_record["timestamp"].append(enc_dat)
                     record_keys.discard(k)
                  except:
                     enc_record["timestamp"] = list()
                     enc_record["timestamp"].append(enc_dat)
                     record_keys.discard(k)
               except:
                  continue
         except:
            traceback.print_exc()
            continue
   except:
      # traceback.print_exc()
      pass



def exact_match(enc_record:dict, record_keys:list, record:dict, enc_policy):

   new_record_keys = set(record_keys) # create new object and dont change original

   try:
      for m in enc_policy:
         try:
            k = m["match"]
            dat = record[k]

            if _to_bool(m["remove"]):
               new_record_keys.discard(k)
               continue

            want_de = _to_bool(m["de_encrypt"])
            if want_de:
               de_k = "de_"+k
               enc_dat_de = encrypt_as_de(dat)
               enc_record[de_k] = enc_dat_de
               new_record_keys.discard(k)

            if "abe_pol" in m:
               abe_k = "cpabe_"+k
               enc_dat_abe = encrypt_as_cpabe(dat,m["abe_pol"])
               enc_record[abe_k] = enc_dat_abe
               new_record_keys.discard(k)

         except:
            # traceback.print_exc()
            continue
   except:
      # traceback.print_exc()
      pass


   record_keys.clear()
   record_keys.extend(new_record_keys)


def regex_match(enc_record:dict, record_keys:list, record:dict, enc_policy):

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

                  want_de = _to_bool(m["de_encrypt"])
                  if want_de:
                     de_k = "de_"+k
                     enc_dat_de = encrypt_as_de(dat)
                     enc_record[de_k] = enc_dat_de
                     new_record_keys.discard(k)

                  if "abe_pol" in m:
                     abe_k = "cpabe_"+k
                     enc_dat_abe = encrypt_as_cpabe(dat,m["abe_pol"])
                     enc_record[abe_k] = enc_dat_abe
                     new_record_keys.discard(k)
               except:
                  continue

         except:
            # traceback.print_exc()
            continue
   except:
      # traceback.print_exc()
      pass


   record_keys.clear()
   record_keys.extend(new_record_keys)


def default_match(enc_record:dict, record_keys:list, record:dict, enc_policy):
   # if we can not enc using deff policy for any field in record_keys return false, sefety measure
   numb_matched = 0
   return True, numb_matched
   return False, numb_matched

def post_record(enc_record:dict):
   print('#'*50)
   pprint(enc_record)
   #post data do server
   return True




# org_abac_attributes = {
#     "UNRCSE": ["UNR", "CICIAffiliate", "Research"],
#     "UNRRC": ["UNR", "ITOps", "Research"],
#     "UNRCISO": ["UNR", "SecEng", "ITOPS", "CICIAffiliate"],
#     "Public": ["Research"]
# }

# https://stackoverflow.com/questions/3640359/regular-expressions-search-in-list/39593126



if __name__ == "__main__":

   config_f_name = "./config.yaml"#sys.argv[1] 
   data_f_name = "./tahoe-honeypot.jsonl"

   config_collector = load_yaml_file(config_f_name)
   honeypot_testdata = load_json_file(data_f_name)


   pprint(config_collector)

   # master_key_set = set()
   for record in honeypot_testdata:
      record_keys = list(record.keys()) # will be used up
      enc_record = dict()

      # master_key_set.update(set(record_keys))
      # print("all keys:",record_keys)

      succ = create_indexes(enc_record, record_keys, record, config_collector['policy']['index'])
      if not succ:
         # print("skiping no index created")
         continue
      

      timestamp_match(enc_record, record_keys, record, config_collector['policy']['timestamp'])

      exact_match(enc_record, record_keys, record, config_collector['policy']['exact'])

      regex_match(enc_record, record_keys, record, config_collector['policy']['regex'])

      succ, numb_matched_def = default_match(enc_record, record_keys, record, config_collector['policy']['default'])
      if not succ:
         print("skipping")
         continue


      # post_succ = post_record(enc_record)
  


   # pprint(master_key_set)





