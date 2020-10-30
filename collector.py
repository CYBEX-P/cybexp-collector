#!/usr/bin/env python3

import sys
sys.path.append("/priv-libs/libs")

import jsonlines
from tqdm import tqdm
import yaml
import re
from pprint import pprint


def load_yaml_file(f_name):
   with open(f_name) as f:
      print("Loading data from {}...".format(f_name))
      data = yaml.load(f, Loader=yaml.FullLoader)
   return data

def load_json_file(f_name):
   with jsonlines.open(f_name) as reader:
      print("Loading data from {}...".format(f_name))
      dat = list()
      for line in tqdm(reader):
         dat.append(line["data"])
   return dat




def create_indexes(enc_record, record_keys, record, enc_policy):
   # if we can not create index for any of the matching record return false, sefety measure
   return False


def timestamp_match(enc_record, record_keys, record, enc_policy):
   pass

def exact_match(enc_record, record_keys, record, config_collector.policy.exact):
   pass

def regex_match(enc_record, record_keys, record, config_collector.policy.regex):
   pass

def default_match(enc_record, record_keys, record, config_collector.policy.regex):
   # if we can not enc using deff policy for any field in record_keys return false, sefety measure
   return False

def post_record(enc_record):
   #post data do server





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

   for record in honeypot_testdata:
      record_keys = record.keys() # will be used up
      enc_record = dict()

      succ = create_indexes(enc_record, record_keys, record, config_collector.policy.index)
      if not succ:
         continue

      timestamp_match(enc_record, record_keys, record, config_collector.policy.exact)

      exact_match(enc_record, record_keys, record, config_collector.policy.exact)

      regex_match(enc_record, record_keys, record, config_collector.policy.regex)

      succ = default_match(enc_record, record_keys, record, config_collector.policy.regex)
      if not succ:
         continue

      if numb_matched_pol == len(record_keys):
         post_record(enc_record)
      else:
         continue









