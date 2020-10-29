#!/usr/bin/env python3

import jsonlines
from tqdm import tqdm
import sys

import yaml
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



# org_abac_attributes = {
#     "UNRCSE": ["UNR", "CICIAffiliate", "Research"],
#     "UNRRC": ["UNR", "ITOps", "Research"],
#     "UNRCISO": ["UNR", "SecEng", "ITOPS", "CICIAffiliate"],
#     "Public": ["Research"]
# }




if __name__ == "__main__":

   config_f_name = "./config.yaml"#sys.argv[1] 
   data_f_name = "./tahoe-honeypot.jsonl"

   config_collector = load_yaml_file(config_f_name)
   # honeypot_testdata = load_json_file(data_f_name)

   pprint(config_collector)