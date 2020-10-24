import json
import os
from IPython import embed

vendor_name = "linux"
product_name = "linux_kernel"

CWEs = ["CWE-125","CWE-787","CWE-190","CWE-191","CWE-192","CWE-193","CWE-194","CWE-195","CWE-196","CWE-197","CWE-128","CWE-369","CWE-468"]
result = {} 
for each_cwe in CWEs:
    result[each_cwe] = set()

def process_cpe(cpe):
    if 'cpe_match' in cpe:
        return True,cpe["cpe_match"]
    else:
        if ('children' not in cpe):
            return False, []
        return False, cpe['children']

total_num_cve = set()
for each_file in os.listdir("datafeed"):
    filename = os.path.join(".","datafeed",each_file)
    if not filename.endswith(".json"):
        continue
    with open(filename) as f:
        data = json.load(f)
        for each_cve in data["CVE_Items"]:
            CVE_num = each_cve["cve"]["CVE_data_meta"]["ID"]
            ## cpe
            cpe_match = False
            cpes = each_cve["configurations"]["nodes"]
            for each_cpe in cpes:
                match, to_do = process_cpe(each_cpe)
                if match:
                    for each_match in to_do:
                        uri  = each_match["cpe23Uri"]
                        uri = uri.split(":")
                        vendor = uri[3]
                        product = uri[4]
                        if(product_name == product and vendor_name == vendor):
                            cpe_match = True
                            break
                else:
                    cpes += to_do
                if cpe_match:
                    break
            ## CWE
            if(cpe_match):
                total_num_cve.add(CVE_num)
            cwe_list = each_cve["cve"]["problemtype"]["problemtype_data"]
            for each_cwe in cwe_list:
                descs = each_cwe["description"]
                for cwe in descs:
                    cwe = cwe["value"]
                    if cwe in CWEs:
                        if cpe_match:
                            result[cwe].add(CVE_num)
print("finished..")
total = set()
for each_cwe in result:
    for each_cve in result[each_cwe]:
        total.add(each_cve)
embed()
