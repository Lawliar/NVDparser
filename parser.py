import json
import os
from IPython import embed

vendor_name = "linux"
product_name = "linux_kernel"

#CWEs = ["CWE-125","CWE-787","CWE-190","CWE-191","CWE-192","CWE-193","CWE-194","CWE-195","CWE-196","CWE-197","CWE-128","CWE-369","CWE-468"]
CWEs = ["CWE-190"]


def process_cpe(cpe):
    if 'cpe_match' in cpe:
        return True,cpe["cpe_match"]
    else:
        if ('children' not in cpe):
            return False, []
        return False, cpe['children']

def is_cpe_match(each_cve,vendor_name,product_name):
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
                    return True
        else:
            cpes += to_do
    return False

def is_cwe_match(each_cve, CWEs):
    cwe_list = each_cve["cve"]["problemtype"]["problemtype_data"]
    for each_cwe in cwe_list:
        descs = each_cwe["description"]
        for cwe in descs:
            cwe = cwe["value"]
            if cwe in CWEs:
                return True
    return False

def get_cvss_score(each_cve):
    if(len(list(each_cve["impact"])) == 0):
        return None, None
    if("baseMetricV2" in each_cve["impact"]):
        exploit_score  = float(each_cve["impact"]['baseMetricV2']["exploitabilityScore"])
        impact_score = float(each_cve["impact"]['baseMetricV2']["impactScore"])
    else:
        exploit_score  = float(each_cve["impact"]['baseMetricV3']["exploitabilityScore"])
        impact_score = float(each_cve["impact"]['baseMetricV3']["impactScore"])
    return exploit_score, impact_score

if __name__ == "__main__":
    result = []
    for each_file in os.listdir("datafeed"):
        filename = os.path.join(".","datafeed",each_file)
        if not filename.endswith(".json"):
            continue
        with open(filename) as f:
            print("process", filename)
            data = json.load(f)
            for each_cve in data["CVE_Items"]:
                CVE_num = each_cve["cve"]["CVE_data_meta"]["ID"]
                # cpe
                cpe_match = is_cpe_match(each_cve,vendor_name,product_name)
                # cwe
                cwe_match = is_cwe_match(each_cve, CWEs)
                # CVSS
                exploit, impact = get_cvss_score(each_cve)
                if cwe_match and cpe_match:
                    result.append(CVE_num)
    print("finished")
    embed()
