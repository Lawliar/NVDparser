import json
import os
from IPython import embed


vendor_product_pairs = [("linux","linux_kernel"),("microsoft","windows"),("freebsd","freebsd"),("*","android"),('*',"iphone"),('*',"mac_os")]
vendor_product_pairs = [("linux","linux_kernel")]
#CWEs = ["CWE-125","CWE-787","CWE-190","CWE-191","CWE-192","CWE-193","CWE-194","CWE-195","CWE-196","CWE-197","CWE-128","CWE-369","CWE-468"]
#CWEs = ["CWE-190","CWE-191","CWE-680"]
CWEs = ["CWE-128", "CWE-190","CWE-191","CWE-192", "CWE-193", "CWE-194", "CWE-195", "CWE-196", "CWE-197", "CWE-369", "CWE-468", "CWE-681", "CWE-682"]

def process_cpe(cpe):
    if 'cpe_match' in cpe:
        return True,cpe["cpe_match"]
    else:
        if ('children' not in cpe):
            return False, []
        return False, cpe['children']

def in_cpe_list(v,p,vp_pairs):
    for t_v, t_p in vp_pairs:
        if t_v == "*":
            ## only compare product
            if p in t_p:
                return True
        elif t_p == "*":
            if v in t_v:
                return True
        else:
            if v in t_v and p in t_p:
                return True
    return False
def is_cpe_match(each_cve,v_p_pairs):
    cpes = each_cve["configurations"]["nodes"]
    for each_cpe in cpes:
        match, to_do = process_cpe(each_cpe)
        if match:
            for each_match in to_do:
                uri  = each_match["cpe23Uri"]
                uri = uri.split(":")
                vendor = uri[3]
                product = uri[4]
                if in_cpe_list(vendor,product,v_p_pairs):
                    return True
        else:
            cpes += to_do
    return False

def is_cwe_match(each_cve, CWEs):
    matched_cwes = set()
    cwe_list = each_cve["cve"]["problemtype"]["problemtype_data"]
    for each_cwe in cwe_list:
        descs = each_cwe["description"]
        for cwe in descs:
            cwe = cwe["value"]
            if cwe in CWEs:
                matched_cwes.add(cwe)
    if(len(matched_cwes) == 0):
        return False,[]
    else:
        return True,list(matched_cwes)

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
    result_dict = {}
    result_list = []
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
                cpe_match = is_cpe_match(each_cve,vendor_product_pairs)
                # cwe
                cwe_match,matched_cwes = is_cwe_match(each_cve, CWEs)
                # CVSS
                exploit, impact = get_cvss_score(each_cve)
                # various dates
                if cwe_match and cpe_match:
                    for each_matched_cwe in matched_cwes:
                        if each_matched_cwe not in result_dict:
                            result_dict[each_matched_cwe] = [CVE_num]
                        else:
                            result_dict[each_matched_cwe].append(CVE_num)
                    result_list.append(CVE_num)
    print("finished")
    parsed_list = {}
    for each_cve in result_list:
        year = each_cve.split('-')[1]
        if(year not in parsed_list):
            parsed_list[year] = [each_cve]
        else:
            parsed_list[year].append(each_cve)

    embed()
