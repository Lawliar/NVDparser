import sys
import os
import shutil
from urllib.request import urlretrieve
import zipfile
url_format = "https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{}.json.zip"
folder_name = 'datafeed'
def print_help():
    print("python downloader.py download/update")
def main():
    choice = None # 1 for a complete download 2. for incrementally addition
    start_year = 2002
    end_year = 2021
    assert(len(sys.argv) == 2)
    if(sys.argv[1] == 'update'):
        choice = 2
    elif(sys.argv[1] == 'download'):
        choice = 1
    else:
        print_help()
        exit(1)
    if choice == 1:
        if(os.path.exists(folder_name)):
            text = input("datafeed dir already exists, delete[y/n]?")
            if(text == 'y'):
                shutil.rmtree(folder_name)
                os.mkdir(folder_name)
            elif(text == 'n'):
                print("abort then, good bye.")
                exit(0)
            else:
                print("unrecognized input, good bye.")
                exit(1)
        else:
            os.mkdir(folder_name)


        for each_year in range(start_year,end_year+1):
            download_url = url_format.format(each_year)
            zip_file_name = os.path.join(".",folder_name,str(each_year)+'.zip') 
            urlretrieve(download_url,zip_file_name)
            with zipfile.ZipFile(zip_file_name,'r') as zip_f:
                zip_f.extractall(os.path.join(".",folder_name))
            os.remove(zip_file_name)
if __name__ == '__main__':
    main()
