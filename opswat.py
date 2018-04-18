import requests
import hashlib
import sys
import json

#Header for api key
headers = {'apikey':'ea0ef10476510cfa50a49d37741959a0'} 
if len(sys.argv) != 2:
 sys.exit('Error: Incorrect arguments\nUsage: opswat.py "filename"')
#calculate hash of the given samplefile.txt
hash = hashlib.sha256()
filename = sys.argv[1]
with open(filename, 'rb') as f:
    for buffer in iter(lambda: f.read(4096), b""):
        hash.update(buffer)
url = 'https://api.metadefender.com/v2/hash/' + hash.hexdigest()

#Perform a hash lookup against metadefender.opswat.com and 
#see if their are previously cached results for the file
g = requests.get(url, headers=headers)
g.raise_for_status()

#if length was less than 2, unsuccessful scan requests
#could not find a better way to determine an unsuccessful requests
#since both successful and unsuccessful requests returned status code 200
if(len(g.json()) < 2):
    #if results not found upload the file, recieve a data_id
    files = {'file': open('samplefile.txt', 'rb')}
    r = requests.post('https://api.metadefender.com/v2/file', headers=headers, files=files)
    r.raise_for_status()
    rjson = r.json()
    print(rjson['data_id'])
    
    #Repeatedly pull on the data_id to retrieve results
    url = 'https://api.metadefender.com/v2/file/' + rjson['data_id']
    r = requests.get(url, headers=headers)
    r.raise_for_status()
    print('UPLOADING FILE....')
    rjson =r.json()
    while(rjson['scan_results']['progress_percentage'] != 100):
        url = 'https://api.metadefender.com/v2/file/' + rjson['data_id']
        r = requests.get(url, headers=headers)
        r.raise_for_status()
        rjson =r.json()
    print('UPLOAD COMPLETE\n')
    #Print results
    print('filename:', rjson['file_info']['display_name'])
    print('overall_status:', rjson['scan_results']['scan_all_result_a'], '\n')
    for key, value in rjson['scan_results']['scan_details'].items():
        print('engine:', key)
        x = 'clean' if value['threat_found'] == '' else value['threat_found']
        print('threat_found:', x)
        print('scan_result:', value['scan_result_i'])
        print('def_time:', value['def_time'], '\n')
#Hash for file found so print results
else:
    print('Previously cached results found for file\n')
    gjson = g.json()
    print('filename:', gjson['file_info']['display_name'])
    print('overall_status:', gjson['scan_results']['scan_all_result_a'], '\n')
    for key, value in gjson['scan_results']['scan_details'].items():
        print('engine:', key)
        x = 'clean' if value['threat_found'] == '' else value['threat_found']
        print('threat_found:', x)
        print('scan_result:', value['scan_result_i'])
        print('def_time:', value['def_time'], '\n')



