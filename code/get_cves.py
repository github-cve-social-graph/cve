import pymongo
import requests
import time
from datetime import datetime

from pymongo import MongoClient
client = MongoClient('mongodb+srv://erinszeto:Fall2020CKIDS!@erincluster.mvldp.mongodb.net/test')

db = client.ckids
collections = db.collection_names()
if "cve" in collections: # If collection has been made already and exists
    db.cve.drop() # drop/delete collection

cve = db.cve # make collection

## Retrieve first 2000 CVEs with "github" keyword
url = "https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=0&keyword=github&resultsPerPage=2000"
response = requests.get(url).json()

total_results = response["totalResults"]
cves = response["result"]["CVE_Items"] #list of CVE dictionaries/JSON

# Get metadata (current time, api URL)
def get_metadata(cves, url):
    time = datetime.utcnow().strftime("%a %b %d %H:%M:%S UTC %Y") # Current time in UTC
    metadata = {"date_accessed": time, "api_url": url}
    for item in cves:
        item["metadata"] = metadata
    return cves

cves = get_metadata(cves, url)
cves_id = cve.insert_many(cves).inserted_ids

index = 2000
while (index < total_results):
    time.sleep(10)

    url = "https://services.nvd.nist.gov/rest/json/cves/1.0?startIndex=%s&keyword=github&resultsPerPage=2000" % str(index)
    response = requests.get(url).json()
    
    cves = response["result"]["CVE_Items"] # list of CVE dictionaries/JSON
    cves = get_metadata(cves, url) # insert metadata

    cves_id = cve.insert_many(cves).inserted_ids

    index += 2000