import pymongo
from pymongo import MongoClient
import csv

client = MongoClient('mongodb+srv://erinszeto:Fall2020CKIDS!@erincluster.mvldp.mongodb.net/ckids')
db = client.ckids

pipeline = [
    { "$match": {"cve.references.reference_data.tags": "Exploit"}},
    { "$project": {
        "cve.references.reference_data.url": 1,
        "cve.references.reference_data.tags": 1}}
]

## Get list of docs that have a URL with Exploit tag
docs = list(db.cve.aggregate(pipeline))

urls = []
for doc in docs:
    for item in doc["cve"]["references"]["reference_data"]:
        if "tags" in item: # If "tags" exist for the URL, check if "Exploit" and if URL has "github.com"
            if ("Exploit" in item["tags"]) & ("github.com" in item["url"]):
                urls.append(item["url"])

## Create "repos" file with list of URLs
with open("repos", "w") as f:
    write = csv.writer(f)
    write.writerow(urls)