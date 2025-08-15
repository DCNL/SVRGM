import os
import re
import json
import csv

cveListPath = "../cvelistV5/cves"
outputPath = "cvss3and4.csv"

output = open(outputPath, mode="w", newline="")
writer = csv.writer(output)
for root, dirs, files in os.walk(cveListPath):
    for file in files:
        if re.match("CVE-[0-9]+-[0-9]+.json",file):
            with open(f"{root}/{file}") as f:
                cveData = json.load(f)
                try:
                    cveID = cveData["cveMetadata"]["cveId"]
                    metrics = cveData["containers"]["cna"]["metrics"]
                    for metric in metrics:
                        if "cvssV3_1" in metric and "cvssV4_0" in metric:
                            writer.writerow([
                                cveID,
                                f'{metric["cvssV3_1"]["vectorString"]}',
                                f'{metric["cvssV4_0"]["vectorString"]}'
                        ])
                except KeyError:
                    pass
output.close