import os
import json
import csv
from datetime import datetime, timezone

base = "../cvelistV5/cves/2024" # 入力データのディレクトリ
#data = {"cves": []} # 結果格納のための変数
data = [] # 結果格納のための変数
for group in os.listdir(base): # サブディレクトリについて繰り返し
    dir = os.path.join(base,group)
    for file in os.listdir(dir): # サブディレクトリ内のファイルについて繰り返し
        path = os.path.join(dir,file)
        with open(path) as cveFile: # ファイルを開いて
            cve = json.load(cveFile) # JSON形式のデータを読み込む
            # 公開済みの脆弱性情報でかつ CNA 情報を含むもを対象にする．
            if cve['cveMetadata']['state'] == "PUBLISHED" and 'metrics' in cve['containers']['cna']:
                # 予約時刻の取り出し
                cveDateRsvd = cve['cveMetadata']['dateReserved']
                cveDateRsvd = cveDateRsvd[:-1] if cveDateRsvd[-1:] == "Z" else cveDateRsvd
                dateRsvd = datetime.fromisoformat(cveDateRsvd)
                # 公開時刻の取り出し
                cveDatePbld = cve['cveMetadata']['datePublished']
                cveDatePbld = cveDatePbld[:-1] if cveDatePbld[-1:] == "Z" else cveDatePbld
                datePbld = datetime.fromisoformat(cveDatePbld)
                    # メトリック情報を持たない場合を除外
                cveMetrics = cve['containers']['cna']['metrics']
                for metric in cveMetrics:
                    # CVSS 3.1 情報を持つ場合のみ
                    if 'cvssV3_1' in metric:
                        # 情報を結果に追加する
                        item = {}
                        item["cveId"] = cve['cveMetadata']['cveId']
                        # if 'title' in cve['cveMetadata']:
                        #     item["desc"] = cve['cveMetadata']['title']
                        # elif 'descriptions' in cve['containers']['cna']:
                        #     item["desc"] = cve['containers']['cna']['descriptions'][0]["value"]
                        item["dateRsvd"] = dateRsvd.timestamp()
                        item["datePbld"] = datePbld.timestamp()
                        item["timeRP"] = (datePbld - dateRsvd).total_seconds()/3600/24
                        item["cvssVector"] = metric['cvssV3_1']['vectorString']
                        item["cvssScore"] = metric['cvssV3_1']['baseScore']
                        data.append(item)
# 処理結果をファイルに出力する
data.sort(key=lambda k: int(k["cveId"].split("-")[2]))
with open("data2024.csv", "w") as f:
    writer = csv.writer(f)
    for item in data:
        writer.writerow([
            item["cveId"],
            item["dateRsvd"],
            item["datePbld"],
            item["timeRP"],
            item["cvssVector"],
            item["cvssScore"],
            ])
