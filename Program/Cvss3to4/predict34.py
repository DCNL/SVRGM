import pandas as pd
from sklearn.metrics import mean_absolute_error
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeRegressor  



# CVSS 3.1
encode3 = {
    "AV": {"N": 0.85, "A":0.62, "L":0.55, "P":0.2},
    "AC": {"L": 0.77, "H":0.44},
    "PR": {"N": 0.85, "L":0.62, "H":0.27},
    "UI": {"N": 0.85, "R":0.62},
    "S": {"U":0, "C":1},
    "C": {"N":0, "L":0.22, "H":0.56},
    "I": {"N":0, "L":0.22, "H":0.56},
    "A": {"N":0, "L":0.22, "H":0.56},
    "E": {"X":1, "U":0.91, "P":0.94, "F":0.97, "H":1}
}
# CVSS 4.0
encode4 = {
    "AV": {"N":4, "A":3, "L":2, "P":1},
    "AC": {"L":2, "H":1},
    "AT": {"N":2, "P":1},
    "PR": {"N":3, "L":2, "H":1},
    "UI": {"N":3, "P":2, "A":1},
    "VC": {"H":3, "L":2, "N":1},
    "VI": {"H":3, "L":2, "N":1},
    "VA": {"H":3, "L":2, "N":1},
    "SC": {"H":3, "L":2, "N":1},
    "SI": {"H":3, "L":2, "N":1},
    "SA": {"H":3, "L":2, "N":1},
    "E": {"X":4, "A":3, "P":2, "U":1}
}

# CVSSのベクトルを数値化して辞書としてまとめる関数
def v2d(vect):
    metrics = vect[9:].split("/")
    ver = vect[5:8]
    d = {}
    for metric in metrics:
        kv = metric.split(":")
        match ver:
            case "3.1":
                d[kv[0]] = encode3[kv[0]][kv[1]]
            case "4.0":
                d[kv[0]] = encode4[kv[0]][kv[1]]                            
    return d

# CVS形式の学習データをデータフレームとして読み込む
inputPath = "./cvss3and4.csv"
data = pd.read_csv(inputPath)
# データフレームを入力(3.1)と出力(4.0)に分けて，数値化する
cvss3 = pd.json_normalize(data["Cvss3.1"].apply(v2d)).fillna(0)
cvss4 = pd.json_normalize(data["Cvss4.0"].apply(v2d)).fillna(0)
# それぞれのデータフレームを学習用と検証用に分ける
trainX, valX, trainY, valY = train_test_split(cvss3, cvss4)

# 決定木のモデルを作成して，学習する
model = DecisionTreeRegressor()
model.fit(trainX, trainY)

# 学習済みのモデルに検証用のデータ(3.1)を入れて，4.0の値を予測する．
predY = pd.DataFrame(data=model.predict(valX),index=valY.index,columns=valY.columns)

def calc3to4(vect):
    metrics = vect[9:].split("/")
    d = {}
    e = None
    scope = False
    for metric in metrics:
        kv = metric.split(":")
        match kv[0]:
            case "CVSS":
                pass
            case "AV"|"PR":
                d[kv[0]] = encode4[kv[0]][kv[1]]
            case "AC":
                d["AC"] = encode4[kv[0]][kv[1]]
                d["AT"] = encode4["AT"]["N"]
            case "UI":
                if kv[1] == "N":
                    d["UI"] = encode4["UI"]["N"]
                else:
                    d["UI"] = encode4["UI"]["P"]
            case "S":
                scope = (kv[1] == "C")
            case "C"|"I"|"A":
                d[f"V{kv[0]}"] = encode4["VC"][kv[1]]
            case "E":
                match kv[1]:
                    case "X"|"U"|"P":
                        e = encode4["E"][kv[1]]
                    case _:
                        e = encode4["E"]["X"]
    for metric in ["C", "I", "A"]:
        if scope:
            d[f"S{metric}"] = d[f"V{metric}"]
        else:
            d[f"S{metric}"] = encode4["SC"]["N"]
    if e != None:
        d["E"] = e
    return d
                    
calcd4 = pd.json_normalize(data["Cvss3.1"].apply(calc3to4)).fillna(0)
calcd4 = pd.DataFrame(calcd4,index=valX.index)

def n2m(num):
    return int(num+0.5)

predY = predY.map(n2m)
#print(valY)
#print(predY)
#print(calcd4)

for met in valY.columns:
    print(f"{met}:{mean_absolute_error(valY[met], predY[met])}")
print(mean_absolute_error(valY, predY))
print(mean_absolute_error(valY, calcd4))
