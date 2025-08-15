from cvss import CVSS3, CVSS4
from datetime import datetime,timedelta
import numpy as np
import matplotlib.pyplot as plt
import json
from scipy.special import gammainc


# retrieve tpr from cve info
def gettpr(cve):
    s = cve.split("-")
    year = s[1]
    number = s[2]
    path = f'cves/{year}/{number[0:-3]}XXX/{cve}.json'
    fp = open(path,"r")
    info = json.load(fp)
    rsvd = datetime.fromisoformat(
        info['cveMetadata']['dateReserved'])
    pbld = datetime.fromisoformat(
        info['cveMetadata']['datePublished'])
    return (pbld-rsvd)/timedelta(days=1)

# calculate IE for CVSS 4
def IE4(vector):
    metrics = {}
    for v in vector.split("/"):
        m = v.split(":")
        metrics[m[0]] = m[1]
    metrics['AV'] = 'N'
    metrics['AC'] = 'L'
    metrics['AT'] = 'N'
    metrics['PR'] = 'N'
    metrics['UI'] = 'N'
    mvect = ""
    for k, v in metrics.items():
        mvect = mvect + f'{k}:{v}/'
    mvect = mvect[:-1]

    return CVSS4(mvect).base_score + 0.001

def Exploit(vector):
    metrics = {}
    em = {'X':0.5, 'A': 0.5, 'P': 0.75, 'U': 1}
    for v in vector.split("/"):
        m = v.split(":")
        metrics[m[0]] = m[1]
    if 'E' in metrics:
        v = em[metrics['E']]
    else:
        v = 1
    return v

# calculate IE for CVSS 3.1
def IE3(vector):
    metrics = {}
    for v in vector.split("/"):
        m = v.split(":")
        metrics[m[0]] = m[1]
    metrics['AV'] = 'N'
    metrics['AC'] = 'L'
    metrics['PR'] = 'N'
    metrics['UI'] = 'N'
    mvect = ""
    for k, v in metrics.items():
        mvect = mvect + f'{k}:{v}/'
    mvect = mvect[:-1]

    # print(mvect, CVSS4(mvect).base_score)
    # print(vector, CVSS4(vector).base_score)

    return CVSS3(mvect).scores()[0] + 0.001

# exponential distribution model
def exmodel(tpr, l, ie, lbl):
    x = np.linspace(-tpr, 4*tpr, 500)
    y = ie * (1 - np.exp(-l * (x + tpr))) 
    plt.plot(x, y, label=lbl)

# gamma distribution model
def gamma(tpr, cvss4, ie, r, lbl):
    #lg = 2 * l
    #k = r*tpr*lg+1
    k = 10 - (ie - cvss4)
    lg = (k-1)/(r*tpr)
    x = np.linspace(-tpr, 4*tpr, 500)
    y = ie * gammainc(k, lg*(x+tpr))
    plt.plot(x, y, label=lbl, linestyle="dashed")

def gamma3(tpr, l, ie, lbl):
    k = tpr*l+1
    x = np.linspace(-tpr, 4*tpr, 500)
    y = ie * gammainc(k, l*(x+tpr))
    plt.plot(x, y, label=lbl, linestyle="dashed")

cves = [
    {"cve":"CVE-2022-41741",
    "vector4":"CVSS:4.0/AV:L/AC:L/AT:P/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    "vector3":"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H"},

    {"cve":"CVE-2020-3549",
     "vector3":"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
     "vector4":"CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N/E:U"},

    {"cve":"CVE-2014-0160",
     "vector3":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "vector4":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A"},

    {"cve":"CVE-2021-44228",
     "vector3":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
     "vector4":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A"},

    {"cve":"CVE-2023-3089",
     "vector3": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
     "vector4": "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:L/VA:L/SC:N/SI:N/SA:N"
    },

    {"cve":"CVE-2021-44714",
     "vector3":"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
     "vector4":"CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:A/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N"
    },

    {"cve":"CVE-2022-21830",
     "vector3":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
     "vector4":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:A/VC:N/VI:N/VA:N/SC:L/SI:L/SA:N"

    }
]

for n in range(len(cves)):
    cve = cves[n]["cve"]
    vector3 = cves[n]["vector3"]
    vector4 = cves[n]["vector4"]

    tpr = gettpr(cve)
    print(cve, tpr)
    
    cvss4 = CVSS4(vector4).base_score
    r = Exploit(vector4)
    ie4 = IE4(vector4)
    l4 = - np.log(1 - cvss4/ie4)/tpr

    cvss3 = CVSS3(vector3).scores()[0]
    ie3 = IE3(vector3)
    l3 = - np.log(1 - cvss3/ie3)/tpr
    
    print(vector4,cvss4)
    print(vector3,cvss3)
    print(cvss4, ie4)
    print(cvss3, ie3)

    exmodel(tpr, l4, ie4, "Exp. CVSS 4")
    exmodel(tpr, l3, ie3, "Exp. CVSS 3.1")
    gamma(tpr, cvss4, ie4, r, "Gamma CVSS 4")
    gamma3(tpr, l3, ie3, "Gamma CVSS 3.1")

    plt.xlabel("time(days)")
    plt.ylabel("score")
    plt.ylim(0,10)
    plt.grid()
    plt.legend()
    #plt.show()
    plt.savefig(f'{cve}.png',bbox_inches='tight', pad_inches=0)
    plt.clf()