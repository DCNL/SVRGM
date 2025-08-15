# data = [ "CVSS:3.1", "AV:N", "AC:L", "PR:N", "UI:N", "S:U", "C:H" ]
data = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H"
print(data.split(":/"))
#print({k:v for (k,v) in data.split(":") })