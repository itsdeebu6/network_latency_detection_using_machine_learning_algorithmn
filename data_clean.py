import pandas as pd
import sys
from functools import reduce

def from_string(s):
  s=str(s)
  "Convert dotted IPv4 address to integer."
  return reduce(lambda a,b: a<<8 | b, map(int, s.split(".")))

def to_string(ip):
  "Convert 32-bit integer to dotted IPv4 address."
  return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))

filename = sys.argv[1]

file1 = pd.read_csv(filename)
file1.head(10)
file1.isnull().sum

# step-1 to replace all empty/null to be empty
update_file = file1.fillna(" ")
update_file.isnull().sum()
update_file.to_csv('update_'+filename, index = False)

# step-2 to remove all rows with empty value
update_file = file1.fillna(0)
print (update_file.isnull().sum())
update_file['tcp.flags'] = update_file['tcp.flags'].apply(lambda  x: int(str(x), 16))
#update_file['ip.src']=update_file['ip.src'].apply(lambda x: from_string(x))
#update_file['ip.dst']=update_file['ip.dst'].apply(lambda x: from_string(x))
update_file.to_csv('update_'+filename, index = False)