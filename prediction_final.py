import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
import sklearn
import imblearn
import pickle
import os
from fnmatch import fnmatch
import pandas as pd
import sys
from functools import reduce

from py2neo import Graph, Node, Relationship
from neo4j import GraphDatabase
import openpyxl as xl

import warnings
warnings.filterwarnings('ignore')

from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
scaler = StandardScaler()

# Settings
pd.set_option('display.max_columns', None)
np.set_printoptions(threshold=np.inf, linewidth=np.nan)
np.set_printoptions(precision=3)
sns.set(style="darkgrid")
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 12
plt.rcParams['ytick.labelsize'] = 12

print("pandas : {0}".format(pd.__version__))
print("numpy : {0}".format(np.__version__))
print("matplotlib : {0}".format(matplotlib.__version__))
print("seaborn : {0}".format(sns.__version__))
print("sklearn : {0}".format(sklearn.__version__))
print("imblearn : {0}".format(imblearn.__version__))

neo4jGraph = Graph(host="192.168.1.73", auth=("neo4j", "123")) 
# Database Credentials
uri = "bolt://192.168.1.73:7687"
userName = "neo4j"
password = "123"

def from_string(s):
  s=str(s)
  "Convert dotted IPv4 address to integer."
  return reduce(lambda a,b: a<<8 | b, map(int, s.split(".")))

def to_string(ip):
  "Convert 32-bit integer to dotted IPv4 address."
  return ".".join(map(lambda n: str(ip>>n & 0xFF), [24,16,8,0]))

 
# Connect to the neo4j database server
graphDB_Driver = GraphDatabase.driver(uri, auth=(userName, password))
cql1 = "match (a) -[r] -> () delete a, r"
cql2 = "match (a) delete a"

# Execute the CQL query
with graphDB_Driver.session() as graphDB_Session:
    nodes = graphDB_Session.run(cql1)
    nodes = graphDB_Session.run(cql2)

graphDB_Driver.close()

root = '/home/deepak/share_path/pcaps/Lab_captures'
pattern = "*.pcap"



dataset_filename = "dataset.csv"
dataset_cleanup = "dataset_clean.csv"

os.system("rm -rf " + dataset_filename)
os.system("rm -rf " + dataset_cleanup)
os.system("touch completed_file.txt")

for path, subdirs, files in os.walk(root):
    for name in files:
        if fnmatch(name, pattern):
            pcap_file_path = (os.path.join(path, name))
            print (pcap_file_path)
            file1 = open("completed_file.txt", "r")
            readfile = file1.read()
            file1.close()
            if pcap_file_path in readfile: 
                print(pcap_file_path + ': Already prediction completed')
            else: 
                os.system("tshark -r "+pcap_file_path+" -T fields -E header=y -E separator=, -E quote=d -E occurrence=f -e ip.src -e ip.dst -e ip.proto -e tcp.flags -e tcp.analysis.ack_rtt -e frame.time_delta -e tcp.time_delta -e tcp.analysis.duplicate_ack -e tcp.analysis.retransmission -e tcp.analysis.fast_retransmission -e tcp.analysis.spurious_retransmission -e tcp.analysis.lost_segment> " + dataset_filename)
                file1 = pd.read_csv(dataset_filename)
                file1.head(10)
                file1.isnull().sum

                # step-1 to replace all empty/null to be empty
                update_file = file1.fillna(" ")
                update_file.isnull().sum()
                update_file.to_csv(dataset_cleanup, index = False)

                # step-2 to remove all rows with empty value
                update_file = file1.fillna(0)
                print (update_file.isnull().sum())
                update_file['tcp.flags'] = update_file['tcp.flags'].apply(lambda  x: int(str(x), 16))
                #update_file['ip.src']=update_file['ip.src'].apply(lambda x: from_string(x))
                #update_file['ip.dst']=update_file['ip.dst'].apply(lambda x: from_string(x))
                update_file.to_csv(dataset_cleanup, index = False)
                f = open('completed_file.txt', 'w')
                f.write(pcap_file_path+'\n')  # python will convert \n to os.linesep
                f.close()


                df_test = pd.read_csv(dataset_cleanup)

                print('Test set dimension: {} rows, {} columns'.format(df_test.shape[0], df_test.shape[1]))


                df_test = df_test[df_test['ip.proto'] == 6]

                df_test.round(3)

                ip_source_list = df_test["ip.src"].tolist()
                ip_source_list = list(set(ip_source_list))


                for src_ip in ip_source_list:
                    df_source_ip_test = df_test[df_test['ip.src'] == src_ip]
                    if "192.168." in src_ip:
                        continue
                    ip_dst_list = df_source_ip_test["ip.dst"].tolist()
                    ip_dst_list = list(set(ip_dst_list))
                    df_to_test = ""
                    for dst_ip in ip_dst_list:
                        df_to_test = df_source_ip_test[df_source_ip_test["ip.dst"] == dst_ip]
                        if "192.168." in dst_ip:
                            continue
                        print("----------------------------------")
                        print(df_to_test['ip.src'].value_counts())
                        print(df_to_test['ip.dst'].value_counts())

                        source_ip = df_to_test['ip.src'].values[0]
                        destination_ip = df_to_test['ip.dst'].values[0]
                        total_packet = df_to_test.shape[0]



                        df_to_test.drop(['ip.src'], axis=1, inplace=True)
                        df_to_test.drop(['ip.dst'], axis=1, inplace=True)

                        X_test = df_to_test

                        #sc = MinMaxScaler()
                        #X_test = sc.fit_transform(X_test)
                        from sklearn import metrics
                        models = []
        
                        KNN_Classifier = pickle.load(open("/home/deepak/ai_temp_scripts/knn_model.sav", 'rb'))
                        models.append(('KNeighborsClassifier', KNN_Classifier))

                        firstNode = Node("Host", name=source_ip)
                        secondNode = Node("Host", name=destination_ip)

                        for i, v in models:
                            predicted = v.predict(X_test)
                            predicted_df = pd.DataFrame()
                            predicted_df["Predicted_value"] = pd.DataFrame(predicted)
                            print (predicted_df)
            
                            predicated_class_freq_test = predicted_df[['Predicted_value']].apply(lambda x: x.value_counts())
                            predicated_class_freq_test['frequency_percent_predicted'] = round((100 * predicated_class_freq_test / predicated_class_freq_test.sum()),2)



                            predicted_class_dist = pd.concat([predicated_class_freq_test], axis=1) 
                            print (predicted_class_dist)


                            predicated_classification = str(predicted_class_dist)

          

                            # Predicated vs Test class plot
                            #plt.bar(type_vs_predict_class_dist[['frequency_percent_predicted', 'frequency_percent_test']])
                            """plot = type_vs_predict_class_dist[['frequency_percent_predicted', 'frequency_percent_test']].plot(kind="bar")
            
                            plot.set_title("Actual Vs Predicted " + source_ip + "->" + destination_ip, fontsize=20)
                            plot.grid(color='lightgray', alpha=0.5)
                            plt.show()"""        
            

                            if i == "KNeighborsClassifier":
             
                                try:
                                    latency_value = predicated_class_freq_test.loc["latency", "frequency_percent_predicted"]
                                except:
                                    latency_value = 0
                                    print ("Latency not found")

                                try:
                                    normal_value = predicated_class_freq_test.loc["Normal", "frequency_percent_predicted"]
                                except:
                                    normal_value = 0
                                    print ("Normal not found")

                                try:
                                    packet_loss_value = predicated_class_freq_test.loc["packet_loss", "frequency_percent_predicted"]
                                except:
                                    packet_loss_value = 0
                                    print ("packet loss not found")
                
                
                                if packet_loss_value > 30:
                                    SENDpl = Relationship.type("packetloss")
                                    neo4jGraph.merge(SENDpl(firstNode, secondNode), "Host", "name")
                                elif latency_value > normal_value and latency_value > packet_loss_value:
                                    SENDla = Relationship.type("latency")
                                    neo4jGraph.merge(SENDla(firstNode, secondNode), "Host", "name")


