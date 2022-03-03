import pandas as pd

df = pd.read_csv("/home/deepak/share_path/pcaps/update_train2.csv")

if 'type' not in df.columns:
    df["type"] = ""

for index, row in df.iterrows():
    print (index)
    
    if int(df['tcp.analysis.retransmission'].values[index]) == 1.0:
        df.loc[index, 'type'] = 'packet_loss'
    elif int(df['tcp.analysis.duplicate_ack'].values[index]) == 1.0:
        df.loc[index, 'type'] = 'latency'
    elif float(df['tcp.analysis.ack_rtt'].values[index]) > 0.200:
        df.loc[index, 'type'] = 'latency'
    elif float(df['tcp.time_delta'].values[index]) > 0.200:
        df.loc[index, 'type'] = 'latency'
    else:
        df.loc[index, 'type'] = 'Normal'

df.to_csv("/home/deepak/share_path/pcaps/update_train2_2.csv", index=False)