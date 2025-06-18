import pandas as pd     
import numpy as np    
import os




 
def sendtoControlList(pkt_list, score_list, ret_a_list, pre_a_list,a_list, w_list, s_list, path="hadoop15_1000_score.csv"):

    data = {
        'ID': [pkt.ID for pkt in pkt_list],
        'len': [pkt.len for pkt in pkt_list],
        't': [pkt.t for pkt in pkt_list],
        'score': score_list,
        'v_i': ret_a_list,
        'v_i_1':pre_a_list,
        'delta': a_list,
        'w': w_list,
        's': s_list
    }
    df = pd.DataFrame(data)
    
    
    df.to_csv(
        path,
        mode='a',
        header=not os.path.exists(path),
        index=False
    )