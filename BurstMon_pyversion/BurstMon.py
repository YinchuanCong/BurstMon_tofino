import numpy as np 
import os
import pandas as pd    
import math 
import time 
import pyecharts 
from matplotlib import pyplot as plt 
import pandas as pd 
import numpy as  np 

from pyecharts.charts import Line, Grid 
from pyecharts import options as opts
from io import StringIO
from pyecharts.globals import ThemeType
from tqdm import tqdm
import csv 

from utils.writetool import sendtoControlList
from utils.sketches import hashings_index
from utils.hashfuncs import hash_function
from utils.sketches import TimeSketch,CMSketch
from utils.metrics import cosine_similarity,mse,euclidean_distance,energy_cal,average_relative_error 
from utils.result_count import res_anaylysis

 
class DataPlane:
    def __init__(self,d,w,timestep):
        HASH_FUNCTIONS = [hash_function(i) for i in range(d)]
        self.tsk0 = TimeSketch(d,w,HASH_FUNCTIONS,timestep)
        self.tsk1 = TimeSketch(d,w,HASH_FUNCTIONS,timestep)
        self.tsk2 = TimeSketch(d,w,HASH_FUNCTIONS,timestep)
        
        self.s = CMSketch(d,w,HASH_FUNCTIONS,timestep)
        self.timestep = timestep 
        self.d = d
        self.w = w
        self.HASH_FUNCTIONS = HASH_FUNCTIONS
        
        total_bits = (self.tsk0.V.dtype.itemsize+self.tsk0.t.dtype.itemsize)*(self.tsk0.d*self.tsk0.w)+(self.tsk1.V.dtype.itemsize+self.tsk1.t.dtype.itemsize)*(self.tsk1.d*self.tsk1.w)+(self.tsk2.V.dtype.itemsize+self.tsk2.t.dtype.itemsize)*(self.tsk2.d*self.tsk2.w)+(self.s.V.dtype.itemsize)*(self.s.d*self.s.w) 
        total_KB = total_bits /8 /1024
        
        self.REGISTER_consumption = f"""
        Register Consumption:
        size:
            tsk0      :({self.tsk0.d},{self.tsk0.w})
            tsk1      :({self.tsk1.d},{self.tsk1.w})
            tsk2      :({self.tsk2.d},{self.tsk2.w})
            s         :({self.s.d},{self.s.w})

        MemCost:
            tsk0      : {(self.tsk0.V.dtype.itemsize+self.tsk0.t.dtype.itemsize)*(self.tsk0.d*self.tsk0.w)} bits, {(self.tsk0.V.dtype.itemsize+self.tsk0.t.dtype.itemsize)*(self.tsk0.d*self.tsk0.w)/1024} KB
            tsk1      : {(self.tsk1.V.dtype.itemsize+self.tsk1.t.dtype.itemsize)*(self.tsk1.d*self.tsk1.w)} bits, {(self.tsk1.V.dtype.itemsize+self.tsk1.t.dtype.itemsize)*(self.tsk1.d*self.tsk1.w)/1024} KB
            tsk2      : {(self.tsk2.V.dtype.itemsize+self.tsk2.t.dtype.itemsize)*(self.tsk2.d*self.tsk2.w)} bits, {(self.tsk2.V.dtype.itemsize+self.tsk2.t.dtype.itemsize)*(self.tsk2.d*self.tsk2.w)/1024} KB
            s      : {(self.s.V.dtype.itemsize)*(self.s.d*self.s.w)} bits, {(self.s.V.dtype.itemsize)*(self.s.d*self.s.w)/1024} KB

        Total bits: {total_bits} bits
        total KB  : {total_KB} KB
        """
        print(self.REGISTER_consumption)
        
        
    def chi_test(self,a,s,t,simulate=False):
        if a==0 or s == 0 or t ==0 or t==1:
            return 0
        if simulate == True:
            return 0
        else: 
            return abs(int(a)*int(t)-int(s))*1.0/math.sqrt(int(s+1)*(int(t)-1))
    
    def Replay(self,path='./output/websearch25_10000_delta_score.csv'):
        timeBegin = time.time()
        if os.path.exists(path):
            os.remove(path)
            
        flows = pd.read_csv("./data/websearch25.csv",header=None,names=['ID', 'len', 't', 'Flag'])
        flows['td'] = flows['t']-flows['t'][0]
        
        
        
        pkts,scores, deltas,v_is,v_i_1s,ws,ss = [],[],[],[],[],[],[]
        for i in tqdm(range(flows.shape[0])):
            pkt = flows.iloc[i]
            windowNum = int(pkt.td//self.timestep)
                
            
            index = hashings_index(self.d,self.w,self.HASH_FUNCTIONS,pkt.ID) 
            _, w = getattr(self, f"tsk{windowNum % 3}").Query(index)
            getattr(self, f"tsk{windowNum % 3}").Update(pkt.len,windowNum,index)
            
            
            if w != windowNum:
                v_i, w = getattr(self, f"tsk{(windowNum-1) % 3}").Query(index)
                v_i_1, _ = getattr(self, f"tsk{(windowNum-2) % 3}").Query(index)
                a = abs(int(v_i) - int(v_i_1))
                self.s.Update(a,index)
                s = self.s.Query(index) 
                
                score = self.chi_test(a,s,windowNum)
                pkts.append(pkt);scores.append(score);deltas.append(a);v_is.append(v_i);v_i_1s.append(v_i_1);ws.append(w);ss.append(s)
            else:
                pass 
                
            if ((i+1) %1000 == 0)   or (i == flows.shape[0]-1):
                sendtoControlList(pkts,scores,v_is,v_i_1s,deltas,ws,ss,path=path)
                pkts,scores, deltas,v_is,v_i_1s,ws,ss = [],[],[],[],[],[],[]
            
        duration = time.time()- timeBegin 
        print('End simulation..., duration: ',duration)
            
            
class ControlPlane:
    def __init__(self,T,timestep=10000,mode='linear') -> None:
        self.T = T  
        self.timestep = timestep 
        self.mode = mode 
    
    def rebuild(self,filepath = 'output/webseach25_10000_delta_score.csv',res_file='websearch25_res.csv'):
        flows = pd.read_csv(filepath,header=1,names=['ID','len','t','score','v_i','v_i_1','delta','w','s'])
        
        if os.path.exists(res_file):
            os.remove(res_file)
        with open(res_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(['ID','packets','windowlen','cos',"ed",'energy','are'])
        
        for ID in list(set(flows['ID'].tolist())):
            
            raw = pd.read_csv("./data/websearch25.csv", header=None, names=['ID', 'PacketSize', 'Time', 'a'])
            raw['Time'] = raw['Time'] - raw['Time'][0]
            raw['TimeGroup'] = (raw['Time'] // self.timestep) * self.timestep

            grouped = raw.groupby(['ID', 'TimeGroup'])['PacketSize'].sum().unstack(level=0)

            grouped = grouped[[ID]]
            id2_series = grouped[ID]

            first_valid_idx = id2_series.first_valid_index()
            last_valid_idx = id2_series.last_valid_index()
            raw_data = grouped.loc[first_valid_idx:last_valid_idx+2].copy()[ID].fillna(0)
            
            # rebuild
            flow = flows[(flows['ID'] == ID) & (flows['score'] > self.T )].copy()
            
            flow['t'] = (flow['t'] - flows['t'].iloc[0] )//self.timestep
            flow = flow[['ID','v_i','v_i_1',"w"]]
            flow = flow[flow['w']>0]
            
            if flow.shape[0] == 0:
                continue
            
            df_w_1 = pd.DataFrame({
            'ID':flow['ID'],
            'w':flow['w']-1,
            'v':flow['v_i_1']
                })

            df_w = pd.DataFrame({
                'ID':flow['ID'],
                'w':flow['w'],
                'v':flow['v_i']
            })
            df=pd.concat([df_w_1,df_w]).sort_values(by=['w']).reset_index(drop=True).drop_duplicates()
            df=df.set_index('w').sort_index()
            df['ID'] = ID
            raw_data.index = (raw_data.index//1e4).astype(int)
            full_index = sorted(set(raw_data.index).union(df.index)) 
            
            
            recovered = df['v'].copy()
            recovered = recovered.groupby(recovered.index).max() # for bug
            recovered= recovered.reindex(full_index,fill_value=np.nan)
            recovered = recovered.interpolate(methods= self.mode)
            
            
            align_raw_data = raw_data.reindex(full_index,fill_value=0)
            align_recovered = recovered.reindex(full_index,fill_value=0)
            
    
            
            cos = cosine_similarity(align_raw_data,align_recovered)
            ed = euclidean_distance(align_raw_data,align_recovered)
            energy = energy_cal(align_raw_data,align_recovered)
            are = average_relative_error(align_raw_data,align_recovered)
            packets = raw[raw['ID']==ID].shape[0]
            windowlen = grouped[[ID]].shape[0]
            
            print(ID,packets, windowlen,cos,ed,energy,are)
            
            with open(res_file, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([ID,packets,windowlen,cos,ed,energy,are])
                        
    def Commumicaiton(self,filepath):
        df = pd.read_csv(filepath,header=1,names=['ID','len','t','score','v_i','v_i_1','delta','w','s']) 
        comPacket = df[df['score']>self.T]
        
        fstring = f"""
        bitwidth:
            flow ID:      bit<32>+bit<32>+bit<16>+bit<16>+bit<8> = 104
            flow timewindow:    bit<16> = 16
            flow psize:   bit<32>+bit<32> = 64
        """
        print(fstring)

        sendedPackets = len(comPacket)
        totalPackets = len(df)
        compressRatio = 1.0*sendedPackets/totalPackets
        dura = (df['t'].iloc[-1] - df['t'].iloc[0]) // 1e6 #ms 

        commBits = sendedPackets*(184)
        commKB  =  commBits // 8 // 1024 
        fstring = f"""
        Comm packets: {sendedPackets}, total packets: {totalPackets}, Compress rate: {compressRatio:.2f}
        Comm bits: {commBits} bits = {commKB} KB
        Comm dura: {dura} ms
        CommBandwidth: {commKB*0.000258} Gbps
        
       """
        print(fstring)


if __name__ == '__main__':
    d=18
    w = 1024*4
    timestep = 1e4 
    outpacket_file = f'output/websearch25_{int(timestep)}_{d}_{w}_outpacket.csv'
    
    dataplane = DataPlane(d,w,timestep) 
    dataplane.Replay(outpacket_file)
   
    T=120
    conplane = ControlPlane(T)
    res_file = f'output/websearch25_{T}_{d}_{w}_{timestep}_res.csv'
    conplane.rebuild(outpacket_file,res_file=res_file)
    conplane.Commumicaiton(outpacket_file)
    dataplane = DataPlane(d,w,timestep) 
    res_anaylysis(res_file,min_packetln=100,scale=0.000258)
