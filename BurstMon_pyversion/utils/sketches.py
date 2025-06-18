# 包驱动+时间驱动
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

    
def hashings_index(d,w,hash_functions,x):
    if len(hash_functions) != d:
            raise ValueError("len(hash_functions) do not match d!")
    index = []
    for i in range(d):
        index.append(hash_functions[i](x) % w)
    return index 
    

class TimeSketch: # 3 time-sketch记录连续两个时间窗口的值
    def __init__(self,d,w,hash_functions,timestep) -> None:
        self.d = d
        self.w = w    
        self.timestep = timestep 
        
        self.V = np.zeros([d,w],dtype=np.uint32)
        self.t = np.zeros([d,w],dtype=np.uint32)
        self.hash_functions = hash_functions




    def Update(self,delta,t,index):
        for i in range(self.d):
            for j in index:
                if self.t[i][j] == t: 
                    self.V[i][j] = self.V[i][j]+ delta 
                else:
                    self.V[i][j] = delta
                    self.t[i][j] = t 

    def Query(self,index):
        ret = []
        for i in range(self.d):
            for j in index:
                ret.append(self.V[i][j])
        ret_t =[]
        for i in range(self.d):
            for j in index:
                ret_t.append(self.t[i][j])
        
        return min(ret),min(ret_t)
    
class CMSketch: # 
    def __init__(self,d,w,hash_functions,timestep) -> None:
        self.d = d
        self.w = w    
        self.timestep = timestep 
        if len(hash_functions) != self.d:
            raise ValueError("len(hash_functions) do not match d!")
        self.V = np.zeros([d,w],dtype=np.uint32)
        self.hash_functions = hash_functions


    def Update(self,delta,index):
        for i in range(self.d):
            for j in index:
                self.V[i][j] = self.V[i][j]+ delta 

    def Query(self,index):
        ret = []
        for i in range(self.d):
            for j in index:
                ret.append(self.V[i][j])
        
        return min(ret)
