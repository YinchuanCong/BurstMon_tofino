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




def cosine_similarity(s1: pd.Series, s2: pd.Series) -> float:
    if len(s1) != len(s2):
        raise ValueError("Series no the same length!")
    
    dot_product = np.dot(s1, s2)
    
    norm_s1 = np.linalg.norm(s1)
    norm_s2 = np.linalg.norm(s2)
    
    return dot_product / (norm_s1 * norm_s2)


def mse(s1: pd.Series, s2: pd.Series,k=1) -> float:
    if len(s1) != len(s2):
        raise ValueError("Series no the same length!")
    
    return (((s1 - s2)*1.0/k) ** 2).mean()

def euclidean_distance(s1: pd.Series, s2: pd.Series,k=1) -> float:
    if len(s1) != len(s2):
        raise ValueError("Series no the same length!")
    return np.sqrt((((s1 - s2)*1.0*k) ** 2).sum())




def energy_cal(x: pd.Series,y:pd.Series) -> float:
    t1 = np.linalg.norm(x)
    t2 = np.linalg.norm(y)
    if t1 > t2:
        return t2/t1
    else:
        return t1/t2