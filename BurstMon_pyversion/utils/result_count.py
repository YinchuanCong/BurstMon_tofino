import pandas as pd     
import numpy as np 


def res_anaylysis(res_file,min_packetln=10,scale=1):
  res = pd.read_csv(res_file,header=1,names=['ID','packets','windowlen','cos','ed','energy'])

  res=res[res['packets']>min_packetln]

  cos = res['cos'].mean()
  ed = res['ed'].mean()
  energy = res['energy'].mean()
  # are = res['are'].mean()
  print(f'''
      cos:   {cos},
      ed:    {ed*scale},
      energy:{energy}
        ''')
