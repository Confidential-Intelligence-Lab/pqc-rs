#!/usr/bin/env python3
import argparse,csv,math,statistics
from pathlib import Path
def load(p):
 c=([],[])
 with p.open(newline='',encoding='utf-8') as f:
  for r in csv.DictReader(f): c[int(r['class'])].append(float(r['nanoseconds']))
 return c
def trim(v):
 v=sorted(v); n=int(len(v)*.01); return v[n:-n] if n else v
def t(a,b):
 d=math.sqrt(statistics.variance(a)/len(a)+statistics.variance(b)/len(b)); return 0 if d==0 else (statistics.fmean(a)-statistics.fmean(b))/d
p=argparse.ArgumentParser();p.add_argument('csv',type=Path);a=p.parse_args();x,y=load(a.csv);r=t(x,y);q=t(trim(x),trim(y));m=max(abs(r),abs(q));
print(f'class 0 n={len(x)} mean={statistics.fmean(x):.2f} ns median={statistics.median(x):.2f} ns');print(f'class 1 n={len(y)} mean={statistics.fmean(y):.2f} ns median={statistics.median(y):.2f} ns');print(f'raw Welch t: {r:.4f}');print(f'trimmed Welch t: {q:.4f}');print('classification: '+('strong timing-class separation' if m>=10 else 'timing signal requiring investigation' if m>=4.5 else 'no timing signal detected at this sample size'))
