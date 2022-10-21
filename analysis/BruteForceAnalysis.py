import pandas as pd
from matplotlib import pyplot as plt
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(ROOT_DIR, 'configuration.conf') 

bruteForcepyTimings = {}

bruteForcecTimings = {}
with open('pytimings/bruteforcecrack.txt', 'r') as f:
    for line in f:
        split = line.split(':')
        split[1] = split[1].replace('\n', '')
        bruteForcepyTimings[split[0]] = float(split[1])
    f.close()

with open('c-timings/bruteforcecrack.txt', 'r') as f:
    for line in f:
        split = line.split(':')
        split[1] = split[1].replace('\n', '')
        bruteForcecTimings[split[0]] = float(split[1])
    f.close()

x,y = zip(*bruteForcepyTimings.items())
plt.plot(x,y, color = 'r', label='python')

x1,y1 = zip(*bruteForcecTimings.items())
plt.plot(x1,y1, color = 'g', label='c')

plt.xlabel("Password length")
plt.ylabel("Running time (ms)")
plt.title("Brute force approach")

plt.legend()
plt.show()

