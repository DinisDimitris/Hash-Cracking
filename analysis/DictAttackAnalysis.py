from matplotlib import pyplot as plt

bruteForcepyTimings = {}

bruteForcecTimings = {}
with open('pytimings/dictcrack.txt', 'r') as f:
    for line in f:
        split = line.split(':')
        split[1] = split[1].replace('\n', '')
        bruteForcepyTimings[split[0]] = float(split[1])
    f.close()

with open('c-timings/dictcrack.txt', 'r') as f:
    for line in f:
        split = line.split(':')
        split[1] = split[1].replace('\n', '')
        bruteForcecTimings[split[0]] = float(split[1])
    f.close()

x,y = zip(*bruteForcepyTimings.items())
plt.plot(x,y, color = 'r', label='python')

x1,y1 = zip(*bruteForcecTimings.items())
plt.plot(x1,y1, color = 'g', label='c')

plt.xlabel("Number of passwords")
plt.ylabel("Running time (ms) ")
plt.title("Dictionary attack")

plt.legend()
plt.show()

