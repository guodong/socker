import matplotlib.pyplot as plt
import numpy as np

plt.rcParams.update({'font.size': 12})


labels = [str(10 * (10 - x)) for x in range(0, 10)]
comp_t = []
net_t = []
socker_comp_t = []
socker_net_t = []
for line in open('no-socker-fix.txt'):
  ts = line.split(' ')
  comp_t.append(float(ts[1]) - float(ts[0]))
  net_t.append(float(ts[2]) - float(ts[1]))

for line in open('dy.txt'):
  ts = line.split(' ')
  socker_comp_t.append(float(ts[1]) - float(ts[0]))
  socker_net_t.append(float(ts[2]) - float(ts[1]))

fig, ax = plt.subplots()
width = 0.3
x = np.arange(len(labels))
ax.bar(x - width/2*1.1, comp_t, width, label='W/o socker: Compression time')
ax.bar(x - width/2*1.1, net_t, width, bottom=comp_t,
       label='W/o socker: Network transmission time')
ax.bar(x + width/2*1.1, socker_comp_t, width, label='With socker: Compression time')
ax.bar(x + width/2*1.1, socker_net_t, width, bottom=socker_comp_t,
       label='With socker: Network transmission time')

ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.set_ylabel('Time (s)')
ax.set_xlabel('Bandwidth of s1-s3 (Mbps)')
# ax.legend(prop={'size': 11},framealpha=1)
fig.tight_layout()
plt.savefig('dy.png')
# plt.show()

t1 = sum(comp_t) + sum(net_t)
t2 = sum(socker_comp_t) + sum(socker_net_t)
print(t1/t2)

