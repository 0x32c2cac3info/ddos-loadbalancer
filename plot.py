#!/usr/bin/python3

import numpy as np
import matplotlib.pyplot as plt

global file

def draw_curve(rate='fast', defense=False):
    filename = "{}{}".format(rate, "-defense" if defense else "")
    df = np.genfromtxt("results/{}.txt".format(filename))
    if df.size > 0:
	    plt.plot(df[:, 0], df[:, 1], color=('b' if defense else 'r'), \
	             linewidth=1, linestyle='-', marker='', \
	             label=('with defense' if defense else 'without defense'))
	    file.write("{} {} {} {}\n".format(rate, defense, df[:, 1].mean(), df[:, 1].var()))



def draw_plot(rate):
    for f in [False, True]:
        draw_curve(rate, f)
    plt.grid()
    plt.xlabel('Time, s')
    plt.ylabel('State count')
    plt.legend(loc='best')
    plt.savefig('figures/{}.pdf'.format(rate))
    plt.close()


if __name__ == "__main__":
    file = open('results/stats.txt', 'w')
    rates = ['zero', 'fast', 'faster', 'flood']
    for r in rates:
        draw_plot(r)
    file.close()
