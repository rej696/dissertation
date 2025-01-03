import itertools
import matplotlib.pyplot as plt
from matplotlib.ticker import (MultipleLocator, FormatStrFormatter, FuncFormatter)

# def format_time(instant, _):
#     if instant < 60:
#         return f"{instant:g}s"
#     minutes, seconds = divmod(instant, 60)
#     return f"{minutes:g}m {seconds:02g}s"

def format_time(instant, _):
    if instant < 60:
        return f"{instant:g}s"
    minutes, seconds = divmod(instant, 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    return f"{days:g}d {hours:02g}h"

def format_percent(value, _):
    return f"{int(value)}%"

def plot(filename, time, percentages):
    fig, ax = plt.subplots()

    ax.set_xlabel("Time")
    ax.set_ylabel("Instruction Coverage")

    ax.set_xlim(0, time[-1])
    ax.set_ylim(65, 100)

    # Make x-axis with major ticks that
    # are multiples of 11 and Label major
    # ticks with '% 1.2f' formatting
    # ax.xaxis.set_major_locator(MultipleLocator(1000))
    ax.xaxis.set_major_formatter(FuncFormatter(format_time))

    # make x-axis with minor ticks that
    # are multiples of 1 and label minor
    # ticks with '% 1.2f' formatting
    ax.yaxis.set_minor_locator(MultipleLocator(10))
    ax.yaxis.set_minor_formatter(FuncFormatter(format_percent))

    ax.plot(time, percentages)
    # time_formatter = FuncFormatter(format_time)
    # plt.xaxis.set_major_formatter(time_formatter)
    # plt.plot(time, percentages)
    plt.tight_layout()
    plt.savefig(filename)


def main(filename):
    times = []
    coverages = []
    with open(filename, "r") as f:
        for time, coverage in itertools.zip_longest(*[f]*2):
            times.append(int(time)/1000)
            coverages.append(float(coverage))
            print(f"{time.strip()}: {coverage.strip()}%")

    plot(filename.split(".")[0], times, coverages)



if __name__ == "__main__":
    main("241219_raw_cov_sanitised.log")
    main("241219_grammar_cov_sanitised.log")
