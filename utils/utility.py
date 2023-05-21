import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

class Utility:
    @staticmethod
    def count_elements(xs):
        counts = {x: 0 for x in xs}

        for x in xs:
            counts[x] += 1

        return counts

    @staticmethod
    def most_common_element(xs):
        counts = Utility.count_elements(xs)
        return max(xs, key=counts.get)
    
    @staticmethod
    def plot_frequencies(candidate_key_bytes, path):
        count = Utility.count_elements(candidate_key_bytes)

        keys = [k for k in range(256)]
        counts = [count.get(k, 0) for k in range(256)]

        frequencies = sns.barplot(
            data=pd.DataFrame({"key": keys, "count": counts}), x="key", y="count",
        )
        frequencies.set_xticklabels(
            frequencies.get_xticklabels(), rotation=90, horizontalalignment="right"
        )

        plt.figure(figsize=(40, 8))
        plt.savefig(path)