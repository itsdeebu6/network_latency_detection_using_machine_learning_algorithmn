import matplotlib
import matplotlib.pyplot as plt
import pandas as pd
import numpy as np
import seaborn as sns
import sklearn
import imblearn
import pickle
import os
from mlxtend.plotting import plot_decision_regions


import warnings
warnings.filterwarnings('ignore')

from sklearn.preprocessing import StandardScaler
from sklearn.preprocessing import MinMaxScaler
scaler = StandardScaler()

# Settings
pd.set_option('display.max_columns', None)
np.set_printoptions(threshold=np.inf, linewidth=np.nan)
np.set_printoptions(precision=3)
sns.set(style="darkgrid")
plt.rcParams['axes.labelsize'] = 14
plt.rcParams['xtick.labelsize'] = 12
plt.rcParams['ytick.labelsize'] = 12

print("pandas : {0}".format(pd.__version__))
print("numpy : {0}".format(np.__version__))
print("matplotlib : {0}".format(matplotlib.__version__))
print("seaborn : {0}".format(sns.__version__))
print("sklearn : {0}".format(sklearn.__version__))
print("imblearn : {0}".format(imblearn.__version__))

df_train = pd.read_csv("/home/deepak/share_path/pcaps/update_train1.csv")

print('Train set dimension: {} rows, {} columns'.format(df_train.shape[0], df_train.shape[1]))

df_train.drop(['ip.src'], axis=1, inplace=True)
df_train.drop(['ip.dst'], axis=1, inplace=True)

df_train = df_train[df_train['ip.proto'] == 6]

df_train.round(3)

print('Train set dimension after clean up: {} rows, {} columns'.format(df_train.shape[0], df_train.shape[1]))


type_class_freq_train = df_train[['type']].apply(lambda x: x.value_counts())
type_class_freq_train['frequency_percent_train'] = round((100 * type_class_freq_train / type_class_freq_train.sum()),2)


# Type class bar plot
plt.plot(type_class_freq_train[['frequency_percent_train']])
plt.title("Type Class Distribution", fontsize=20)
plt.grid(color='lightgray', alpha=0.5)
plt.show()


y_train = df_train['type']
X_train = df_train.drop('type',axis=1)
#sc = StandardScaler()
#X_train = sc.fit_transform(X_train)


from sklearn.svm import SVC 
from sklearn.naive_bayes import BernoulliNB 
from sklearn import tree
from sklearn.model_selection import cross_val_score
from sklearn.neighbors import KNeighborsClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import VotingClassifier
from sklearn.tree import DecisionTreeClassifier


# Train KNeighborsClassifier Model
KNN_Classifier = KNeighborsClassifier(n_jobs=-1)
print ("KNN classifier train score : " + str(KNN_Classifier.fit(X_train, y_train).score(X_train, y_train)))
filename = "knn_model.sav"
try:
    os.remove(filename)
except:
    print("Unable to delete or file not found: " + filename)

pickle.dump(KNN_Classifier, open(filename, 'wb'))


