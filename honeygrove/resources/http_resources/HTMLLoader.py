import pickle
import honeygrove

#Loading and saving of HTTP Site Dictionary
import os


def save_HTMLDictionary(obj):
    with open(honeygrove.__path__._path[0] + '/resources/http_resources/' + 'HTMLDictionary.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)

def load_HTMLDictionary():
    with open(honeygrove.__path__._path[0] + '/resources/http_resources/' + 'HTMLDictionary.pkl', 'rb') as f:
        return pickle.load(f)
