import sys, os
sys.path.append(os.path.abspath(__file__ + "/.."))

from PrepareES.PrepareES import readyToMap

if __name__ == '__main__':

    # Start the mapping process
    print('\033[94m'+"Start Mapping..."+'\033[0m')
    readyToMap()
