import sys
from time import sleep
use_ui = not (len(sys.argv)>1 and sys.argv[1] == "-cli")

#use_ui = False  #zum debuggen

if use_ui:
    try:
        from parser.ui import Ui
    except:
        use_ui = False
else:
    try:
        import readline #input history
    except:
        pass
from parser.parser import Parser
from logic.logic import Logic
from logging.logging import Logging

logic = Logic()
logging = Logging(logic)

parser = Parser(logic,logging)

if len(sys.argv) > 1 and sys.argv[1] != "-cli":
    logging.start()
    parser.default_script()
    sleep(0.1) #wait for pybroker connection
    parser.print(">".join(sys.argv[1:]))
    parser.parse(" ".join(sys.argv[1:]))
    if sys.argv[1] == "log":
        print("Press enter to end logging")
        input()
elif use_ui:
    ui = Ui()
    ui.logging = logging
    logging.ui = ui
    parser.ui = ui
    ui.parser = parser
    ui.start()
else:
    run = True
    logging.start()
    if parser.default_script():
        while run:
            i = input(">")
            run = parser.parse(i)
