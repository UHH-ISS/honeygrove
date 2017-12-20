def log(parser,logic,logging,args=0):
    if args:
        options = args.keys()
        if "freq" in options:
            try:
                sec = int(args["freq"][0])
                logging.freq = sec
            except:
                parser.print("-freq: "+str(args["freq"][0])+" could not cast to integer")
        if "k" in options:
            if "o" in options:
                operator = args["o"][0]
            else:
                operator = []
            if "f" in options:
                filename = args["f"][0]
            else:
                filename = None
            logging.new_task(args["k"],operator,filename)
        if "e" in options:
            for n in args["e"]:
                try:
                    i = int(n)
                except:
                    parser.print(n+": could not cast to integer")
                    continue
                r = logging.end_task(i)
                if r:
                    parser.print("Loggingtask:"+n+" terminated")
                else:
                    parser.print("Loggingtask:"+n+" could not be terminated")
    else:
        logging.print_tasks()
