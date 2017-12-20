def help(parser,logic,logging,args=0):
    if args:
        for k in args[0]:
            try:
                with open("parser/functions/help/" + str(k) + ".txt") as f:
                    for line in f:
                        parser.print(line[:len(line)-1])
            except IOError as e:
                parser.print(k+":command unknown")

    else:
        with open("parser/functions/help/help.txt") as f:
            for line in f:
                if line in ["\n","\r\n"]:
                    parser.print()
                else:
                    parser.print(line[:len(line)-1])
