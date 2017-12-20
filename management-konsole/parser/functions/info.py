def info(parser,logic,logging,args=0):
    if args:
        if "hid" in args.keys():
            answer = logic.get_info(args["hid"])
            for honeypot in answer.keys():
                parser.print("Honeypot: "+honeypot)
                for i in answer[honeypot].keys():
                    parser.print("    "+i+": "+str(answer[honeypot][i]))
            for h in args["hid"]:
                if h not in answer.keys():
                    parser.print(h+": did not respond")
    else:
        parser.print("No arguments passed")
