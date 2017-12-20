def start(parser,logic,logging,args=0):
    if args:
        if "hid" not in args.keys() or "sid" not in args.keys():
            parser.print ("Not all necessary arguments passed")
            return
        msgs = logic.start_service(args["hid"],args["sid"])
        for msg in msgs.keys():
            parser.print(msg + ": " + str(msgs[msg]) + " started")
    else:
        print("No arguments passed")
