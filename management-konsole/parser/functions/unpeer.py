def unpeer(parser,logic,logging,args=0):
    if args:
        if "hid" in args.keys():
            answer = logic.honeypot_unpeer(args["hid"])
            for a in answer:
                parser.print(a+" unpeered")
        for i in args[0]:
            r = logic.disconnect(int(i))
            if r:
                parser.print(i+": unpeered")
            else:
                parser.print(i+": connection could not be terminated")
    else:
        parser.print("No arguments passed")
