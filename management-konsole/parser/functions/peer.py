def peer(parser,logic,logging,args=0):
    if args:
        if "ip" in args.keys() and "p" in args.keys():
            ip = args["ip"][0]
            try:
                port = int(args["p"][0])
            except:
                parser.print(args["p"][0]+": could not be cast to integer")
                return
            if "hid" in args.keys():
                answer = logic.honeypot_peer(args["hid"],ip,port)
                for honeypot in answer.keys():
                    parser.print(honeypot+" peered to ip:"+answer[honeypot][0]+" port:"+str(answer[honeypot][1]))
                for h in args["hid"]:
                    if h not in answer.keys():
                        parser.print(h+": did not respond")
            else:
                if logic.connect(ip,port):
                    parser.print("Peered to ip:"+ip+" port:"+str(port))
                else:
                    parser.print("Could not peer to ip:"+ip+" port:"+str(port))
        else:
            parser.print("Not all necessary parameters passed")
    else:
        parser.print("No Arguments passed")
