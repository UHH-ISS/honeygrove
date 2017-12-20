def peers(parser,logic,logging,args=0):
    if args:
        if "hid" in args.keys():
            answer = logic.honeypot_get_peering(args["hid"])
            for a in answer.keys():
                parser.print("Honeypot:"+str(a)+" peered to ip: "+str(answer[a][0])+" port:"+str(answer[a][1]))
            for h in args["hid"]:
                if h not in answer.keys():
                    parser.print(h+": did not respond")
    else:
        c_dict = logic.list_connections()
        if c_dict:
            for i in c_dict.keys():
                parser.print("Nr."+str(i)+"    "+"ip: "+c_dict[i][0]+"    "+"Port: "+str(c_dict[i][1]))
        else:
            parser.print("No peerings")

