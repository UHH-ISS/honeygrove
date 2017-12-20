def config(parser, logic, logging, args=0):
    if args:
        options = args.keys()
        if "hid" in options and "sid" in options:
            if "p" in options:
                if args["sid"][0] != "LISTEN" and len(args["sid"]) > 1:
                    parser.print("More than one port passed")
                    return
                ports = []
                for p in args["p"]:
                    try:
                        port = int(p)
                    except:
                        parser.print(str(p) + ": could not cast to integer")
                        return
                    if port in range(0, 65535):
                        ports.append(port)
                    else:
                        parser.print(str(port) + ": no valid port number")
            if "tp" in options: 
                try:
                    tp = float(args["tp"][0])
                except:
                    parser.print(args["tp"][0]+": could not cast to float")
                    return
            configs = logic.get_service_config(args["hid"], args["sid"][0])
            for honeypot in args["hid"]:
                if honeypot not in configs.keys():
                    parser.print(honeypot + ": no settings recieved")
            for honeypot in configs.keys():
                if "p" in options:
                    configs[honeypot]["ports"] = ports
                else:
                    configs[honeypot]["ports"] = ""
                if "tp" in options:
                    configs[honeypot]["token_probability"] = tp
                else:
                    configs[honeypot]["token_probability"] = ""
                answer = logic.send_service_config(honeypot, configs[honeypot])
                if answer:
                    parser.print("Response from: " + honeypot)
                    for setting in answer:
                        parser.print("New configuration: " + str(answer[setting]))
                else:
                    parser.print(honeypot+": no confirmation recieved")
        else:
            parser.print("not all necessary arguments passed")
    else:
        parser.print("No arguments passed")
