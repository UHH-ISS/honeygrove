def ls(parser, logic, logging, args=0):
    honeylist = logic.list_honeypots()
    if args:
        options = args.keys()
    else:
        options = []
    honeypots = []
    for i in honeylist:
        if "hid" in options:  # not all honeypots
            if i in args["hid"]:
                honeypots.append(i)
        else:
            honeypots.append(i)
    for h in honeypots:
        parser.print("Honeypot:"+h)
        selected_services = None
        all_services = None
        if "sid" in options:
            selected_services = args["sid"]
        if "s" in options:	#list all services
            parser.print("Services:")
            all_services = logic.list_services([h])
            for s in all_services[h]:
                parser.print("    "+s)
        if "c" in options: #list config
            if selected_services: #not list all service configs
                services = selected_services
            elif all_services:
                services = all_services[h]
            else:
                services = logic.list_services([h])[h]

            for service in services:
                parser.print("Service:"+service)
                c = logic.get_service_config(h,service)
                if not c:
                    parser.print(h+" did not send a config of "+service)
                    continue
                for i in c[h]:
                    parser.print("    "+i+": "+str(c[h][i]))
                
