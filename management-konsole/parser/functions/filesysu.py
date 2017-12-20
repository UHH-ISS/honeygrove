def filesysu(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys() or "f" not in args.keys():
            parser.print("Not all neccessary options set")
            return
        hid = args["hid"]
        infiles = args["f"]
        msgs = logic.send_filesystem(hid, infiles[0])
        for msg in msgs:
            if msgs[msg]:
                parser.print("Honeypot " + msg + ": successfully uploaded")
            else:
                parser.print("Honeypot " + msg + ": upload error")
        return
    else:
        parser.print("No arguments passed")
