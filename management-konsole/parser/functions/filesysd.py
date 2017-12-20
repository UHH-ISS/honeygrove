def filesysd(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys():
            parser.print("No honeypots passed")
            return
        hid = args["hid"]
        for h in hid:
            if "dir" in args.keys():
                r = logic.get_filesystem(h, directory=args["dir"])
            else:
                r = logic.get_filesystem(h)
            if r != "":
                parser.print("Filesystem downloaded and saved as " + r)
            else:
                parser.print(h+": Filesystem could not be downloaded")
    else:
        parser.print("No arguments passed")
