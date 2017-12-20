def get_token_files(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys():
            parser.print("missing honeypotid")
            return
        hid = args["hid"]
        for h in hid:
            r = logic.get_token_files(h)
            if r != "":
                parser.print("Tokens loaded and saved: \n" + r)
            else:
                parser.print(h+": Tokens not downloaded")
    else:
        parser.print("missing arguments")