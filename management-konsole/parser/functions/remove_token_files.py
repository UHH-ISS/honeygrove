def remove_token_files(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys() or "f" not in args.keys():
            parser.print("Not all parameter set")
            return
        hid = args["hid"]
        filenames = args["f"]
        for h in hid:
            error = logic.remove_token_files(h, filenames)
            if not error:
                parser.print("Error while token removal")
            else:
                parser.print(h+": tokens removed")
    else:
        parser.print("missing arguments")