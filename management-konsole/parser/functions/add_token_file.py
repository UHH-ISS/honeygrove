def add_token_file(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys() or "dir" not in args.keys():
            parser.print("Nicht alle Pflichtparameter gesetzt")
            return
        hid = args["hid"]
        filepath = args["dir"][0]
        for h in hid:
            error = logic.add_token_files(h, filepath)
            if not error:
                parser.print("Error while token upload")
            else:
                parser.print(h+": uploaded")
    else:
        parser.print("missing arguments")