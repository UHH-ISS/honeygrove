def remove_html_pages(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys() or "urls" not in args.keys():
            parser.print("Not all parameter set")
            return
        hid = args["hid"]
        urls = args["urls"]
        for h in hid:
            error = logic.remove_html_pages(h, urls)
            if not error:
                parser.print("Error while token removal")
            else:
                parser.print(h+": HTML pages removed")
    else:
        parser.print("missing arguments")