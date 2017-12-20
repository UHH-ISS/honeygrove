def get_html_pages(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys():
            parser.print("missing honeypotid")
            return
        hid = args["hid"]
        for h in hid:
            r = logic.get_html_pages(h)
            if r != "":
                parser.print("HTML pages loaded and saved: \n" + r)
            else:
                parser.print(h+": error HTML not downloaded")
    else:
        parser.print("missing arguments")