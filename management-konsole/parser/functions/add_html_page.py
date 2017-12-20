def add_html_page(parser, logic, logging, args=0):
    if args:
        if "hid" not in args.keys() or "url" not in args.keys() or "dir" not in args.keys():
            parser.print("missing honeypotid")
            return
        hid = args["hid"]
        url = args["url"][0]
        dir = args["dir"][0]
        for h in hid:
            if "dashdir" in args.keys():
                dashdir = args["dashdir"][0]
            else:
                dashdir = ""
            error = logic.add_html_page(h, url, dir, dashdir)
            if not error:
                parser.print("Error while HTML page upload")
            else:
                parser.print(h + ": uploaded")
    else:
        parser.print("missing arguments")
