#automatically import all modules in parser/functions
#import os
#__all__ = [f[:len(f)-3] for f in os.listdir("./parser/functions/") if f.endswith(".py") and not f.startswith("_")]


__all__ = ["ls",
            "start",
            "stop",
            "help",
            "peer",
            "peers",
            "unpeer",
            "log",
            "filesysd",
            "config",
            "filesysu",
            "get_token_files",
            "add_token_file",
            "remove_token_files",
            "add_html_page",
            "remove_html_pages",
            "get_html_pages",
            "info"
           ]

ALL_FUNCTIONS = __all__

#Select will never set the "hid" option of these functions
NO_SELECT = ["log","unpeer","peers","peer","help","quit","script","select"]
