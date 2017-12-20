class LoggingTask(object):

    def __init__(self, logging,task_id, keywords, operator, name = None):
        """
        Mangages one logging task

        :param logging: reference to the logging module
        :param task_id: id
        :param keywords: keywords, the logs are scanned for
        :param operator: how multilple keywords combined to evaluate the logs. Possible operators:"or","and"
        :param name: name of the file the logs are printed to. If not passed logs are printed to the console
        """
        self.logging = logging
        self.keywords= keywords
        self.name = name
        self.id = task_id
        if operator in ["or","and"]:
            self.operator = operator
        elif operator == []:
            self.operator = "or"
        else:
            self.logging.print("Operator: "+operator+" unknown")
            self.logging.print("Using operator:or")
            self.operator = "or"
        
    def log(self,msg_list):
        """
        Evaluate a logs
        :param msg_list: a list of log strings
        """
        for msg in msg_list:
            if self.evaluate_log(str(msg)):
                if self.name:
                    with open(self.name + ".txt", "a") as myfile:
                        myfile.write(str(msg) + "\n")
                else:
                    self.logging.print("["+str(self.id)+"]"+str(msg))

    def evaluate_log(self,msg):
        """
        Evaluate a log according to the choosen operator
        :param msg: a message to evaluate
        """
        if self.keywords == []:
            return True
        if self.operator == "or":
            for k in self.keywords:
                if k in msg:
                    return True
            else:
                return False
        if self.operator == "and":
            for k in self.keywords:
                if k not in msg:
                    return False
            else:
                return True
        
    def info(self):
        """ Print the details of this LoggingTask """
        self.logging.print("Loggingtask ID:"+str(self.id))
        self.logging.print("Filters: " + str(self.keywords))
        self.logging.print("Operator: " + self.operator)
        if self.name:
            self.logging.print("Logfile: " + str(self.name + ".txt"))
        else:
            self.logging.print("Logging to console")

