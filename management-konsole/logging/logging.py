import threading
import time
from logging.loggingTask import LoggingTask
class Logging(object):

    def __init__(self,logic):
        """
        Manages the LoggingTasks

        :param logic: reference to the logic module
        """
        self.lock = threading.Lock()
        self.logic = logic
        self.ui = None
        self.task_list = []
        self.task_count = 0
        self.freq = 2
        
    def new_task(self,keywords,operator,filename=None):
        """
        Create a new LoggingTask.
        
        :param keywords: keywords the logs are scanned for
        :param operator: how multiple keywords are combuned to evaluate the logs
        :param filename: filename the logs are written to. If not passed the LoggingTask prints to the console
        """
        task = LoggingTask(self,self.task_count,keywords,operator,filename) 
        self.task_count += 1
        self.task_list.append(task)

    def end_task(self,number):
        """
        Terminate a loggingTask.

        :param number: loggingTask ID
        """
        l = len(self.task_list)
        self.lock.acquire()
        try:
            self.task_list[:] = [t for t in self.task_list if not t.id == number]
        finally:
            self.lock.release()
            return not l == len(self.task_list)

    def print_tasks(self):
        """ Print a list of all active loggingTasks """
        self.print("Logging frequency:"+str(self.freq)+" seconds")
        for l in self.task_list:
            l.info()
            self.print("")

    def start(self):
        """ Start the thread, that executes the loggingTask """
        thread = threading.Thread(target=self.loop, args=())
        thread.daemon = True                        
        thread.start()                              

    def print(self,string):
        """ Print to the UI (if it exists) or else to stdout """
        if self.ui:
            self.ui.print(string)
        else:
            print(string)

    def loop(self):
        """ loggingTask execution """
        while True:
            self.lock.acquire()
            logs = self.logic.get_logs()
            self.lock.release()
            if logs:
                for task in self.task_list:
                    task.log(logs)
            time.sleep(self.freq)
