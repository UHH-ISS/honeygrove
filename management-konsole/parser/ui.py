import curses
from curses import ascii
import math

class Ui(object):

    logging = None
    parser = None
    def __init__(self):
        """ Create and manage the ui """
        self.log_length = 100 #lines of the log pad
        self.command_history = ["",""] #first and last command history entry are empty


    def print(self,string):
        """ Print a string to the log window """
        #split too long lines
        lines = [string[i:i+self.log_w] for i in range(0, len(string), self.log_w)]
        for l in lines:
            if self.log_lines == self.log_length -1:
                self.log_pad.move(0,0)
                self.log_pad.deleteln()
                self.log_pad.addstr(self.log_lines -1 ,0, l)
            else:
                self.log_pad.addstr(self.log_lines,0, l)
                self.log_lines += 1
                if self.log_lines > self.log_h:
                    self.log_pos += 1
            self.log_pad.refresh(self.log_pos,0,0,0,self.log_h,self.log_w)

    def draw_log(self):
        """ Draw the empty log window """
        self.log_pad = curses.newpad(self.log_length,self.log_w)
        self.log_pos = 0
        self.log_lines = 0
        self.log_pad.refresh(self.log_pos,0,0,0,self.log_h,self.log_w)

    def draw_cmd(self,prompt_string=">"):
        """ Draw the empty command line """
        self.cmd_win = curses.newwin(self.cmd_h,self.cmd_w,self.log_h + 1,0)
        self.cmd_win.move(0,0)
        self.cmd_win.hline(0,self.cmd_w)
        self.cmd_win.keypad(True)
        self.cmd_win.addstr(0,0,"CMD")
        self.cmd_win.addstr(1,0,prompt_string)
        self.cmd_win.refresh()
        
    def draw_select(self):
        """ Draw the select window """
        is_select = self.parser.is_select
        selected_group = self.parser.selected_group
        selected = self.parser.select_dict[selected_group]
        self.sel_win = curses.newwin(self.sel_h,self.sel_w,0,self.log_w)
        self.sel_win.vline(0,0,0,self.sel_h)
        self.sel_win.addstr(0,0,"Select",curses.A_UNDERLINE)
        if is_select:
            self.sel_win.addstr(1,1,"on",curses.color_pair(1))
        else:
            self.sel_win.addstr(1,1,"off",curses.color_pair(2))
        self.sel_win.addstr(3,1,"Group",curses.A_UNDERLINE)
        self.sel_win.addstr(4,1,selected_group)
        #list selected
        self.sel_win.addstr(6,1,"Honeypots",curses.A_UNDERLINE)
        #split too long honeypotids
        lines = []
        for s in selected:
            s = "-" + s
            l = [s[i:i+self.sel_w-2] for i in range(0, len(s) ,self.sel_w-2)]
            for x in l:
                lines.append(x)

        self.sel_pad_len = len(lines)
        self.sel_pad = curses.newpad(self.sel_pad_len +1,self.sel_w -2)
        self.sel_pos = 0
        index = 0
        for i in lines:
            self.sel_pad.addstr(index,0,i)
            index += 1
        self.sel_win.refresh()
        self.sel_pad.refresh( self.sel_pos,0, 7,self.log_w +1, self.sel_h -1,self.log_w + self.sel_w)

    def resize(self):
        """ Redraw all windows """
        max_lines, max_cols = self.stdscr.getmaxyx()
        self.cmd_h = 2
        self.cmd_w = max_cols
        self.log_h = max_lines - self.cmd_h - 1
        self.log_w = math.floor(max_cols / 1.2)
        self.sel_h = self.log_h + 1
        self.sel_w = max_cols - self.log_w
        self.draw_log()
        self.draw_cmd()
        self.draw_select()

    def input(self,prompt_string):
        """ Get input characters and ui control commands """
        line =""
        up_count = 0
        log_move = self.log_pos
        curser_pos = 0
        self.draw_cmd(prompt_string)
        while(True):
            c = self.cmd_win.getch()
            if c == curses.KEY_RESIZE:
                self.resize()
            if c == curses.ascii.NL:#enter
                self.print(prompt_string + line)
                self.draw_cmd("...")
                up_count = 0
                break
            if c == curses.KEY_UP:#history one step back
                if len(self.command_history) > up_count+1:
                    up_count += 1
                    self.draw_cmd()
                    self.cmd_win.addstr(1,0,prompt_string + self.command_history[up_count])
                    self.cmd_win.refresh()
                    line = self.command_history[up_count]
                    curser_pos = len(line)
            if c == curses.KEY_DOWN:#history one step forward
                if up_count > 0:
                    up_count -= 1
                    self.draw_cmd()
                    self.cmd_win.addstr(1,0,prompt_string + self.command_history[up_count])
                    self.cmd_win.refresh()
                    line = self.command_history[up_count]
                    curser_pos = len(line)
            if c == curses.KEY_LEFT: #cursor one character to the left
                if curser_pos > 0:
                    curser_pos -= 1
                    self.cmd_win.move(1,len(prompt_string)+curser_pos)
            if c == curses.KEY_RIGHT: #cursor one character to the right
                if curser_pos < len(line):
                    curser_pos += 1
                    self.cmd_win.move(1,len(prompt_string)+curser_pos)
            if c in [569,566]:#strg up -> select scroll up
                if self.sel_pos < self.sel_pad_len -1:
                    self.sel_pos += 1
                    self.sel_pad.refresh(self.sel_pos,0, 7,self.log_w +1, self.sel_h -1,self.log_w + self.sel_w)
            if c in [528,525]:#strg down -> select scroll down
                if self.sel_pos > 0:
                    self.sel_pos -= 1
                    self.sel_pad.refresh(self.sel_pos,0, 7,self.log_w +1, self.sel_h -1,self.log_w + self.sel_w)
            if c == 339:#page up -> log scroll up
                if log_move < self.log_lines -1:
                    log_move += 1
                    self.log_pad.refresh(log_move,0,0,0,self.log_h,self.log_w)
            if c == 338:#page down -> log scroll down
                if log_move > 0:
                    log_move -= 1
                    self.log_pad.refresh(log_move,0,0,0,self.log_h,self.log_w)
            if c == 127 or c == 263: #backspace -> delete character
                if curser_pos > 0:
                    curser_pos -= 1
                    self.cmd_win.move(1,len(prompt_string)+curser_pos)
                    self.cmd_win.delch(1,len(prompt_string)+curser_pos)
                    line = line[:curser_pos] + line[1+curser_pos:]
                up_count = 0
            if curses.ascii.isascii(c) and not c == 127: #character input
                if len(line) < self.cmd_w - len(prompt_string)-2:
                    if curser_pos < len(line):
                        self.cmd_win.insstr(1,len(prompt_string)+ curser_pos,chr(c))
                        line = line[:curser_pos] + chr(c) + line[curser_pos:]
                        curser_pos += 1
                        self.cmd_win.refresh()
                    elif curser_pos == len(line):
                        self.cmd_win.addstr(1,len(prompt_string)+curser_pos,chr(c))
                        line = line + chr(c)
                        curser_pos +=1
                up_count = 0
        if line:
            self.command_history.insert(1,line)
        return line
           

    def loop(self):
        """ Loop of getting input and hand it to the parser """
        self.resize()
        self.logging.start()

        run = True
        if self.parser.default_script():
            while(run):
                i = self.input(">")
                run = self.parser.parse(i)

    def start(self):
        try:
            self.stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.stdscr.keypad(True)
            try:
                curses.start_color()
                curses.use_default_colors()
                curses.init_pair(1, curses.COLOR_GREEN,-1)
                curses.init_pair(2, curses.COLOR_RED, -1)
            except:
                pass

            self.loop()
        finally:
            self.stdscr.keypad(0)
            curses.echo()
            curses.nocbreak()
            curses.endwin()

