from Tkinter import *
import  tkMessageBox as messagebox

class Message(object):
    def __init__(self,widget):
         self.widget = widget
    
    
def message():
    procedure='''
    This is a python based tool which crowl the target web site and print scripts and comments present at the target web page. 
   
    
    Ther are two attack methods.\n
    
    1. Spider -: In this mode, this tool will crowl thw target web site.
    2. Scan   -: In this mode, this toll scan the target site for scripts and comments.
    
    Attack Steps:
    
    1. Entre the target address.
    2. Select the attack mode.
    3. Start the Scan.
    4. First select the link from the list box then press any of the tabs \t(Script, Comments,Request, Response and Vulnerabilites) to see the \nresults.

    Script: This will show the scripts present in the web page.\n
    Comments: This will show the cooment present in the web page.\n
    Vulnerabilites: This will show the basic vulnerabilites present at the target web site. \n
    Response : This will show the response from the target address.\n
    Request : This will show the request header.\n
    
    User Agent Spoofing:
    
    1. Go to setting tab in menu bar and select 'User agent spoffing'
    2. Select the options of your choise.
    3. Default user agent is Chrome on Windows 8.1
    
    
    
    
    
    
    
    
    
    '''
    
    
    return procedure
    