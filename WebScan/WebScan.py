
from Tkinter import *
import  tkMessageBox as messagebox
from ScrolledText import ScrolledText
import Tkinter as tk
import ttk
import time
import requests
import threading
from bs4 import BeautifulSoup
import tooltip as tt
import queue 
import message as mes
L = queue.Queue(maxsize=0)
comm={}
sop={}
sc={}
head={}
res={}
resp={}
req={}
rpo={}
duplic=set()

class app():
    def __init__(self):
        self.root=Tk()
        self.root.title("WebScan")
        self.root.resizable(False,False)
        self.rr=IntVar()
        
        #self.root.geometry("1000x800")
        self.creat_weaget()
        
        ##varible to paues the scan##
        self.aa=IntVar()
        self.aa=False
        self.tt=StringVar
        self.va=StringVar
        ###left frame###
        self.left=Frame(self.root)
        self.left.grid(row=0,column=0,sticky=W)
        self.creat_left_weget()
        
        ###right frame##
        self.right=Frame(self.root)
        self.right.grid(row=0,column=1,sticky=E)
        self.creat_right_weget()
        
        
        
        ##progressbar text##
        
        self.style = ttk.Style(self.root)

        self.style.layout('text.Horizontal.TProgressbar', 
             [('Horizontal.Progressbar.trough',
               {'children': [('Horizontal.Progressbar.pbar',
                              {'side': 'left', 'sticky': 'ns'})],
                'sticky': 'nswe'}), 
              ('Horizontal.Progressbar.label', {'sticky': ''})])

        self.style.configure('text.Horizontal.TProgressbar', text='')
        
        
    def creat_weaget(self):
        
        ##top menu##
        
        self.menu_bar=Menu(self.root)
        self.root.config(menu=self.menu_bar)
        file_menu=Menu(self.menu_bar,tearoff=0)
        file_menu.add_command(label="About",command=self.he)
        self.menu_bar.add_cascade(label="Help",menu=file_menu)
        conf_menu=Menu(self.menu_bar,tearoff=0)
        conf_menu.add_command(label="User Agent Spoofing",command=self.con)
        self.menu_bar.add_cascade(label="Setting",menu=conf_menu)
        
        
        
        
        
        pass
        

    def creat_left_weget(self):
         ###label##
        label=Label(self.left,text="Entre the target Address")
        label.grid(row=0,column=0,pady=10,sticky=N)
        
        ##entry##
        self.entry=Entry(self.left)
        self.entry.grid(row=1,column=0,padx=10,pady=5,sticky=W+E)  
        self.entry.focus()
        
        
        
         ##radio box##
        self.r=IntVar()
        
        ba_1=Radiobutton(self.left,variable=self.r,value=1,text="Scan ")
        ba_1.grid(row=2,column=0,sticky=W)
        tt.create_ToolTip(ba_1,'Only Scant the target Site')
        ba_2=Radiobutton(self.left,variable=self.r,value=2,text="Spider")
        ba_2.grid(row=2,column=0,sticky=E)
        tt.create_ToolTip(ba_2,'Spider the target site')
        ##submit batton##
        
        self.submit=Button(self.left,text="Start Scan",command=self.th)
        self.submit.grid(row=3,column=0,padx=10,pady=5,sticky=W)     
     
        ##paus button##
        
        self.stop=Button(self.left,text="Pause Scan",command=self.st)
        self.stop.grid(row=4,column=0,padx=10,pady=5,sticky=W+E)
        self.stop.config(state='disabled')
        ##exit button##
        self.exit=Button(self.left,text="Exit",command=self.exe)
        self.exit.grid(row=3,column=0,padx=10,pady=5,sticky=E)
        
        
        ##progress bar##
        self.progre=ttk.Progressbar(self.left,style='text.Horizontal.TProgressbar',length=200,mode='determinate')
        self.progre.grid(row=5,column=0,padx=10)
        self.progre["maximum"]=100
        self.progre["value"]=0
    
        
        
        ##scrollbar##
        self.scroll=Scrollbar(self.left)
        self.scroll.grid(row=6,column=0,rowspan=5,sticky=N+E+S)
        xscrollbar = Scrollbar(self.left, orient=HORIZONTAL)
        xscrollbar.grid(row=13, column=0, sticky=E+W)
        ###listbox## 
        
        self.list=Listbox(self.left,width=10,height=20,yscrollcommand=self.scroll.set,xscrollcommand=xscrollbar.set)
        self.list.grid(row=6,column=0,sticky=W+E+N+S,columnspan=1,rowspan=5,pady=5,padx=10)
        xscrollbar.config(command=self.list.xview)
        
        
        
        pass
    def creat_right_weget(self):
        ##textpt##
        self.script=Button(self.right,text="Scrip",command=self.script)
        self.script.grid(row=1,column=1,pady=5,sticky=W+E) 
        tt.create_ToolTip(self.script,'Search for scripts in Seleted Site')
        self.script.config(state='disabled')
        ##comments##
        self.comments=Button(self.right,text="Comments",command=self.comment)
        self.comments.grid(row=1,column=2,pady=5,sticky=W+E)     
        self.comments.config(state='disabled')
        tt.create_ToolTip(self.comments,'Search for Comments in Seleted Site')
        ##Vulnerabilites##
        self.vul=Button(self.right,text="Vulnerabilites",command=self.vul_2)
        self.vul.grid(row=1,column=3,pady=5,sticky=W+E)     
        self.vul.config(state='disabled')
        tt.create_ToolTip(self.vul,'Scan passively for Vulnerabilites in Seleted Site')
        ##response header##
        self.response=Button(self.right,text="Response",command=self.head_2)
        self.response.grid(row=1,column=4,pady=5,sticky=W+E)     
        self.response.config(state='disabled')
        tt.create_ToolTip(self.response,'Print Response header for Seleted Site')
                ##request header##
        self.request=Button(self.right,text="Request",command=self.req_2)
        self.request.grid(row=1,column=5,pady=5,sticky=W+E)     
        self.request.config(state='disabled')   
        tt.create_ToolTip(self.request,'Print Request header for textpts in Seleted Site')
        ##scrolltest##
        
        xscrollbar = Scrollbar(self.right, orient=HORIZONTAL)
        xscrollbar.grid(row=3, column=1,columnspan=6, sticky=E+W)
        self.text=ScrolledText(self.right,height=30,state='disabled',wrap=NONE,xscrollcommand=xscrollbar.set)
        self.text.grid(row=2,column=1,columnspan=6,padx=10,pady=5,sticky=W+E)
        xscrollbar.config(command=self.text.xview)
        
        pass

    
    
    
    
    def st(self):
        if self.aa==False:
            self.aa=True
            self.stop.config(text="resume scan")
        elif self.aa==True:
            self.aa=False
            self.stop.config(text="pause scan")
    
    
    
    
    
    
    
    

    def th(self):
        if self.entry.get():
            if self.r.get():
                print self.r.get()
                self.t1 = threading.Thread(target=self.rev, args=[])
                self.t1.setDaemon(True)
                self.t1.start() 
                
                #self.t2 = threading.Thread(target=self.status, args=[])
                #self.t2.start() 
            else:
                messagebox.showerror("Error","First Select the Attack Mode")     
        else: 
              
            messagebox.showerror("Error", "First Entre the target site")
            








##callback function for exit button##

    def exe(self):
        self.root.destroy()


##callback function for help menu##
    def he(self):
        
       help=mes.message()
       self.text.config(state='normal')
       #help="This is python based tool which crowl the target web site and print scripts and comments present at the target web page. "
       self.text.insert(END,help)
       self.text.config(state='disabled') 
        
        
        
  ##call back function for seting menu bar##  
    def con(self):
        self.top=Toplevel()
        self.top.title("User Agents")
        self.top.geometry("200x150")
        self.top.resizable(False,False)
        
        ba_1=Radiobutton(self.top,variable=self.rr,value=1,text="Chrome on Windows 8.1")
        ba_1.grid(row=0,column=0,sticky=W)
        tt.create_ToolTip(ba_1,'User-Agent : Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36')
        ba_2=Radiobutton(self.top,variable=self.rr,value=2,text="Safari on iOS")
        ba_2.grid(row=1,column=0,sticky=W)
        tt.create_ToolTip(ba_2,'User-Agent : Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4')
        ba_3=Radiobutton(self.top,variable=self.rr,value=3,text="IE6 on Windows XP")
        ba_3.grid(row=2,column=0,sticky=W)
        tt.create_ToolTip(ba_3,'User-Agent : Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)')
        ba_4=Radiobutton(self.top,variable=self.rr,value=4,text="Googlebot")
        ba_4.grid(row=3,column=0,sticky=W)
        tt.create_ToolTip(ba_4,'User-Agent : Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)')
        bb=Button(self.top,text="Exit",command=self.top.destroy)
        bb.grid(row=4,column=0)
        


    ##callback function for submitt button##
    
    
    def _mess(self):
        messagebox.showerror("Error","First Select the target from listbox") 
     
    ##print the textpts##    
    def comment(self):
        
        click_item=self.list.curselection()
        self.text.config(state='normal')
        if click_item:
            self.text.delete(1.0,END)
            t=self.list.get(click_item)
            tt=str(comm[t])
            
            self.text.insert(END,tt)
            
        else:
            self._mess() 
        self.text.config(state='disabled')
    
    def script(self):
        click_item=self.list.curselection()
        self.text.config(state='normal')
        if click_item:
            self.text.delete(1.0,END)
            
            t=self.list.get(click_item)
            self.tt=(sc[t])
            
            self.text.insert(END,self.tt)
            
        else:
            self._mess()
        
        self.text.config(state='disabled')
    ##print the request headers##
    def req_2(self):
        click_item=self.list.curselection()
        self.text.config(state='normal')
        if click_item:
            self.text.delete(1.0,END)
            self.text.insert(END,"GET\t")
            self.text.insert(END,self.list.get(click_item))
            
            t=self.list.get(click_item)
            tt=req[t]
            for ta in tt:
                pa=ta+"\t\t"+":"+tt[ta]+"\n"
                self.text.insert(END,pa,'rehead')
        else :
            self._mess()
        self.text.config(state='disabled')
        
        self.text.tag_config('rehead',foreground='red')
    
    ##print the response##
    def head_2(self):
        click_item=self.list.curselection()
        self.text.config(state='normal')
        if click_item:
            self.text.delete(1.0,END)
            statue=str(resp[self.list.get(click_item)])+"\n"
            self.text.insert(END,statue,'statue')
            t=self.list.get(click_item)
            tt=head[t]
            for ta in tt:
                pa=ta+"\t\t"+":"+tt[ta]+"\n"
                self.text.insert(END,pa,'head')
            self.text.insert(END,"\n")
            la=res[self.list.get(click_item)]
            #print la
            self.text.insert(END,la,'body')
            
        else:
            self._mess()
        self.text.tag_config('statue',foreground='blue')
        self.text.tag_config('head',foreground='red')
        self.text.tag_config('body',foreground='green')
        self.text.config(state='disabled')
    
    
            
            
        
        
        
        
        
        
        
        
        
        
    ##scan for vulnerabilites##
    def vul_2(self):
        
        click_item=self.list.curselection()
        self.text.config(state='normal')
        if click_item:
            self.text.delete(1.0,END)
            
            t=self.list.get(click_item)
            tt=head[t]
            try:
                xssprotect = tt['X-XSS-Protection']
                if xssprotect != '1; mode=block':
                    self.text.insert(END, '\nX-XSS-Protection not set properly, XSS may be possible:')
            except:
                self.text.insert(END, '\nX-XSS-Protection not set, XSS may be possible')
        
    
            try:
                contenttype = tt['X-Content-Type-Options']
                if contenttype != 'nosniff':
                    self.text.insert(END, '\nX-Content-Type-Options not set properly:')
            except:
                self.text.insert(END,'\nX-Content-Type-Options not set')
            try:
                hsts = tt['Strict-Transport-Security']
            except:
                self.text.insert(END,'\nHSTS header not set, MITM attacks may be possible')
            try:
                csp = tt['Content-Security-Policy']
                self.text.insert(END, '\nContent-Security-Policy set:')
            except:
                self.text.insert(END,'\nContent-Security-Policy missing')
            try:
                click=tt['x-frame-options']
            except:
                self.text.insert(END,"\nX-Frame-Options Header is not set, Clickjacking may be possible\n")    
                   
            self.text.insert(END,"\nCookie Information\n",'title')
            self.text.tag_config('title',foreground='blue')
            
            for cookie in sop[t].cookies:
                name=str(cookie.name)
                self.text.insert(END,'Name :','nam')
                self.text.insert(END,name+'\n','value')
                self.text.insert(END,'Value :','nam')
                self.text.insert(END,cookie.value+'\n','value')
                if not cookie.secure:
                    cookie.secure = "False"
                    self.text.insert(END,'Secure :','nam')
                    self.text.insert(END,cookie.secure+'\n','value')
                    
                if 'httponly' in cookie._rest.keys():
                    cookie.httponly = 'True'
                else:
                    cookie.httponly = 'False'
                
                self.text.insert(END,'HTTPOnly :','nam')
                self.text.insert(END,cookie.httponly+'\n','value')
                if cookie.domain_initial_dot:
                    cookie.domain_initial_dot = 'True'
                self.text.insert(END,'Cookie Scope to parent domain :','nam')
                self.text.insert(END,str(cookie.domain_initial_dot)+'\n','value')  
                self.text.insert(END,"-------------------------------\n",'new')
            
            self.text.tag_config('nam',foreground='red')
            self.text.tag_config('value',foreground='green')
            self.text.tag_config('new',foreground='orange')
            
              
        else:
            self._mess()

    
        self.text.config(state='disabled')
    
    
    
    
    def rev(self):
        self.text.config(state='normal')
        self.text.delete(1.0,END)
        self.text.config(state='disabled')
        self.menu_bar.entryconfig("Help",state='disabled')
        self.menu_bar.entryconfig("Setting",state='disabled')
        self.script.config(state='normal')
        self.comments.config(state='normal')
        self.request.config(state='normal')
        self.response.config(state='normal')
        self.vul.config(state='normal')
        self.stop.config(state='normal')
        self.submit.config(state='disabled')
        self.entry.config(state='disabled')
        if self.rr.get()==1:
            headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36'}
        elif self.rr.get()==2:
            headers = {'User-Agent' : 'Mozilla/5.0 (iPhone; CPU iPhone OS 8_1_3 like Mac OS X) AppleWebKit/600.1.4 (KHTML, like Gecko) Version/8.0 Mobile/12B466 Safari/600.1.4'}
        elif self.rr.get()==3:
            headers = {'User-Agent' : 'Mozilla/5.0 (Windows; U; MSIE 6.0; Windows NT 5.1; SV1; .NET CLR 2.0.50727)'}
        elif self.rr.get()==4:
            headers = {'User-Agent' : 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)'}
            
        else:
            headers = {'User-Agent' : 'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.115 Safari/537.36'}
        
        
        print "user agent"+str(self.rr.get())
        content=self.entry.get()
        if (content[:4]=="http") or (content[:5]=="https"):
            L.put(content)
        else:
            content="https://"+content
            L.put(content)   
        print self.entry.get()
        
        while(L.qsize()):
            ##start progress bar##
            self.progre.start()
        
            self.style.configure("text.Horizontal.TProgressbar", text="Scan is running")
            ##pause the scan##
            print self.aa
            while(self.aa):
                self.progre.stop()
        
                self.style.configure("text.Horizontal.TProgressbar", text="Scan Paused")
                #print("scan stop")
            trurl=L.get()
            
            ##check target is previsely scaned or not##
            if trurl in duplic:
                continue
            else:
                duplic.add(str(trurl))
                
                
            ## check target address is correct or not##
            
            try:
                response=requests.get(trurl,headers=headers)
            except:
                
                self.text.delete(1.0,END)
                self.progre.stop()
                #self.text.insert(END,"Please Entre Valid Address")
                messagebox.showerror("Error","Please Entre Valid Address") 
                break
            
            ##insert the scaned links in the list box##
            self.list.insert(END,trurl)
            
            
            
            
            
            resp[trurl]=response
            head[trurl]=response.headers # storing response the headers
            
            req[trurl]=response.request.headers#storing request headers
            com=" "    
            sc[trurl]=com
            ##finding the scripts##
            
            soup = BeautifulSoup(response.content,"lxml")
            for line in soup.find_all('script'):
                for r in line.text.split(">"):
                    #print r+"\n"
                    sc[trurl]+=(r)+"\n"
                    
            
            ##finding the comments##
            aa=re.compile("\n")
            a=aa.sub(" ",response.text)
            comments = re.findall(r'[^>]<!--(.*?)-->',a)
            sop[trurl]=response
            if comments:
              com=" "    
              comm[trurl]=com
    
        
              for c in comments:
        
                comm[trurl]+= "\n"+com+str(c)
            else:
               comm[trurl]="Comments not avaliable"
        #tt=str(sc[click_item]
        
        
        
         
                 
            #print soup.prettify()
            res[trurl]= soup.prettify()   #response.text  #storing response
            if (self.r.get()==2):                        
    
                for line in soup.find_all('a'):
                    newline = line.get('href') 
                    print newline
                    try:
                        if newline[:4] == "http"or newline[:5]=="https":#count up to four digits
                            if trurl in newline:
                                L.put(newline)
                                    #print L.qsize()
                     
                        elif newline[:1] == "/":            
                            combine = trurl+newline
                            L.put(combine)
                                  #print L.qsize()
                             #print combine
                        elif newline[:1] != "/":
                            combine = trurl+"/"+newline
                            L.put(combine)    
                                  
                    except:
                        print "Error"
            
            elif (self.r.get()==1):
                 L.empty()
        self.progre.stop()
        self.style.configure("text.Horizontal.TProgressbar", text="Scan is completed")
        self.progre['value']=200
        self.submit.config(state='normal')
        self.entry.config(state='normal')
        self.entry.delete(0,'end')
        self.stop.config(state='disabled')
        self.menu_bar.entryconfig("Help",state='normal')
        self.menu_bar.entryconfig("Setting",state='normal')




opp=app()
opp.root.mainloop()