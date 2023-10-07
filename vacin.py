import getpass
import hashlib
import os
import time
from multiprocessing import Process
from tkinter import *
from tkinter import filedialog
import sys
import subprocess
import tempfile
import pyautogui
from pynput.keyboard import Key, KeyCode, Listener
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer
import pickle

v1  ='ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa'.lower() #v1 ~V22 실제 악성코드의 sha256 코드
v2  ='c365ddaa345cfcaff3d629505572a484cff5221933d68e4a52130b8bb7badaf9'.lower() #t1 테스트용 파일의 sha256 코드
v3  ='09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa'.lower()
v4  ='0a73291ab5607aef7db23863cf8e72f55bcb3c273bb47f00edf011515aeb5894'.lower()
v5  ='428f22a9afd2797ede7c0583d34a052c32693cbb55f567a60298587b6e675c6f'.lower()
v6  ='5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624e06cfa5bcbacd2211046ed6'.lower()
v7  ='62d828ee000e44f670ba322644c2351fe31af5b88a98f2b2ce27e423dcf1d1b1'.lower()
v8  ='72af12d8139a80f317e851a60027fdf20887334c12637f49d819ab4b033dd'.lower()
v9  ='85ce324b8f78021ecfc9b811c748f19b82e61bb093ff64f2eab457f9ef19b186'.lower()
v10  ='a1d9cd6f189beff28a0a49b10f8fe4510128471f004b3e4283ddc7f78594906b'.lower()
v11 ='a93ee7ea13238bd038bcbec635f39619db566145498fe6e0ea60e6e76d614bd3'.lower()
v12 ='b43b234012b8233b3df6adb7c0a3b2b13cc2354dd6de27e092873bf58af2693c'.lower()
v13 ='eb47cd6a937221411bb8daf35900a9897fb234160087089a064066a65f42bcd4'.lower()
v14 ='24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c'.lower()
v15 ='2c2d8bc91564050cf073745f1b117f4ffdd6470e87166abdfcd10ecdff040a2e'.lower()
v16 ='7a828afd2abf153d840938090d498072b7e507c7021e4cdd8c6baf727cafc545'.lower()
v17 ='a897345b68191fd36f8cefb52e6a77acb2367432abb648b9ae0a9d708406de5b'.lower()
v18 ='b0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc'.lower()
v19 ='9588f2ef06b7e1c8509f32d8eddfa18041a9cc15b1c90d6da484a39f8dcdf967'.lower()
v20 ='b43b234012b8233b3df6adb7c0a3b2b13cc2354dd6de27e092873bf58af2693c'.lower()
v21 ='4186675cb6706f9d51167fb0f14cd3f8fcfb0065093f62b10a15f7d9a6c8d982'.lower()
v22 ='09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa'.lower()
t1 ='A37220E099E01D00D26E74678A0632F5A1F5FE819D864F593A2FAA01071706D7'.lower()
# t2 ='0D6AFB7E939F0936F40AFDC759B5A354EA5427EC250A47E7B904AB1EA800A01D'.lower()
# t4 ='8739C76E681F900923B900C9DF0EF75CF421D39CABB54650C4B9AD19B6A76D85'.lower()


virus_list = [t1, v1, v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15,v16,v17,v18,v19,v20,v21,v22]

sus_path1 = []   #의심되는 파일 경로를 모아놓는 리스트
cantfind = []    #검사를 진행 할 수 없는 파일 경로를 모아놓는 리스트
allfilelist = [] #전체 검사한 파일 경로를 모아놓는 리스트


#####################################################################################################################

def vacin(root_dir, prefix):                                        #컴퓨터 내의 모든 파일을 출력할 함수
    try:
        global path
        global file_path
        if os.path.isfile(root_dir):
            file_path = root_dir
            scan()
        else:
            files = os.listdir(root_dir)                                #root_dir은 main 함수에
            for file in files:                                          #files의 file을 출력할 때 까지
                path = os.path.join(root_dir, file)                     #root_dir변수와 file 변수를 합쳐 path라는 변수 생성
                file_path = prefix + path           
                print(file_path)                                        #file_path를 출력
                scan()                                                  #위의 scan 함수를 이용하여 악성코드인지 검사
                if os.path.isdir(path):                                 #만약 path가 파일이 아닌 폴더라면 폴더안의 파일을 출력후 검사
                    vacin(path, prefix)
                    scan()
    except:                                                         #예외가 발생했을때
       print("파일탐색중 에러가 났습니다.")                           #파일탐색중 에러가 났습니다. 출력 (흰색)

################################################################################################################################

def scan():                                                         #악성코드의 sha256와 컴퓨터 파일의 sha256을 대조하는 함수
        try:
            global sus_path1
            global sha256
            fp = open(file_path, 'rb')                              #vacin 함수의 path변수 읽기모드 진입
            fread = fp.read()                                       #fp 읽기
            fp.close                                                #fp 읽은 후 닫기 - fread변수에 저장
            hash=hashlib.sha256()                                   
            hash.update(fread)                                      #fread의 sha256r 값을 구함
            sha256 = hash.hexdigest()                               #fread를 sha256 값으로 변환 값을 sha256 변수에 저장
            allfilelist.append(file_path)                           #만약 sha256의 값이 virus_list값과 하나라도 같다면
            if sha256 in virus_list:
                sus_path1.append(file_path)                         #sus_path1 리스트에 파일경로 추가
                # print ('is suspect')                                #is suspect출력 (빨간색)
                time.sleep(0.1)
            else:                                                   #아니라면
                # print('no doubt')
                time.sleep(0.1)                                     #no doubt출력 (노란색)
        except:                                                     #예외가 발생했을 때
            # print('예외가 발생하였습니다.')#예외가 발생하였습니다. 출력 (파란색)
            cantfind.append(file_path)                              #cantfind 리스트에 파일경로 추가
            

################################################################################################################################

# def interface():                                                    #사용자의 인터페이스 구성 함수

#     btn1 = pyautogui.confirm('검사를 진행하시겠습니까?', 'vacin', buttons = ['전체 검사', '파일 경로 입력', '종료하기'])
#     if btn1 == '전체 검사':
#         root_dir = "C:/"
#           
#         if not sus_path1:
#             print('아무것도 없습니다.')
#             print(str(len(sus_path1)) + '의심되는 파일 개수')
#             print(str(len(cantfind)) + '검사 불가 파일 개수')
#             print(str(len(allfilelist))+ '전체 검사한 파일 개수')
#             print(hash)

            lensus = len(sus_path1)
            lencant = len(cantfind)
            lenfile= len(allfilelist)
            
            
#             if lencant == 0:
#                 pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개', buttons = ['ok'], title = 'vacin')
#             else:
#                 finishbtn = pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개\n검사가 불가능한 파일: ' + str(lencant) + '개 \n검사 불가능한 파일 경로를 보시겠습니까?', buttons = ['yes', 'no'], title = 'vacin')
#                 if finishbtn == 'yes':
#                     pyautogui.confirm(str(cantfind), title = 'vacin')
#                 else:
#                     print('종료합니다.')
#         else:
#             print('의심되는 파일이 존재합니다')
#             print(str(len(sus_path1)) + '의심되는 파일 개수')
#             print(str(len(cantfind)) + '검사 불가 파일 개수')
#             print(str(len(allfilelist))+ '전체 검사한 파일 개수')
#             print(hash)

#             lensus = len(sus_path1)
#             lencant = len(cantfind)
#             lenfile= len(allfilelist)
#             btn3 = pyautogui.confirm(text = '검사가 종료되었습니다. \n검사한 파일: '+  str(lenfile) + '개\n의심되는 파일: '+ str(lensus) + '개 \n의심되는 파일 경로: ' + str(sus_path1) +'\n의심되는 파일을 제거 할까요?', buttons = ['yes', 'no'], title = 'vacin')
#             if btn3 == 'yes':
#                 for dlfdls in sus_path1:
#                     os.remove.dlfdls
#             else:
#                 print('종료합니다.')
#     elif btn1 == '파일 경로 입력':

#         btn4 = pyautogui.prompt(title='vacin', text= '파일 경로를 입력해주세요')
#         if btn4 == '':
#             print('종료합니다')
#         else:
#             try:
#                 btn4 = btn4.replace('\\','/')
#                 root_dir = btn4
#                 print(root_dir)
#                 vacin(root_dir, "")
#                 if not sus_path1:
#                     print('아무것도 없습니다.')
#                     print(str(len(sus_path1)) + '의심되는 파일 개수')
#                     print(str(len(cantfind)) + '검사 불가 파일 개수')
#                     print(str(len(allfilelist))+ '전체 검사한 파일 개수')
#                     lensus = len(sus_path1)
#                     lencant = len(cantfind)
#                     lenfile= len(allfilelist)

                    
#                     if lencant == 0:
#                         pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개', buttons = ['ok'], title = 'vacin')
#                     else:
#                         finishbtn = pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개\n검사가 불가능한 파일: ' + str(lencant) + '개 \n검사 불가능한 파일 경로를 보시겠습니까?', buttons = ['yes', 'no'], title = 'vacin')
#                         if finishbtn == 'yes':
#                             pyautogui.confirm(str(cantfind), title = 'vacin')
#                         else:
#                             print('종료합니다.')
#                 else:
#                     print('의심되는 파일이 존재합니다.')
#                     print(str(len(sus_path1)) + '의심되는 파일 개수')
#                     print(str(len(cantfind)) + '검사 불가 파일 개수')
#                     print(str(len(allfilelist))+ '전체 검사한 파일 개수')
#                     lensus = len(sus_path1)
#                     lencant = len(cantfind)
#                     lenfile= len(allfilelist)
#                     btn3 = pyautogui.confirm(text = '검사가 종료되었습니다. \n검사한 파일: '+  str(lenfile) + '개\n의심되는 파일: '+ str(lensus) + '개 \n의심되는 파일 경로: ' + str(sus_path1) +'\n의심되는 파일을 제거 할까요?', buttons = ['yes', 'no'], title = 'vacin')
#                     if btn3 == 'yes':
#                         try:
#                             print(sus_path1)
#                             newlist = list(dict.fromkeys(sus_path1))
#                             newlist1= [element.replace('\\', '/') for element in newlist]
#                             print(newlist)
#                             for susdir in newlist:
#                                 os.remove(susdir)
#                                 # shutil.rmtree(susdir)
#                             pyautogui.alert(text= '제거가 완료되었습니다.')
#                         except:
#                             pyautogui.alert(text = '제거에 실패하였습니다.\n파일경로: ' +  str(newlist1))
#                     else:
#                         print('종료합니다.')
#             except:
#                 print('종료합니다')
#     else:
#         print('종료합니다.')

###############################################################################################################################

# from tkinter import Label, Tk, Toplevel

win = Tk()

def toplevelwin():
    global top
    lensus = len(sus_path1)
    lencant = len(cantfind)
    lenfile = len(allfilelist)
    top = Toplevel()
    top.geometry("500x300")
    top.title("vacin")
    if lensus >= 1:
        text = Label(top, text='검사가 종료되었습니다.')
        text1 = Label(top, text='검사한 파일: ' + str(lenfile))
        text2 = Label(top, text='의심되는 파일: ' + str(lensus))
        text3 = Label(top, text='검사를 진행할 수 없는 파일: ' + str(lencant))
        # text4 = Label(top, text="의심되는 파일 경로: " + str(sus_path1))
        text5 = Label(top, text = "의심되는 파일을 제거할까요?")
        asslabel = Label(top, width= 500)
        btn_y = Button(asslabel, text="YES", command= removesus)
        btn_n = Button(asslabel, text="NO", command = top.destroy)
        text.pack(pady=5)
        text1.pack(pady=5)
        text2.pack(pady=5)
        text3.pack(pady=5)
        text5.pack(pady=5)
        asslabel.pack(pady=8)
        btn_y.pack(side="left")
        btn_n.pack(side="left")
        # text4.pack()
        with open('susfile.txt','w',encoding='UTF-8') as f:
            for name in sus_path1:
                f.write(name+'\n')
        lencant = 0
        lenfile = 0
        lensus = 0

    else:
        text = Label(top, text='검사가 종료되었습니다.')
        text1 = Label(top, text='검사한 파일: ' + str(lenfile))
        text2 = Label(top, text='의심되는 파일: ' + str(lensus))
        text3 = Label(top, text='검사를 진행할 수 없는 파일: ' + str(lencant))
        # btn_ok = Button(asslabel, text="확인", command = top.destroy)
        text.pack()
        text1.pack()
        text2.pack()
        text3.pack()
        # btn_ok.pack(side="left")

    # lab = Label(top, text='검사가 종료되었습니다. \n검사한 파일: '+  str(lenfile) + '개\n의심되는 파일: '+ str(lensus) + '개 \n의심되는 파일 경로: ' + str(sus_path1) +'\n의심되는 파일을 제거 할까요?').pack()
def removesus():
    try:
        print(sus_path1)
        newlist = list(dict.fromkeys(sus_path1))
        newlist1= [element.replace('\\', '/') for element in newlist]
        print(newlist)
        for susdir in newlist:
            os.remove(susdir)
            # shutil.rmtree(susdir)
        pyautogui.alert(text= '제거가 완료되었습니다.')
        top.destory
    except:
        pyautogui.alert(text = '제거에 실패하였습니다.\n파일경로: ' +  str(newlist1))

def Cdrive():
    root_dir = "C:/"
    vacin(root_dir, "")
    toplevelwin()
#아무것도 없을 때 이벤트
#있을 때 이벤트

def findfile():
    win.filename = filedialog.askopenfilename(initialdir="C:/",title='파일선택', filetypes=(('모든파일','*.*'), ('jpg files', '*.jpg')))
    root_dir = win.filename
    vacin(root_dir,"")
    toplevelwin()
#아무것도 없을 때 이벤트
#있을 때 이벤트

def finddir():
    win.dirName=filedialog.askdirectory()
    root_dir = win.dirName
    vacin(root_dir,"")
    toplevelwin()


def selftype():
    def clickevent():
        root_dir = entry1.get()
        vacin(root_dir,"")
        top1.destroy()
        toplevelwin()
    top1= Toplevel()
    top1.geometry("500x200")
    top1.title("vacin")
    entry1 = Entry(top1, width=30, border=1, relief='solid')
    entry1.pack()
    btn = Button(top1, text='완료', command=clickevent)
    btn.pack()

state_file1 = 'switch_state1.pkl'
state_file2 = 'switch_state2.pkl'

# 스위치 상태를 저장하고 불러오는 함수
def save_switch_state1(state):
    with open(state_file1, 'wb') as f:
        pickle.dump(state, f)

def load_switch_state1():
    try:
        with open(state_file1, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return 0  # 파일이 없을 경우 기본 상태는 Off (0)

def save_switch_state2(state):
    with open(state_file2, 'wb') as f:
        pickle.dump(state, f)

def load_switch_state2():
    try:
        with open(state_file2, 'rb') as f:
            return pickle.load(f)
    except FileNotFoundError:
        return 0  # 파일이 없을 경우 기본 상태는 Off (0)

def toggle_switch1():
    if switch_var1.get() == 1:
        label1.config(text="On")
        auto_start()
    else:
        label1.config(text="Off")
    # 스위치 상태 저장
    save_switch_state1(switch_var1.get())

def toggle_switch2():
    a = Target()
    if switch_var2.get() == 1:
        label2.config(text="On")
        a.run()
    else:
        label2.config(text="Off")
    # 스위치 상태 저장
    save_switch_state2(switch_var2.get())

def setting():
    global switch_var1
    global switch_var2
    global label1
    global label2

    top2 = Toplevel()
    top2.geometry("550x200")
    top2.title("vacin")

    switch_var1 = IntVar(value=load_switch_state1())
    lb1= Label(top2, text= "컴퓨터 부팅시 자동 검사")
    switch1 = Checkbutton(top2, text="On/Off", variable=switch_var1, command=toggle_switch1)
    label1 = Label(top2, text="ON" if switch_var1.get() == 1 else "OFF")

    lb1.grid(row=0, column=0, padx=10, pady=10, sticky="w")
    switch1.grid(row=0, column=1, padx=10, pady=10, sticky="e")
    label1.grid(row=0, column=2, padx=10, pady=10, sticky="w")

    switch_var2 = IntVar(value=load_switch_state2())
    lb2= Label(top2, text="파일 다운로드 시 자동 검사")
    switch2 = Checkbutton(top2, text="On/Off", variable=switch_var2, command=toggle_switch2)
    label2 = Label(top2, text="ON" if switch_var2.get() == 1 else "OFF")
    lb2.grid(row=3, column=0, padx=10, pady=10, sticky="w")
    switch2.grid(row=3, column=1, padx=10, pady=10, sticky="e")
    label2.grid(row=3, column=2, padx=10, pady=10, sticky="w")


def auto_start():
    current_script_directory = os.path.dirname(os.path.abspath(__file__))
    relative_path_to_script = "vacin.py"
    script_path = os.path.join(current_script_directory, relative_path_to_script)
    print(f"파이썬 스크립트 경로: {script_path}")
    task_name = "MyPythonTask"
    task_description = "vacin will start"
    command = f"{sys.executable} {script_path}"
    userid= getpass.getuser()
    xml_content = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Date>2023-10-07T00:00:00</Date>
    <Author>username</Author>
    <Description>{task_description}</Description>
  </RegistrationInfo>
  <Triggers>
    <BootTrigger>
      <Enabled>true</Enabled>
    </BootTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <UserId>{userid}</UserId>
      <LogonType>Password</LogonType>
      <RunLevel>HighestAvailable</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>true</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>true</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <IdleSettings>
      <StopOnIdleEnd>true</StopOnIdleEnd>
      <RestartOnIdle>false</RestartOnIdle>
    </IdleSettings>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <DisallowStartOnRemoteAppSession>false</DisallowStartOnRemoteAppSession>
    <UseUnifiedSchedulingEngine>true</UseUnifiedSchedulingEngine>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{script_path}</Arguments>
    </Exec>
  </Actions>
</Task>
"""

#임시 파일 저장
    temp_dir = tempfile.gettempdir()
    task_xml_file = os.path.join(temp_dir, f"{task_name}.xml")
    with open(task_xml_file, "w") as xml_file:
        xml_file.write(xml_content)

    subprocess.run(["schtasks", "/create", "/tn", task_name, "/xml", task_xml_file])


    os.remove(task_xml_file)
    
def first():
    
    win.title("vacin")
    win.resizable(FALSE, FALSE)
    win.geometry("400x500")
    win.option_add("*Font", "맑은고딕 15")

    lb1 =Label(win, text =  "검사 방법 선택")
    photo = PhotoImage(file="setting.png")
    photo = photo.subsample(30,30)
    pbtn = Button(win, image=photo, borderwidth=0, command= setting)
    pbtn.pack(anchor="e")
    lb1.pack(side = "top")
    btn1 = Button(win, text="C드라이브 검사", width=18, command = Cdrive)
    btn2 = Button(win, text="폴더 불러오기", width=18, command=finddir)
    btn3 = Button(win, text="파일 불러오기", width=18, command = findfile)
    btn4 = Button(win, text="파일경로 직접 입력", width=18, command=selftype)
    btn5 = Button(win, text="종료하기", width=18, command = win.destroy)
    btn1.place(x=80, y=100)
    btn2.place(x=80, y=150)
    btn3.place(x=80, y=200)
    btn4.place(x=80, y=250)
    btn5.place(x=80, y=300)


    win.mainloop()

#############################################################################################################################

class Target:
    hostname = getpass.getuser()
    watchDir = "C:/Users/" + hostname + "/Downloads"
    #watchDir에 감시하려는 디렉토리를 명시한다.

    def __init__(self):
        self.observer = Observer()   #observer객체를 만듦

    def run(self):
        event_handler = Handler()
        self.observer.schedule(event_handler, self.watchDir, recursive=True)
        self.observer.start()
        try:
            while True:
                time.sleep(1)
        except:
            self.observer.stop()
            print("Error")
            self.observer.join()
 
 
class Handler(FileSystemEventHandler):
#FileSystemEventHandler 클래스를 상속받음.
#아래 핸들러들을 오버라이드 함

    #파일, 디렉터리가 move 되거나 rename 되면 실행
    def on_moved(self, event):
        print("moved")
        print(event.src_path)

    def on_created(self, event): #파일, 디렉터리가 생성되면 실행
        print("created")
        yetfile = event.src_path
        root_dir = yetfile.replace('\\','/')
        print(root_dir)
        vacin(root_dir, "")

    def on_deleted(self, event): #파일, 디렉터리가 삭제되면 실행
        print("deleted")
        print(event.src_path)


if __name__ == "__main__":
    # first()
    y=Target()
    y.run()
