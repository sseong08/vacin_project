import os
import pyautogui
import hashlib
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import getpass
import time


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
t1 ='EC132CCE6D321DC488D3112C2905889C9859C1470DD31896578575F349FC7139'.lower()

virus_list = [t1, v1, v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15,v16,v17,v18,v19,v20,v21,v22]

sus_path1 = []   #의심되는 파일 경로를 모아놓는 리스트
cantfind = []    #검사를 진행 할 수 없는 파일 경로를 모아놓는 리스트
allfilelist = [] #전체 검사한 파일 경로를 모아놓는 리스트

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
                print ('\033[91m' + 'is suspect' + '\033[31m')      #is suspect출력 (빨간색)
            else:                                                   #아니라면
                print('\033[93m' + 'no doubt' + '\033[33m')         #no doubt출력 (노란색)
        except:                                                     #예외가 발생했을 때
            print('\033[94m' + '예외가 발생하였습니다.' + '\033[34m')#예외가 발생하였습니다. 출력 (파란색)
            cantfind.append(file_path)                              #cantfind 리스트에 파일경로 추가



def interface():                                                    #사용자의 인터페이스 구성 함수

    btn1 = pyautogui.confirm('검사를 진행하시겠습니까?', 'vacin', buttons = ['전체 검사', '파일 경로 입력', '종료하기'])
    if btn1 == '전체 검사':
        root_dir = "C:/"
        vacin(root_dir, "")
        if not sus_path1:
            print('아무것도 없습니다.')
            print(str(len(sus_path1)) + '의심되는 파일 개수')
            print(str(len(cantfind)) + '검사 불가 파일 개수')
            print(str(len(allfilelist))+ '전체 검사한 파일 개수')
            print(hash)

            lensus = len(sus_path1)
            lencant = len(cantfind)
            lenfile= len(allfilelist)
            
            
            if lencant == 0:
                pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개', buttons = ['ok'], title = 'vacin')
            else:
                finishbtn = pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개\n검사가 불가능한 파일: ' + str(lencant) + '개 \n검사 불가능한 파일 경로를 보시겠습니까?', buttons = ['yes', 'no'], title = 'vacin')
                if finishbtn == 'yes':
                    pyautogui.confirm(str(cantfind), title = 'vacin')
                else:
                    print('종료합니다.')
        else:
            print('의심되는 파일이 존재합니다')
            print(str(len(sus_path1)) + '의심되는 파일 개수')
            print(str(len(cantfind)) + '검사 불가 파일 개수')
            print(str(len(allfilelist))+ '전체 검사한 파일 개수')
            print(hash)

            lensus = len(sus_path1)
            lencant = len(cantfind)
            lenfile= len(allfilelist)
            btn3 = pyautogui.confirm(text = '검사가 종료되었습니다. \n검사한 파일: '+  str(lenfile) + '개\n의심되는 파일: '+ str(lensus) + '개 \n의심되는 파일 경로: ' + str(sus_path1) +'\n의심되는 파일을 제거 할까요?', buttons = ['yes', 'no'], title = 'vacin')
            if btn3 == 'yes':
                for dlfdls in sus_path1:
                    os.remove.dlfdls
            else:
                print('종료합니다.')
    elif btn1 == '파일 경로 입력':

        btn4 = pyautogui.prompt(title='vacin', text= '파일 경로를 입력해주세요')
        if btn4 == '':
            print('종료합니다')
        else:
            try:
                btn4 = btn4.replace('\\','/')
                root_dir = btn4
                print(root_dir)
                vacin(root_dir, "")
                if not sus_path1:
                    print('아무것도 없습니다.')
                    print(str(len(sus_path1)) + '의심되는 파일 개수')
                    print(str(len(cantfind)) + '검사 불가 파일 개수')
                    print(str(len(allfilelist))+ '전체 검사한 파일 개수')
                    lensus = len(sus_path1)
                    lencant = len(cantfind)
                    lenfile= len(allfilelist)

                    
                    if lencant == 0:
                        pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개', buttons = ['ok'], title = 'vacin')
                    else:
                        finishbtn = pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개\n검사가 불가능한 파일: ' + str(lencant) + '개 \n검사 불가능한 파일 경로를 보시겠습니까?', buttons = ['yes', 'no'], title = 'vacin')
                        if finishbtn == 'yes':
                            pyautogui.confirm(str(cantfind), title = 'vacin')
                        else:
                            print('종료합니다.')
                else:
                    print('의심되는 파일이 존재합니다.')
                    print(str(len(sus_path1)) + '의심되는 파일 개수')
                    print(str(len(cantfind)) + '검사 불가 파일 개수')
                    print(str(len(allfilelist))+ '전체 검사한 파일 개수')
                    lensus = len(sus_path1)
                    lencant = len(cantfind)
                    lenfile= len(allfilelist)
                    btn3 = pyautogui.confirm(text = '검사가 종료되었습니다. \n검사한 파일: '+  str(lenfile) + '개\n의심되는 파일: '+ str(lensus) + '개 \n의심되는 파일 경로: ' + str(sus_path1) +'\n의심되는 파일을 제거 할까요?', buttons = ['yes', 'no'], title = 'vacin')
                    if btn3 == 'yes':
                        try:
                            print(sus_path1)
                            newlist = list(dict.fromkeys(sus_path1))
                            newlist1= [element.replace('\\', '/') for element in newlist]
                            print(newlist)
                            for susdir in newlist:
                                os.remove(susdir)
                                # shutil.rmtree(susdir)
                            pyautogui.alert(text= '제거가 완료되었습니다.')
                        except:
                            pyautogui.alert(text = '제거에 실패하였습니다.\n파일경로: ' +  str(newlist1))
                    else:
                        print('종료합니다.')
            except:
                print('종료합니다')
    else:
        print('종료합니다.')

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
    # interface()
    w = Target()
    w.run()
