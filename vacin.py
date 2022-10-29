import os
import pyautogui
import hashlib

v1  = 'ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa'
v2  ='c365ddaa345cfcaff3d629505572a484cff5221933d68e4a52130b8bb7badaf9'
v3  ='09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa'
v4  ='0a73291ab5607aef7db23863cf8e72f55bcb3c273bb47f00edf011515aeb5894'
v5  ='428f22a9afd2797ede7c0583d34a052c32693cbb55f567a60298587b6e675c6f'
v6  ='5c1f4f69c45cff9725d9969f9ffcf79d07bd0f624e06cfa5bcbacd2211046ed6'
v7  ='62d828ee000e44f670ba322644c2351fe31af5b88a98f2b2ce27e423dcf1d1b1'
v8  ='72af12d8139a80f317e851a60027fdf20887334c12637f49d819ab4b033dd'
v9  ='85ce324b8f78021ecfc9b811c748f19b82e61bb093ff64f2eab457f9ef19b186'
v10  ='a1d9cd6f189beff28a0a49b10f8fe4510128471f004b3e4283ddc7f78594906b'
v11 ='a93ee7ea13238bd038bcbec635f39619db566145498fe6e0ea60e6e76d614bd3'
v12 ='b43b234012b8233b3df6adb7c0a3b2b13cc2354dd6de27e092873bf58af2693c'
v13 ='eb47cd6a937221411bb8daf35900a9897fb234160087089a064066a65f42bcd4'
v14 ='24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c'
v15 ='2c2d8bc91564050cf073745f1b117f4ffdd6470e87166abdfcd10ecdff040a2e'
v16 ='7a828afd2abf153d840938090d498072b7e507c7021e4cdd8c6baf727cafc545'
v17 ='a897345b68191fd36f8cefb52e6a77acb2367432abb648b9ae0a9d708406de5b'
v18 ='b0b6044347e972e21b6c376e37e1115dab494a2c6b9fb28b92b1e45b45d0ebc'
v19 ='9588f2ef06b7e1c8509f32d8eddfa18041a9cc15b1c90d6da484a39f8dcdf967'
v20 ='b43b234012b8233b3df6adb7c0a3b2b13cc2354dd6de27e092873bf58af2693c'
v21 ='4186675cb6706f9d51167fb0f14cd3f8fcfb0065093f62b10a15f7d9a6c8d982'
v22 ='09a46b3e1be080745a6d8d88d6b5bd351b1c7586ae0dc94d0c238ee36421cafa'
t1 = '288B12A8600419F900747353BCC50D6F3C85290BA0F3DECDEC8B3401A2ABEA97'

virus_list= [t1, v1, v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15,v16,v17,v18,v19,v20,v21,v22]

sus_path1 = []
cantfind = []
allfilelist = []
def scan():
        try:
            global sus_path1
            fp = open(path, 'rb')
            fread = fp.read()
            fp.close
            hash=hashlib.sha256()
            hash.update(fread)
            sha256 = hash.hexdigest()
            allfilelist.append(file_path)
            # if any(sha256 == s for s in virus_list):
            if any(str in sha256 for str in virus_list):
                sus_path1.append(file_path)
                print ('\033[91m' + 'is suspect' + '\033[31m')
            else:
                print('\033[93m' + 'no doubt' + '\033[33m')

        except:
            print('\033[94m' + '예외가 발생하였습니다.' + '\033[34m')
            cantfind.append(file_path)

def vacin(root_dir, prefix):
    try:
        global path
        global file_path
        files = os.listdir(root_dir)
        for file in files:
            path = os.path.join(root_dir, file)
            file_path = prefix + path
            print(file_path)
            scan()
            if os.path.isdir(path):
                vacin(path, prefix)
                scan()
    except:
       print("파일탐색중 에러가 났습니다.")

def interface():
    btn1 = pyautogui.confirm('검사를 진행하시겠습니까?', 'vacin', buttons = ['yes', 'no'])
    if btn1 == 'yes':
        vacin(root_dir, "")
        if not sus_path1:
            print('아무것도 없습니다.')
            print(str(len(sus_path1)) + '의심되는 파일 개수')
            print(str(len(cantfind)) + '검사 불가 파일 개수')
            print(str(len(allfilelist))+ '전체 검사한 파일 개수')

            lensus = len(sus_path1)
            lencant = len(cantfind)
            lenfile= len(allfilelist)

            finishbtn = pyautogui.confirm('검사가 종료되었습니다. \n검사한 파일: '+str(lenfile)+'개\n의심되는 파일:' + str(lensus) + '개\n검사가 불가능한 파일: ' + str(lencant) + '개 \n검사 불가능한 파일 경로를 보시겠습니까?', buttons = ['yes', 'no'], title = 'vacin')
            if finishbtn == 'yes':
                pyautogui.confirm(str(cantfind), title = 'vacin')
            else:
                print('종료합니다.')
        else:
            print(sus_path1)
            btn3 = pyautogui.confirm(text = '검사가 종료되었습니다. \n검사한 파일: '+  str(lenfile) + '개\n의심되는 파일: '+ str(lensus) + '개 \n의심되는 파일 경로: ' + str(sus_path1) +'\n의심되는 파일을 제거 할까요?', buttons = ['yes', 'no'], title = 'vacin')
            if btn3 == 'yes':
                for dlfdls in sus_path1:
                    os.remove.dlfdls
            else:
                print('종료합니다.')
    else:
        print('종료합니다.')

if __name__ == "__main__":
    root_dir = "C:/Users/kkhhs/Downloads"
    # vacin(root_dir, "")
    interface()
