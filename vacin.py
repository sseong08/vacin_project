import os
import hashlib
import glob



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

virus_list= [v1, v2,v3,v4,v5,v6,v7,v8,v9,v10,v11,v12,v13,v14,v15,v16,v17,v18,v19,v20,v21,v22]


root_dir = 'C:/'
item_list = os.listdir(root_dir) #아이템 리스트 나열

for item in item_list:
    path = root_dir + '/' + item
    
    if os.path.isfile:
        fp = open('readme.txt','rb') #바이너리 모드로 읽기 위해 r뒤에 b를 붙임
        fread = fp.read() #파일을 읽음
        fp.close() #파일을 닫음
        hash=hashlib.sha256()
        hash.update(fread)
        sha256 = hash.hexdigest()
    if any(sha256 == s for s in virus_list):
        if sha256 == virus_list:  #sha256, virus_list 코드 추가하기
            sus_path1 = path
        else:
            print(path+'is not suspect')
            
    if os.path.isdir(path):  #만약 파일이라면
        dir_path = path  #파일 주소를 dir_path변수에 저장
        diritem_list = os.listdir(dir_path)  #dir_path item 정렬
        
        for diritem in diritem_list:
            file_path= dir_path + '/' +diritem
# file_list = os.listdir('C:/')
# for file in file_list:
#     print(file_list)
#     fp = open('readme.txt','rb') #바이너리 모드로 읽기 위해 r뒤에 b를 붙임
#     fread = fp.read() #파일을 읽음
#     fp.close() #파일을 닫음
#     hash=hashlib.sha256()
#     hash.update(fread)
#     sha256 = hash.hexdigest()
#     if any(sha256 == s for s in virus_list):
#        print('yes')
#     else:
#       print('no')
# # file_list = glob.glob('*.*')
# # print(file_list)
