import os

root_dir = 'C:/' #경로설정
item_list = os.listdir(root_dir) #아이템 리스트 나열

for item in item_list:
    path = root_dir + '/' + item
    
    if os.path.isfile:
        if sha256 == virus_list:  #sha256, virus_list 코드 추가하기
            sus_path1 = path
        else:
            print(path+'is not suspect')
            
    if os.path.isdir(path):
        dir_path = path
        diritem_list = os.listdir(dir_path)
        
        for diritem in diritem_list:
            file-path= dir_path + '/' +diritem
        
