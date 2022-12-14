# vacin_project

# 프로그램 구동전 인스톨해야할 모듈
<p>pip install pyautogui</p>


## 작동원리

1. 컴퓨터의 C드라이브, 혹은 입력받은 경로의 모든 파일을 검사
2. 만약 폴더라면 폴더안의 파일을 검사
3. 파일의 sha256값을 구함
4. sha256의 값이 virus_list값 중 하나라도 같다면 sus_path1리스트에 저장
5. 아니라면 다음 파일 검사, 2번으로 돌아가기
6. 만약 파일의 해시값을 구할 수 없거나 오류가 생긴다면 cantfind리스트에 저장
7. 모든 파일을 전부 검사 할때까지 반복
8. 검사가 끝났을 때 sus_path에 값이 있다면 출력& 제거 요청
9. 아니라면 종료

## 알고리즘
<p align="center"><img src = "https://user-images.githubusercontent.com/73373959/201302202-25555509-0bca-4c17-a211-349b15673b1d.svg" width ="800" height="1308.6"/></p>

#### 변수

변수 이름| 정보|변수 타입
---| ---| ---|
virus_list | 실제 악성코드의 sha256값을 모아둔 리스트|list
sus_path1 | 의심되는 파일 경로를 모아놓는 리스트|list
cantfind | 검사를 진행 할 수 없는 파일 경로를 모아놓는 리스트|list
allfilelist | 전체 검사한 파일 경로를 모아놓는 리스트|list
root_dir | 파일 검사를 진행할 상위 경로|str
file_path | root_dir 안의 파일 경로|str
fp | file_path 읽기 모드 진입|
fread | fp읽기|
hash | sha256으로 설정|
sha256 | file_path의 sha256 값 저장|str
btn(숫자)| 인터페이스|
lensus | sus_path1 안의 개체 개수|str
lencant | cantfind 안의 개체 개수|str
lenfile | allfilelist 안의 개체 개수|str

#### 함수
함수 이름 | 정보
---|---|
scan| vacin에서 받은 파일 경로를 sha256값으로 변경하고 virus_lost와 겹치는 것이 있는지 확인
vacin|root_dir을 기본 경로로 그 속의 파일정보를 전부 출력
interface| 사용자의 인터페이스를 구성



### 실행 모습
<p align="center">1. 처음 프로그램을 실행하였을 때</p>
<p align="center"><img src = "https://user-images.githubusercontent.com/73373959/200122738-a1c7bdcb-d05c-4eef-b86c-a488f60269bc.png"/></p>
<br>
<p align="center">2. 파일 경로를 입력하였을 때</p>
<p align="center"><img src = "https://user-images.githubusercontent.com/73373959/200122735-847ea9a2-1691-4a36-b301-044c38ac8e04.png"/></p>
<br>
<p align="center">3. 검사가 종료 되었을 때</p>
<p align="center"><img src = "https://user-images.githubusercontent.com/73373959/200122737-f2486fb9-1494-4d30-beb6-d67559a1742b.png"/></p>
<p align="center">5. 제거가 완료된 모습
<p align="center"><img src = "https://user-images.githubusercontent.com/73373959/201461735-80bd73db-797b-4a19-bbf1-e8f6c2adfda1.png"/></p>
