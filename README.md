# vacin_project

## 작동원리

### 1. 컴퓨터의 C드라이브, 혹은 입력받은 경로의 모든 파일을 검사
### 2. 만약 폴더라면 폴더안의 파일을 검사
### 3. 파일의 sha256값을 구함
### 4. sha256의 값이 virus_list값 중 하나라도 같다면 sus_path1리스트에 저장
### 5. 아니라면 다음 파일 검사, 2번으로 돌아가기
### 6. 만약 파일의 해시값을 구할 수 없거나 오류가 생긴다면 cantfind리스트에 저장
### 7. 모든 파일을 전부 검사 할때까지 반복
### 8. 검사가 끝났을 때 sus_path에 값이 있다면 출력& 제거 요청
### 9. 아니라면 종료


변수 이름| 정보
---| ---|
virus_list | 실제 악성코드의 sha256값을 모아둔 리스트
sus_path1 | 의심되는 파일 경로를 모아놓는 리스트
cantfind | 검사를 진행 할 수 없는 파일 경로를 모아놓는 리스트
allfilelist | 전체 검사한 파일 경로를 모아놓는 리스트
root_dir | 파일 검사를 진행할 상위 경로
file_path | root_dir 안의 파일 경로
fp | file_path 읽기 모드 진입
fread | fp읽기
hash | sha256으로 설정
sha256 | file_path의 sha256 값 저장
btn(숫자)| 인터페이스
lensus | sus_path1 안의 개체 개수
lencant | cantfind 안의 개체 개수
lenfile | allfilelist 안의 개체 개수


![2](https://user-images.githubusercontent.com/73373959/200122735-847ea9a2-1691-4a36-b301-044c38ac8e04.png)
![3](https://user-images.githubusercontent.com/73373959/200122737-f2486fb9-1494-4d30-beb6-d67559a1742b.png)
![1](https://user-images.githubusercontent.com/73373959/200122738-a1c7bdcb-d05c-4eef-b86c-a488f60269bc.png)
