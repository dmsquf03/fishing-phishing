# fishing-phishing

빅데이터 활용 미래 사회문제 해결 아이디어 해커톤 <br><br>

## 🗄️ Dataset

+ 스팸 문자
+ 피싱사이트 url
+ 정상사이트 url

## ✂️ 데이터 전처리

스팸문자 url
- 중복 제거 필요

피싱 url
- 피싱공격_IP_도메인 : IP만 제공되는 것이 많아 url 있는 행 외에 삭제 필요
- 스미싱공격_IP_도메인 : 스미싱 url 클릭 방지를 위해 http -> hxxp, https -> hxxps 되어 있음. 원복 필요
- 한국인터넷진흥원 : http, https 없는 url 존재. 처리 필요

정상 url
- 기관 관련 url 화이트리스트 필요


## 📂 Directory Structure

```
 📂 dataset    ▶︎ 피싱, 정상 사이트 url 데이터
```
