# fishing-phishing

빅데이터 활용 미래 사회문제 해결 아이디어 해커톤 <br><br>

스미싱 문자, 악성 URL 판별 및 관련 교육, 신고 기능을 탑재한 'Fishing Phishing' 앱/웹 <br><br>

# ✨ Fishing Phishing Structure

### App/Web Structure
<img width="777" alt="image" src="https://github.com/dmsquf03/fishing-phishing/assets/99008137/6f67057e-6a9d-4618-b1cb-6634f61d6c4c">
<br>

### ML Structure
<img width="776" alt="image" src="https://github.com/dmsquf03/fishing-phishing/assets/99008137/82c3abe0-cb76-4f13-a357-f0e4f4cd2fa3">
<br>

## 🗄️ Dataset

+ 스팸 문자
-- KT 통신 빅데이터 플랫폼, 한국진흥원, https://www.bigdata-telecom.kr/invoke/SOKBP2603/?goodsCode=KIS00000000000000022
  <br>
  
+ 피싱사이트 url
-- 피싱공격 : KT 통신 빅데이터 플랫폼, 한국진흥원, https://bdp.kt.co.kr/invoke/SOKBP2603/?goodsCode=KIS00000000000000008
  <br>
-- 스미싱공격 : KT 통신 빅데이터 플랫폼, 한국진흥원, https://bdp.kt.co.kr/invoke/SOKBP2603/?goodsCode=KIS00000000000000009
  <br>
  
+ 정상사이트 url
-- Top 20000 Domains data  출처: https://radar.cloudflare.com/domains
<br>

## 📂 Directory Structure

```
 📂 fishing-phishing
├─ 📂 App         ▶︎ 피싱피싱 앱의 화면, 로고
├─ 📂 Dataset     ▶︎ 머신 러닝에 사용한 url 데이터셋
│  ├─ 📂 정상 url 
│  ├─ 📂 피싱 url
│  ├─ 📂 학습 url
│  └─ 휴대전화 스팸트랩 문자 수집 내역.zip
├─ 📂 DB          ▶︎ database 올라가 있는 파일
│  ├─ 📂 whitelist
│  └─ keywords_list.csv
├─ 📂 ML          ▶︎ ML 모델, 실행함수 정의 파일
└─ README.md
```
