# phishing_site_url 탐지 ML

빅데이터 활용 미래 사회문제 해결 아이디어 해커톤 <br><br>

## 🗄️ Dataset

+ 피싱사이트 url
+ 정상사이트 url

## ✂️ 데이터 전처리
- 피싱공격_IP_도메인 dataset : IP만 제공되는 것이 많아 url 있는 행 외에 삭제 필요.
- 스미싱공격_IP_도메인 dataset : 스미싱 url 클릭 방지를 위해 http -> hxxp, https -> hxxps 되어 있음. 원복 필요

## 📂 Directory Structure

```
 📂 dataset    ▶︎ 피싱, 정상 사이트 url 데이터
```
