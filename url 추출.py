import re
import requests
import logging
from tqdm import tqdm
import ssl


def extract_urls_1(text_tokens):
    
    urls = []
    
    url_pattern = re.compile(r'\b(?:https?://|www\.)\S+\b')

    # 정규 표현식과 매치되는 모든 URL 추출
    for token in text_tokens:
        result = re.match(url_pattern, token)
        print(result)
        if result != None:
            urls.append(token)
    return urls

def extract_urls_2(token, urls2):
    try:
        response = requests.get('https://' + token, timeout=3, verify=False)
        if response.status_code == 200:
            urls2.append('https://' + token)
            return token
    except Exception as e:
        logging.error(f"HTTPS 연결 오류 - {token}: {e}")
        
    
    try:
        response = requests.get('http://' + token, timeout=3)
        if response.status_code == 200:
            urls2.append('http://' + token)
            return token
    except Exception as e:
        logging.error(f"HTTP 연결 오류 - {token}: {e}")

# 토큰화된 문자 텍스트 삽입
urls1 = extract_urls_1(text_tokens)

# 토큰화된 문자 텍스트와 url 리스트 삽입
for token in text_tokens:
    urls2 = [] 
    extract_urls_2(token, urls2)

urls = urls1+urls2
print(urls)
