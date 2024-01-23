import pandas as pd
import requests
import threading
import queue
import logging
from tqdm import tqdm

# 로깅 설정
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# DataFrame. # 파일 이름 변경하기!
df = pd.read_csv('domains_part_.csv', encoding='utf-8')

# 결과를 저장할 큐
results = queue.Queue()

# https 연결되는지 확인 함수
def check_https(domain, index):
    try:
        response = requests.get('https://' + domain, timeout=3)
        if response.status_code == 200:
            results.put((index, 'https://' + domain))
            return
    except Exception as e:
        logging.error(f"HTTPS 연결 오류 - {domain}: {e}")

    try:
        response = requests.get('http://' + domain, timeout=3)
        if response.status_code == 200:
            results.put((index, 'http://' + domain))
            return
    except Exception as e:
        logging.error(f"HTTP 연결 오류 - {domain}: {e}")

    results.put((index, domain))

# 스레드에서 실행할 작업
def worker():
    while True:
        item = domain_queue.get()
        if item is None:
            break
        domain, index = item
        check_https(domain, index)
        domain_queue.task_done()

# 도메인 큐 생성
domain_queue = queue.Queue()
for i, domain in enumerate(df['domain']):
    domain_queue.put((domain, i))

# 스레드 생성 및 시작
num_threads = 10
threads = []
for _ in range(num_threads):
    t = threading.Thread(target=worker)
    t.start()
    threads.append(t)

# 진행률 표시
pbar = tqdm(total=len(df['domain']), desc="도메인 검사 진행")

# 결과 처리 및 파일 저장
file_count = 0
while True:
    try:
        index, url = results.get(timeout=10)
        df.loc[index, 'url'] = url
        pbar.update(1)
        if (index + 1) % 1000 == 0 or index == len(df['domain']) - 1:
            file_name = f'updated_domains_{file_count}.csv'
            df.iloc[file_count*1000:(index+1)].to_csv(file_name, index=False, encoding='utf-8')
            logging.info(f"파일 저장됨: {file_name}")
            file_count += 1
    except queue.Empty:
        break

# 모든 스레드 종료
for _ in range(num_threads):
    domain_queue.put(None)
for t in threads:
    t.join()

pbar.close()
