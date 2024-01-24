## 1. IMPORTING REQUIRED LIBRARIES

import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse


## 2. EXTRACTING FEATURES

# 피처 추출 후 features list에 저장
class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass


        

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainRegLen())
        self.features.append(self.Favicon())
        

        self.features.append(self.NonStdPort())
        self.features.append(self.HTTPSDomainURL())
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())
        self.features.append(self.InfoEmail())
        self.features.append(self.AbnormalURL())
        self.features.append(self.WebsiteForwarding())
        self.features.append(self.StatusBarCust())

        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.IframeRedirection())
        self.features.append(self.AgeofDomain())
        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())
        self.features.append(self.StatsReport())


    # 1.UsingIp
    # 현재 유효한 IP 주소인지 확인
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return -1
        except:
            return 1

    # 2.longUrl
    # url의 길이가 54 미만이면 1, 54 이상 75 이하면 0, 75 초과면 -1 반환
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1

    # 3.shortUrl
    # url이 축약 url의 보편적인 형태를 띄면 -1, 그렇지 않으면 1을 반환
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return -1
        return 1

    # 4.Symbol@
    # url 내에 '@'가 포함되어 있으면 -1, 그렇지 않으면 1 반환
    def symbol(self):
        if re.findall("@",self.url):
            return -1
        return 1
    
    # 5.Redirecting //
    # 오른쪽에서 처음 나타난 '//'의 인덱스가 6보다 크면 -1 반환
    def redirecting(self):
        if self.url.rfind('//')>6:
            return -1
        return 1
    
    # 6.prefixSuffix
    # url에 '-'이 포함되어 있으면 -1 반환
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
    # 7.SubDomains
    # '.'이 한번 포함되어 있으면 1 반환, 두번 포함되어 있으면 0 반환, 그 이상이거나 아예 없으면 -1 반환
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return 1
        elif dot_count == 2:
            return 0
        return -1

    # 8.HTTPS
    # url이 HTTPS 프로토콜을 사용하면 1 반환, 아니면 -1 반환
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return 1
            return -1
        except:
            return 1

    # 9.DomainRegLen
    # 도메인이 1년 이상 유지되었으면 1 반환, 아니면 -1 반환
    def DomainRegLen(self):
        try:
            expiration_date = self.whois_response.expiration_date
            creation_date = self.whois_response.creation_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                pass
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            age = (expiration_date.year-creation_date.year)*12+ (expiration_date.month-creation_date.month)
            if age >=12:
                return 1
            return -1
        except:
            return -1

    # 10. Favicon
    # url과 웹 페이지의 파비콘이 연관 있는지 확인하고 연관이 있다면 1 반환, 없다면 -1 반환
    # 파비콘 : 웹 사이트 아이콘
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or domain in head.link['href']:
                        return 1
            return -1
        except:
            return -1

    # 11. NonStdPort
    # 해당 도메인이 표준 포트를 사용하는지 확인, 사용하면 1 반환, 사용하지 않으면 -1 반환
    # 표준 포트는 포트 번호 생략함
    def NonStdPort(self):
        try:
            port = self.domain.split(":")
            if len(port)>1:
                return -1
            return 1
        except:
            return -1

    # 12. HTTPSDomainURL: HTTPS 프로토콜을 사용하면 -1 반환, 사용하지 않으면 1 반환
    def HTTPSDomainURL(self):
        try:
            if 'https' in self.domain:
                return -1
            return 1
        except:
            return -1
    
    # 13. RequestURL
    # 웹페이지에서 주로 요청하는 이미지, 오디오, 임베드, iframe의 요청이 성공했는지 여부를 확률로 나타내고
    # 22% 미만이면 -1, 22% 이상 61% 미만이면 0, 61% 이상이면 1 반환
    def RequestURL(self):
        try:
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success/float(i) * 100
                if percentage < 22.0:
                    return 1
                elif((percentage >= 22.0) and (percentage < 61.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1
    
    # 14. AnchorURL
    # 웹 페이지에서 <a> 태그의 'href'속성을 조사하여 특정 불안전 조건을 만족하면 위험도를 높임
    # 불안전 조건 : 'javascript' or 'mailto' 포함 / '#' 포함 / 주어진 url 미포함
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1

            try:
                percentage = unsafe / float(i) * 100
                if percentage < 31.0:
                    return 1
                elif ((percentage >= 31.0) and (percentage < 67.0)):
                    return 0
                else:
                    return -1
            except:
                return -1

        except:
            return -1

    # 15. LinksInScriptTags
    # 웹 페이지으 <link> 태그와 <script> 태그의 'href' 속성과 'src'이 특정 안전 조건을 만족하는 경우 안전도를 높임
    # 안전 조건 : url 포함 /  '.'이 하나만 존재

    def LinksInScriptTags(self):
        try:
            i,success = 0,0
        
            for link in self.soup.find_all('link', href=True):
                dots = [x.start(0) for x in re.finditer('\.', link['href'])]
                if self.url in link['href'] or self.domain in link['href'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for script in self.soup.find_all('script', src=True):
                dots = [x.start(0) for x in re.finditer('\.', script['src'])]
                if self.url in script['src'] or self.domain in script['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            try:
                percentage = success / float(i) * 100
                if percentage < 17.0:
                    return 1
                elif((percentage >= 17.0) and (percentage < 81.0)):
                    return 0
                else:
                    return -1
            except:
                return 0
        except:
            return -1

  
    # 16. ServerFormHandler: 사이트에 서버로의 폼 핸들링이 있는지 탐색
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1 #폼이 없을 시 정상 사이트
            else : #폼에 액션 속성이 비어 있거나 about:blank인 경우 악성으로 간주
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

    # 17. InfoEmail: 정규표현식을 이용해 소스코드 내 이메일 주소 찾아냄
    def InfoEmail(self):
        try:
            if re.findall(r"[mail\(\)|mailto:?]", self.soap):
                return -1 #이메일 주소가 있을 시 악성으로 간주
            else:
                return 1
        except:
            return -1

    # 18. AbnormalURL : 현재 웹페이지와 whois에 등록된 정보가 같은지 체크
    def AbnormalURL(self):
        try:
            if self.response.text == self.whois_response:
                return 1 #같다면 정상
            else:
                return -1 #다를시 악성
        except:
            return -1

    # 19. WebsiteForwarding:리다이렉션 수를 카운트
    def WebsiteForwarding(self):
        try:
            if len(self.response.history) <= 1: #1이하는 정상
                return 1
            elif len(self.response.history) <= 4: #2~4는 0
                return 0
            else: #5이상 악성
                return -1
        except:
             return -1

    # 20. StatusBarCust:마우스를 특정 요소 위에 가져다놓으면 실행되는 이벤트(마우스오버이벤트)가 있는지 체크
    def StatusBarCust(self):
        try:
            if re.findall("<script>.+onmouseover.+</script>", self.response.text):
                return 1 #마우스오버 이벤트가 있으면 정상 사이트로 간주
            else:
                return -1
        except:
             return -1

    # 21. DisableRightClick: 악성사이트는 우클릭을 막아 놓는 경우가 많이 우클릭이 가능한지 체크함
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return 1 #우클릭 가능할시 저상 사이트
            else:
                return -1
        except:
             return -1

    # 22. UsingPopupWindow: 해당페이지에 팝업창이 있는지
    def UsingPopupWindow(self):
        try: #자바스크립트에서 alert()는 팝업을 띄움->해당 코드가 포함되어 있는지 판별->있을시 악성
            if re.findall(r"alert\(", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 23. IframeRedirection 외부문서가 해당 페이지에 삽입되어 있는지
    #chat gpt 패셜 정규표현식이 틀렸다고 함 만약 사용한다면 삭제하거나 수정할것!
    def IframeRedirection(self):
        try: #url에 iframe, frameBorder 이 포함->다른 페이지가 삽입되어 있음->악성으로 간주
            if re.findall(r"[<iframe>|<frameBorder>]", self.response.text):
                return 1
            else:
                return -1
        except:
             return -1

    # 24. AgeofDomain: whois 사이트를 통해 해당 도메인이 생성된 기간을 6개월을 기준으로 판단
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass

            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6: #받아온 날짜가 6개월 이상이여야 정상 사이트로 판단
                return 1
            return -1
        except:
            return -1

    # 25. DNSRecording->DNS 레코딩에 등록된 기간을  6개월을 기준으로 판단
    def DNSRecording(self):
        try:
            creation_date = self.whois_response.creation_date #도메인 생성 날짜를 받아옴
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except: #등록x 도메인이면 패스
                pass

            #오늘 날짜기준으로 6개월이 지났는지 계산
            today  = date.today() 
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return 1
            return -1
        except:
            return -1

    # 26. WebsiteTraffic   웹사이트 트래픽으로 정상인지 판단
    def WebsiteTraffic(self):
        try: #alexa.com으로 부터 트래픽 수를 받아옴->XML 형태로 파싱 reach 태그의 rank 추출
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000): #100000 미만이면 정상
                return 1
            return 0
        except :
            return -1

    # 27. PageRank 페이지 랭크가 높을수록 검색결과가 많이 나옴->신뢰할만한 사이트라고 판단할 수 있음
    def PageRank(self):
        try: #도메인에 post 요청을 보냄
            prank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {"name": self.domain})
            #도메인의 페이지 랭크를 받음
            global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            if global_rank > 0 and global_rank < 100000:
                return 1 #랭크가  0초과 100000 미만일때 정상으로 판단
            return -1
        except:
            return -1
            

    # 28. GoogleIndex 해당 페이지가 구글의 db에 등록되었는지(=인덱싱되었는지)판단. 인덱싱될 경우 구글 검색결과가 있음
    def GoogleIndex(self):
        try: #구글에 인덱싱 되어 있다면 정상, 아니면 악성
            site = search(self.url, 5)
            if site:
                return 1
            else:
                return -1
        except:
            return 1

    # 29. LinksPointingToPage해당 페이지에 연결된 링크의 개수를 카운트
    def LinksPointingToPage(self):
        try: #url 내 다른 페이지로 연결되는 html 코드의 개수를 카운트 해서 판별
            number_of_links = len(re.findall(r"<a href=", self.response.text))
            if number_of_links == 0: #링크가 없을시->정상
                return 1
            elif number_of_links <= 2: #2개 이하->의심
                return 0
            else: #그외->악성
                return -1
        except:
            return -1

    # 30. StatsReport 악성코드 도메인에 자주 쓰이는 문자열/ip를 걸러냄
    def StatsReport(self):
        try:
            url_match = re.search(#해당 도메인에 다음과 같은 문자열(ex: at.ua, usa.cc)이 포함되어 있다면 악성으로 간주
        'at\.ua|usa\.cc|baltazarpresentes\.com\.br|pe\.hu|esy\.es|hol\.es|sweddy\.com|myjino\.ru|96\.lt|ow\.ly', url)
            ip_address = socket.gethostbyname(self.domain) #갖고 있는 도메인을 ipv4 형식 주소로 땀
            #이미 알려진 악성url ip와 일치하는지 대조
            ip_match = re.search('146\.112\.61\.108|213\.174\.157\.151|121\.50\.168\.88|192\.185\.217\.116|78\.46\.211\.158|181\.174\.165\.13|46\.242\.145\.103|121\.50\.168\.40|83\.125\.22\.219|46\.242\.145\.98|'
                                '107\.151\.148\.44|107\.151\.148\.107|64\.70\.19\.203|199\.184\.144\.27|107\.151\.148\.108|107\.151\.148\.109|119\.28\.52\.61|54\.83\.43\.69|52\.69\.166\.231|216\.58\.192\.225|'
                                '118\.184\.25\.86|67\.208\.74\.71|23\.253\.126\.58|104\.239\.157\.210|175\.126\.123\.219|141\.8\.224\.221|10\.10\.10\.10|43\.229\.108\.32|103\.232\.215\.140|69\.172\.201\.153|'
                                '216\.218\.185\.162|54\.225\.104\.146|103\.243\.24\.98|199\.59\.243\.120|31\.170\.160\.61|213\.19\.128\.77|62\.113\.226\.131|208\.100\.26\.234|195\.16\.127\.102|195\.16\.127\.157|'
                                '34\.196\.13\.28|103\.224\.212\.222|172\.217\.4\.225|54\.72\.9\.51|192\.64\.147\.141|198\.200\.56\.183|23\.253\.164\.103|52\.48\.191\.26|52\.214\.197\.72|87\.98\.255\.18|209\.99\.17\.27|'
                                '216\.38\.62\.18|104\.130\.124\.96|47\.89\.58\.141|78\.46\.211\.158|54\.86\.225\.156|54\.82\.156\.19|37\.157\.192\.102|204\.11\.56\.48|110\.34\.231\.42', ip_address)
            if url_match:#url에 악성 패턴이 나타난다-> -1반환
                return -1
            elif ip_match: #악성ip 주소와 일치한다->-1반환
                return -1
            return 1
        except:
            return 1
    
    def getFeaturesList(self): #0,-1,1로 구성된 배열 값을 반환
        return self.features
