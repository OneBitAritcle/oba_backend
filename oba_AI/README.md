# OBA AI Service (FastAPI 기반 AI 분석 서버)

이 레포지토리는 **OBA(One Bite Article)** 프로젝트의 AI 분석 기능을 담당하는 **독립된 FastAPI 기반 서버**입니다.

뉴스 기사 본문을 기반으로 OpenAI GPT를 활용해 요약, 핵심 키워드, 퀴즈 등을 자동으로 생성하며  MongoDB에 저장합니다.

---

## 구성 요소

| 구성요소 | 역할 |
|---------|------|
| **FastAPI (app.py)** | GPT 분석 API, MongoDB 연동 |
| **Dockerfile** | FastAPI 컨테이너 이미지 빌드 |
| **docker-compose.yml** | FastAPI + MongoDB + Nginx 전체 환경 구성 |
| **nginx.conf** | 프론트 요청 → FastAPI 라우팅 |
| **index.html** | 테스트용 간단 UI |
| **requirements.txt** | Python 의존성 목록 |
| **.env** | OpenAI API Key 및 MongoDB URI (Git 추적 제외) |

---

## API 주요 기능

## 1) 단일 기사 분석 (POST /generate_gpt_result)
- MongoDB에서 기사 조회  
- 기사 본문(content_col) 평탄화  
- GPT 요약/키워드/퀴즈 생성  
- DB에 `gpt_result` 저장  


## 2) 오늘 날짜 기사 5개 자동 분석 (POST /generate_daily_gpt_results)
- serving_date가 오늘인 기사 5개 자동 처리  
- 결과 자동 저장  

