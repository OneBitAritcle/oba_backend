# oba_AI/app/services/ai_service.py

import json
import re
from datetime import datetime
from bson.objectid import ObjectId
from bson.errors import InvalidId
from fastapi import HTTPException
from openai import OpenAI

from app.core.config import settings
from app.db.mongo import mongo_db
from app.schemas.gpt_schema import GptResponse

class AiService:
    def __init__(self):
        self.client = OpenAI(api_key=settings.OPENAI_API_KEY)
        self.collection = mongo_db.collection

    def _extract_article_text(self, content_blocks: list) -> str:
        """MongoDB의 content_col 구조에서 텍스트만 추출"""
        if not content_blocks:
            return ""
        
        flat_lines = [
            line.strip() 
            for block in content_blocks 
            if isinstance(block, list) 
            for line in block 
            if isinstance(line, str)
        ]
        return "\n".join(flat_lines)

    def _generate_gpt_content(self, article_text: str) -> dict:
        """OpenAI API 호출"""
        prompt = f"""
        다음 뉴스 내용을 기반으로 아래 요청을 수행해줘. 대상은 IT 직무 취업준비생이야.

        summary: 기사에서 전달하는 핵심 내용을 빠짐없이 포함하되, IT 취업준비생에게 특히 중요한 기술 동향·시장 변화·기업 전략 등을 중심으로 요약해줘.

        keywords: 기사 속에서 IT 취업준비생이 반드시 이해해야 하는 핵심 기술 개념 또는 최신 기술 트렌드를 10개 이내로 추출하고, 각 키워드는 신뢰할 수 있고 명확한 기술 설명을 붙여줘.

        quizzes: 기사를 읽고 학습한 내용을 점검할 수 있도록, 기사 내용 기반의 4지선다형 퀴즈 5개를 생성해줘. 각 퀴즈는 질문, 보기 4개, 정답 1개 (0~3 인덱스 번호가 아닌 정답 텍스트 혹은 번호 문자열), 정답과 오답에 대한 상세한 해설을 포함해야 해.

        결과물은 반드시 JSON 형식으로만 출력해야 하며, 마크다운 태그(```json)는 제외해.

        형식:
        {{
            "summary": "요약 내용",
            "keywords": [
                {{"keyword": "키워드", "description": "설명"}}
            ],
            "quizzes": [
                {{
                    "question": "질문",
                    "options": ["보기1", "보기2", "보기3", "보기4"],
                    "answer": "정답",
                    "explanation": "해설"
                }}
            ]
        }}

        뉴스 본문:
        \"\"\"{article_text[:7000]}\"\"\"
        """

        try:
            response = self.client.chat.completions.create(
                model=settings.GPT_MODEL,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7
            )
            raw_output = response.choices[0].message.content.strip()
            
            # Markdown code block 제거 (혹시 GPT가 붙일 경우 대비)
            clean_json = raw_output.replace("```json", "").replace("```", "").strip()
            
            result_dict = json.loads(clean_json)
            
            # Pydantic을 이용한 구조 검증 (선택 사항, 데이터 무결성 보장)
            GptResponse(**result_dict) 
            
            return result_dict

        except json.JSONDecodeError:
            raise HTTPException(status_code=500, detail="GPT 응답 JSON 파싱 실패")
        except Exception as e:
            print(f"GPT Error: {e}")
            raise HTTPException(status_code=500, detail=f"AI 서비스 오류: {str(e)}")

    def process_single_article(self, article_id: str):
        """단일 기사 처리 로직"""
        try:
            oid = ObjectId(article_id)
        except InvalidId:
            raise HTTPException(status_code=400, detail="유효하지 않은 Article ID입니다.")

        document = self.collection.find_one({"_id": oid})
        if not document:
            raise HTTPException(status_code=404, detail="기사를 찾을 수 없습니다.")

        article_text = self._extract_article_text(document.get("content_col", []))
        if not article_text:
            raise HTTPException(status_code=400, detail="기사 본문이 비어있습니다.")

        gpt_result = self._generate_gpt_content(article_text)

        # DB 업데이트
        self.collection.update_one(
            {"_id": oid}, 
            {"$set": {"gpt_result": gpt_result}}
        )

        return gpt_result

    def process_daily_articles(self):
        """오늘 날짜 기사 일괄 처리"""
        today = datetime.now().strftime("%Y-%m-%d")
        
        # 아직 gpt_result가 없는 오늘자 기사만 타겟팅하는 것이 효율적일 수 있음
        # 현재는 무조건 오늘자 5개 가져옴
        articles = list(self.collection.find({"serving_date": today}).limit(5))

        if not articles:
            return {"message": f"오늘({today}) 날짜의 처리할 기사가 없습니다."}

        processed_ids = []
        for article in articles:
            try:
                article_text = self._extract_article_text(article.get("content_col", []))
                if article_text:
                    gpt_result = self._generate_gpt_content(article_text)
                    self.collection.update_one(
                        {"_id": article["_id"]},
                        {"$set": {"gpt_result": gpt_result}}
                    )
                    processed_ids.append(str(article["_id"]))
            except Exception as e:
                print(f"Article {article['_id']} 처리 중 오류: {e}")
                continue

        return {
            "status": "OK",
            "processed_count": len(processed_ids),
            "processed_ids": processed_ids
        }

ai_service = AiService()