# oba_AI/app/api/ai_controller.py

from fastapi import APIRouter
from app.schemas.gpt_schema import AnalyzeRequest
from app.services.ai_service import ai_service

router = APIRouter(prefix="/generate", tags=["AI"])

@router.post("/gpt_result")
def generate_gpt_result(req: AnalyzeRequest):
    """특정 Article ID에 대해 GPT 분석 수행"""
    result = ai_service.process_single_article(req.article_id)
    return {
        "status": "OK",
        "article_id": req.article_id,
        "gpt_result": result
    }

@router.post("/daily_gpt_results")
def generate_daily_gpt_results():
    """오늘 날짜 기사들에 대해 일괄 GPT 분석 수행 (스케줄러용)"""
    return ai_service.process_daily_articles()