# oba_AI/app/schemas/gpt_schema.py

from pydantic import BaseModel
from typing import List, Union

class Keyword(BaseModel):
    keyword: str
    description: str

class Quiz(BaseModel):
    question: str
    options: List[str]
    answer: Union[int, str]
    explanation: str

class GptResponse(BaseModel):
    summary: str
    keywords: List[Keyword]
    quizzes: List[Quiz]

class AnalyzeRequest(BaseModel):
    article_id: str