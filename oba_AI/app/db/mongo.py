# oba_AI/app/db/mongo.py

from pymongo import MongoClient
from app.core.config import settings

class MongoDB:
    def __init__(self):
        self.client = MongoClient(settings.MONGODB_URI)
        self.db = self.client[settings.DB_NAME]
        self.collection = self.db[settings.COLLECTION_NAME]

# 인스턴스 생성 (import해서 사용)
mongo_db = MongoDB()