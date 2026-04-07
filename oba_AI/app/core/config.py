# oba_AI/app/core/config.py

import os
from dotenv import load_dotenv

load_dotenv()

class Settings:
    OPENAI_API_KEY: str = os.getenv("OPENAI_API_KEY")
    MONGODB_URI: str = os.getenv("MONGODB_URI")
    DB_NAME: str = "OneBitArticle"
    COLLECTION_NAME: str = "Selected_Articles"
    GPT_MODEL: str = "gpt-4o-mini"

    def validate(self):
        if not self.OPENAI_API_KEY:
            raise ValueError("OPENAI_API_KEY is missing!")
        if not self.MONGODB_URI:
            raise ValueError("MONGODB_URI is missing!")

settings = Settings()
settings.validate()