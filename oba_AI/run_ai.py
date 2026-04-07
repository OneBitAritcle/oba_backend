import sys
sys.path.insert(0, '/app')
from app.services.ai_service import ai_service
print(ai_service.process_daily_articles())
