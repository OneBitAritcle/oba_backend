# OBA Project - API 명세서

> 학습 리포트 화면(Report Page) 및 마이페이지(My Page)의 백엔드 API 명세

---

## 📋 API 목록

| 번호 | 엔드포인트 | HTTP 메서드 | 설명 | 대응 컴포넌트 |
|-----|----------|----------|------|------------|
| 1 | `/api/report/stats` | GET | 사용자 통계 (연속학습일, 최고기록, 퍼펙트데이) | ReportStats |
| 2 | `/api/report/progress` | GET | 전체 학습 진도 (푼 문제/전체 문제) | ProgressBar |
| 3 | `/api/report/daily-stats` | GET | 요일별 정답률 (최근 7일) | DailyChart |
| 4 | `/api/report/category-progress` | GET | 카테고리별 정답률 | CategoryProgress |
| 5 | `/api/feedback` | POST | 고객 소리함 전송 | MyPage (Feedback Modal) |

---

## 🔐 인증 & 공통사항

- **인증**: Bearer Token (JWT) - Authorization Header 필수
  - **중요**: 모든 API는 JWT 토큰에서 **사용자 ID를 자동으로 추출**
  - 백엔드에서 JWT를 디코딩하여 user_id를 특정
  - 프론트엔드는 user_id를 Query Parameter로 전달하지 않음
  
- **요청 응답 형식**: JSON
- **Timestamp 형식**: ISO 8601 (YYYY-MM-DD'T'HH:mm:ss'Z')
- **에러 응답**:
  ```json
  {
    "code": "ERROR_CODE",
    "message": "에러 메시지",
    "timestamp": "2026-02-12T10:30:00Z"
  }
  ```

### JWT 토큰 검증 플로우

```
프론트엔드: Authorization: Bearer {JWT_TOKEN}
         ↓
백엔드: JWT 토큰 검증
     ↓
    JWT 디코딩 → user_id 추출
     ↓
    해당 user_id의 데이터 조회
```

---

## 1️⃣ 사용자 통계 조회

### Endpoint
```
GET /api/report/stats
```

### Description
사용자의 학습 통계 정보 조회 (User_Stats 테이블 기반)

### Request

**Headers**
```
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json
```

**Query Parameters**
없음 (사용자 ID는 JWT 토큰에서 자동으로 추출)

### Response

**Status: 200 OK**
```json
{
  "code": "SUCCESS",
  "message": "통계 조회 성공",
  "data": {
    "consecutiveDays": 12,
    "maxConsecutiveDays": 28,
    "perfectDays": 16,
    "lastLearnedAt": "2026-02-12"
  },
  "timestamp": "2026-02-12T10:30:00Z"
}
```

### Response Field Description

| 필드명 | 타입 | 설명 | DB 매핑 |
|-------|------|------|--------|
| consecutiveDays | INT | 현재 연속 학습 일수 | User_Stats.current_streak |
| maxConsecutiveDays | INT | 역대 최고 연속 학습 일수 | User_Stats.max_streak |
| perfectDays | INT | 5개 기사 모두 완독한 총 일수 | User_Stats.total_perfect_days |
| lastLearnedAt | DATE | 마지막 학습 날짜 (YYYY-MM-DD) | User_Stats.last_learned_at |

### Error Cases

| Status | Code | Message | 설명 |
|--------|------|---------|------|
| 401 | UNAUTHORIZED | JWT 토큰이 없거나 유효하지 않음 | Authorization 헤더 확인 필요 |
| 401 | INVALID_TOKEN | 토큰 만료 또는 서명 검증 실패 | 새로운 토큰 요청 필요 |
| 404 | NOT_FOUND | 사용자 통계 데이터 없음 | 해당 사용자의 데이터 없음 |
| 500 | INTERNAL_ERROR | 서버 에러 | 서버 로그 확인 필요 |

### Example Usage (Frontend)
```typescript
const response = await apiClient.get("/api/report/stats");
setReportStats({
  consecutiveDays: response.data.consecutiveDays,
  maxConsecutiveDays: response.data.maxConsecutiveDays,
  perfectDays: response.data.perfectDays,
});
```

---

## 2️⃣ 전체 학습 진도 조회

### Endpoint
```
GET /api/report/progress
```

### Description
사용자가 푼 전체 문제(`correct_quizzes`) / 전체 문제 수(`total_quizzes`)를 조회합니다.
(User_Category_Stats 테이블의 모든 카테고리 합계)

### Request

**Headers**
```
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json
```

**Query Parameters**
없음 (사용자 ID는 JWT 토큰에서 자동으로 추출)

### Response

**Status: 200 OK**
```json
{
  "code": "SUCCESS",
  "message": "진도 조회 성공",
  "data": {
    "solvedCount": 150,
    "totalCount": 200,
    "progressPercentage": 75
  },
  "timestamp": "2026-02-12T10:30:00Z"
}
```

### Response Field Description

| 필드명 | 타입 | 설명 | DB 매핑 |
|-------|------|------|--------|
| solvedCount | INT | 모든 카테고리의 정답 문제 총 개수 | SUM(User_Category_Stats.correct_quizzes) |
| totalCount | INT | 모든 카테고리의 풀이 문제 총 개수 | SUM(User_Category_Stats.total_quizzes) |
| progressPercentage | INT | 진도율 (0~100, 백엔드에서 계산) | (solvedCount / totalCount) * 100 |

### Calculation Rule
```
progressPercentage = floor((solvedCount / totalCount) * 100)
if totalCount === 0 → progressPercentage = 0
```

### Error Cases

| Status | Code | Message | 설명 |
|--------|------|---------|------|
| 401 | UNAUTHORIZED | JWT 토큰이 없거나 유효하지 않음 | Authorization 헤더 확인 필요 |
| 401 | INVALID_TOKEN | 토큰 만료 또는 서명 검증 실패 | 새로운 토큰 요청 필요 |
| 404 | NOT_FOUND | 사용자 진도 데이터 없음 | 해당 사용자의 데이터 없음 |
| 500 | INTERNAL_ERROR | 서버 에러 | 서버 로그 확인 필요 |

### Example Usage (Frontend)
```typescript
const response = await apiClient.get("/api/report/progress");
setProgressBar({
  solvedCount: response.data.solvedCount,
  totalCount: response.data.totalCount,
});
```

---

## 3️⃣ 요일별 정답률 조회

### Endpoint
```
GET /api/report/daily-stats
```

### Description
최근 7일간 요일별 정답률(`accuracy`)을 조회합니다.
(Article_Logs + Incorrect_Quiz 기반, 일별 집계)

### Request

**Headers**
```
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json
```

**Query Parameters**
| 파라미터 | 타입 | 필수 | 설명 |
|---------|------|------|------|
| days | INT | ❌ | 조회할 일수 (기본값: 7, 1~365 범위) |

**주의**: user_id는 JWT 토큰에서 자동으로 추출

### Response

**Status: 200 OK**
```json
{
  "code": "SUCCESS",
  "message": "요일별 정답률 조회 성공",
  "data": [
    {
      "date": "2026-02-09",
      "day": "Mon",
      "accuracy": 60,
      "attemptedQuizzes": 5,
      "correctQuizzes": 3
    },
    {
      "date": "2026-02-10",
      "day": "Tue",
      "accuracy": 50,
      "attemptedQuizzes": 4,
      "correctQuizzes": 2
    },
    {
      "date": "2026-02-11",
      "day": "Wed",
      "accuracy": 75,
      "attemptedQuizzes": 4,
      "correctQuizzes": 3
    },
    {
      "date": "2026-02-12",
      "day": "Thu",
      "accuracy": 65,
      "attemptedQuizzes": 17,
      "correctQuizzes": 11
    },
    {
      "date": "2026-02-13",
      "day": "Fri",
      "accuracy": 90,
      "attemptedQuizzes": 10,
      "correctQuizzes": 9
    },
    {
      "date": "2026-02-14",
      "day": "Sat",
      "accuracy": 100,
      "attemptedQuizzes": 5,
      "correctQuizzes": 5
    },
    {
      "date": "2026-02-15",
      "day": "Sun",
      "accuracy": 80,
      "attemptedQuizzes": 10,
      "correctQuizzes": 8
    }
  ],
  "timestamp": "2026-02-12T10:30:00Z"
}
```

### Response Field Description

| 필드명 | 타입 | 설명 | DB 매핑 |
|-------|------|------|--------|
| date | DATE | 해당 날짜 (YYYY-MM-DD) | Article_Logs의 initial_at 기준 |
| day | STRING | 요일 (Mon/Tue/Wed/Thu/Fri/Sat/Sun) | date 기반 계산 |
| accuracy | INT | 해당 날짜 정답률 (0~100) | (correctQuizzes / attemptedQuizzes) * 100 |
| attemptedQuizzes | INT | 해당 날짜 풀이한 문제 수 | Incorrect_Quiz 레코드당 1개 계산 |
| correctQuizzes | INT | 해당 날짜 맞춘 문제 수 | SUM(quiz1~5이 true인 개수) / 5 |

### Calculation Rules

**정확한 정답 계산식**:
```
correctCount = 
  (quiz1이 true면 1 + quiz2이 true면 1 + ... + quiz5이 true면 1) / (문제 개수)
  
ex) quiz1=true, quiz2=false, quiz3=true, quiz4=false, quiz5=true 
  → correctCount = 3/5 = 0.6

accuracy = floor((correctQuizzes / attemptedQuizzes) * 100)
if attemptedQuizzes === 0 → accuracy = 0
```

### Error Cases

| Status | Code | Message | 설명 |
|--------|------|---------|------|
| 400 | INVALID_PARAM | days 파라미터 유효하지 않음 (1~365) | days 범위 확인 |
| 401 | UNAUTHORIZED | JWT 토큰이 없거나 유효하지 않음 | Authorization 헤더 확인 필요 |
| 401 | INVALID_TOKEN | 토큰 만료 또는 서명 검증 실패 | 새로운 토큰 요청 필요 |
| 404 | NOT_FOUND | 사용자 데이터 없음 | 해당 사용자의 데이터 없음 |
| 500 | INTERNAL_ERROR | 서버 에러 | 서버 로그 확인 필요 |

### Example Usage (Frontend)
```typescript
const response = await apiClient.get("/api/report/daily-stats?days=7");
setChartData(response.data.map(item => ({
  day: item.day,
  accuracy: item.accuracy,
})));
```

---

## 4️⃣ 카테고리별 정답률 조회

### Endpoint
```
GET /api/report/category-progress
```

### Description
모든 카테고리의 정답률을 조회합니다.
(User_Category_Stats 테이블 기반)

### Request

**Headers**
```
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json
```

**Query Parameters**
없음 (사용자 ID는 JWT 토큰에서 자동으로 추출)

### Response

**Status: 200 OK**
```json
{
  "code": "SUCCESS",
  "message": "카테고리별 정답률 조회 성공",
  "data": [
    {
      "categoryId": 1,
      "category": "Tech",
      "progress": 72,
      "totalQuizzes": 50,
      "correctQuizzes": 36,
      "color": "#87CEEB"
    },
    {
      "categoryId": 2,
      "category": "AI",
      "progress": 80,
      "totalQuizzes": 45,
      "correctQuizzes": 36,
      "color": "#D4845C"
    },
    {
      "categoryId": 3,
      "category": "Health",
      "progress": 70,
      "totalQuizzes": 40,
      "correctQuizzes": 28,
      "color": "#D4C9AA"
    },
    {
      "categoryId": 4,
      "category": "Social",
      "progress": 94,
      "totalQuizzes": 50,
      "correctQuizzes": 47,
      "color": "#A9A9A9"
    },
    {
      "categoryId": 5,
      "category": "Pizza",
      "progress": 60,
      "totalQuizzes": 35,
      "correctQuizzes": 21,
      "color": "#7FCD7F"
    }
  ],
  "timestamp": "2026-02-12T10:30:00Z"
}
```

### Response Field Description

| 필드명 | 타입 | 설명 | DB 매핑 |
|-------|------|------|--------|
| categoryId | INT | 카테고리 ID | Categories.category_id |
| category | STRING | 카테고리명 | Categories.category_name |
| progress | INT | 정답률 (0~100) | (correctQuizzes / totalQuizzes) * 100 |
| totalQuizzes | INT | 풀이한 총 문제 수 | User_Category_Stats.total_quizzes |
| correctQuizzes | INT | 정답 문제 수 | User_Category_Stats.correct_quizzes |
| color | STRING (Hex) | UI 표시용 색상 (선택) | 백엔드에서 제공 또는 프론트엔드에서 관리 |

### Calculation Rules

```
progress = floor((correctQuizzes / totalQuizzes) * 100)
if totalQuizzes === 0 → progress = 0
```

### Sorting
기본적으로 `category_name` 가나다 순서로 정렬

### Error Cases

| Status | Code | Message | 설명 |
|--------|------|---------|------|
| 401 | UNAUTHORIZED | JWT 토큰이 없거나 유효하지 않음 | Authorization 헤더 확인 필요 |
| 401 | INVALID_TOKEN | 토큰 만료 또는 서명 검증 실패 | 새로운 토큰 요청 필요 |
| 404 | NOT_FOUND | 사용자 카테고리 통계 없음 | 해당 사용자의 데이터 없음 |
| 500 | INTERNAL_ERROR | 서버 에러 | 서버 로그 확인 필요 |

### Example Usage (Frontend)
```typescript
const response = await apiClient.get("/api/report/category-progress");
setCategoryProgress(response.data.map(item => ({
  category: item.category,
  progress: item.progress,
  color: item.color,
})));
```

---

## 📊 통합 조회 엔드포인트 (선택사항)

모든 리포트 데이터를 한 번에 조회할 수 있는 통합 엔드포인트:

### Endpoint
```
GET /api/report/all
```

### Response (200 OK)
```json
{
  "code": "SUCCESS",
  "message": "전체 리포트 조회 성공",
  "data": {
    "stats": { ... },           // 1번 API 응답과 동일
    "progress": { ... },        // 2번 API 응답과 동일
    "dailyStats": [ ... ],      // 3번 API 응답과 동일
    "categoryProgress": [ ... ] // 4번 API 응답과 동일
  },
  "timestamp": "2026-02-12T10:30:00Z"
}
```

---

## 5️⃣ 고객 소리함 (Feedback) 전송

### Endpoint
```
POST /api/feedback
```

### Description
사용자의 피드백, 의견, 건의사항을 MongoDB에 저장합니다.
JWT 토큰에서 자동으로 user_id를 추출하고, 서버에서 현재 시간을 기록합니다.

### Request

**Headers**
```
Authorization: Bearer {JWT_TOKEN}
Content-Type: application/json
```

**Request Body**
```json
{
  "content": "앱 사용성이 정말 좋습니다. 더 많은 카테고리가 추가되길 바랍니다."
}
```

### Request Field Description

| 필드명 | 타입 | 필수 | 설명 | 제약조건 |
|-------|------|------|------|--------|
| content | STRING | Yes | 피드백 내용 | 1자 이상 700자 이하 |

### Response

**Status: 201 Created**
```json
{
  "code": "SUCCESS",
  "message": "피드백이 성공적으로 저장되었습니다.",
  "data": {
    "feedbackId": "65f8b2c9d4e5f1a2b3c4d5e6",
    "userId": "user12345",
    "content": "앱 사용성이 정말 좋습니다. 더 많은 카테고리가 추가되길 바랍니다.",
    "submittedAt": "2026-02-13T10:45:30Z"
  },
  "timestamp": "2026-02-13T10:45:30Z"
}
```

### Response Field Description

| 필드명 | 타입 | 설명 | DB 매핑 |
|-------|------|------|--------|
| feedbackId | STRING | 생성된 피드백 ID (MongoDB ObjectId) | Feedback._id |
| userId | STRING | 피드백을 제출한 사용자 ID (JWT에서 추출) | Feedback.user_id |
| content | STRING | 피드백 내용 | Feedback.content |
| submittedAt | DATETIME | 피드백 제출 시간 (ISO 8601 UTC) | Feedback.submitted_at |

### MongoDB Schema (Feedback Collection)
```javascript
{
  _id: ObjectId,                  // 자동 생성
  user_id: String,                // JWT 토큰에서 추출
  content: String,                // 사용자가 입력한 피드백 (700자 이하)
  submitted_at: Date,             // 서버 현재 시간 (ISO 8601 UTC)
  created_at: Date,               // 문서 생성 시간 (선택사항)
  status: String                  // "pending" | "reviewed" | "resolved" (선택사항)
}
```

### 프론트엔드 임시저장 메커니즘
- **로컬 스토리지 키**: `oba_feedback_draft`
- **저장 시점**: 모달 닫기 시 (X 버튼, 닫기 버튼, 뒤로가기)
- **로드 시점**: 모달 열릴 때 AsyncStorage에서 로드
- **삭제 시점**: 피드백 전송 성공 후 또는 취소/빈 입력일 때

### Error Cases

| Status | Code | Message | 설명 |
|--------|------|---------|------|
| 400 | INVALID_REQUEST | 요청 형식이 올바르지 않음 | content 필드 누락 또는 잘못된 형식 |
| 400 | CONTENT_EMPTY | 피드백 내용이 비어있음 | content가 빈 문자열 또는 공백만 포함 |
| 400 | CONTENT_TOO_LONG | 피드백 내용이 너무 길어요 | content 길이 > 700자 |
| 401 | UNAUTHORIZED | JWT 토큰이 없거나 유효하지 않음 | Authorization 헤더 확인 필요 |
| 401 | INVALID_TOKEN | 토큰 만료 또는 서명 검증 실패 | 새로운 토큰 요청 필요 |
| 429 | RATE_LIMIT_EXCEEDED | 피드백 요청이 너무 많아요 | 일정 시간 후 다시 시도 |
| 500 | INTERNAL_ERROR | 서버 오류 | 서버 로그 확인 필요 |

### Example Usage (Frontend)
```typescript
// ✅ app/(tabs)/my/index.tsx - handleSubmitFeedback 함수

const handleSubmitFeedback = async () => {
  if (feedbackText.trim() === "") {
    Alert.alert("알림", "피드백을 입력해주세요.");
    return;
  }

  setIsSubmittingFeedback(true);
  try {
    // JWT 토큰은 apiClient에 자동으로 포함됨
    const response = await apiClient.post("/api/feedback", {
      content: feedbackText,
      // Note: user_id는 JWT 토큰에서 자동으로 추출됨 (백엔드)
      // Note: submitted_at은 백엔드에서 자동으로 현재 시간으로 설정됨
      // Note: 프론트엔드에서 localStorage로 임시저장 후 전송
    });

    // 성공 응답
    if (response.data.code === "SUCCESS") {
      // 1. 저장된 초안 삭제
      await deleteFeedbackDraft();
      // 2. 모달 닫기
      setFeedbackModalVisible(false);
      // 3. 입력 텍스트 초기화
      setFeedbackText("");
      // 4. 토스트 메시지 띄우기 (Alert 대신 사용)
      showThankYouToast(); // "소중한 의견 감사합니다!"
      console.log("✅ 피드백 제출 완료:", response.data.data.feedbackId);
    }
  } catch (error: any) {
    console.error("❌ 소리함 전송 실패:", error);
    
    const errorCode = error.response?.data?.code;
    const errorMessage = error.response?.data?.message;

    if (errorCode === "CONTENT_EMPTY") {
      Alert.alert("오류", "피드백 내용을 입력해주세요.");
    } else if (errorCode === "CONTENT_TOO_LONG") {
      Alert.alert("오류", "피드백은 700자 이하여야 합니다.");
    } else if (errorCode === "RATE_LIMIT_EXCEEDED") {
      Alert.alert("알림", "요청이 너무 많습니다. 잠시 후 다시 시도해주세요.");
    } else {
      Alert.alert("오류", errorMessage || "소리함 전송에 실패했습니다.");
    }
  } finally {
    setIsSubmittingFeedback(false);
  }
};
```

### 프론트엔드 통합 체크리스트
- [x] `apiClient` 설정 확인 (JWT 토큰 자동 포함)
- [x] 피드백 모달 UI 구현 완료 (AsyncStorage 기반 임시저장)
- [x] 텍스트 입력 유효성 검사 (700자 제한)
- [x] 전송 로딩 상태 표시
- [x] 성공/실패 알림 메시지 처리 (토스트 메시지)
- [x] 에러 응답 코드별 처리
- [x] 빈 입력값 방지
- [x] 로컬 스토리지 임시저장 및 자동 로드
- [x] 뒤로가기 버튼 및 X 버튼으로 모달 닫기 시 자동저장

---

## 🔄 프론트엔드 통합 가이드

### report/index.tsx에서 API 활용 예시

```typescript
// 📍 report/index.tsx의 fetchReportData 함수 수정
const fetchReportData = async () => {
  try {
    setLoading(true);

    // 방법 1: 개별 API 호출 (병렬)
    const [statsRes, progressRes, dailyRes, categoryRes] = await Promise.all([
      apiClient.get("/api/report/stats"),
      apiClient.get("/api/report/progress"),
      apiClient.get("/api/report/daily-stats"),
      apiClient.get("/api/report/category-progress"),
    ]);

    setReportData({
      consecutiveDays: statsRes.data.consecutiveDays,
      maxConsecutiveDays: statsRes.data.maxConsecutiveDays,
      perfectDays: statsRes.data.perfectDays,
      solvedCount: progressRes.data.solvedCount,
      totalCount: progressRes.data.totalCount,
      dailyStats: dailyRes.data,
      categoryProgress: categoryRes.data,
    });

    // 방법 2: 통합 API 호출 (권장)
    // const response = await apiClient.get("/api/report/all");
    // setReportData(response.data);

  } catch (error) {
    console.error("❌ [Report] 데이터 로드 실패:", error);
    setReportData(DUMMY_REPORT_DATA); // 폴백
  } finally {
    setLoading(false);
  }
};
```

---

## 📝 주의사항

1. **JWT 토큰 필수**: 모든 API는 Authorization 헤더의 JWT 토큰으로만 user_id 식별
   - Query Parameter로 user_id 전달받지 않음
   - JWT 디코딩하여 user_id 자동 추출
   - 토큰 무효/만료 시 401 응답

2. **Timezone 처리**: 모든 날짜/시간은 UTC 기준 (또는 일관된 타임존 문서화 필요)

3. **정답률 계산**: 프론트엔드와 백엔드 계산식 일치 필수

4. **캐싱**: 성능 최적화를 위해 캐시 정책 검토 필요

5. **Rate Limiting**: 과도한 요청 방지를 위해 구현 권장

6. **Pagination**: 향후 데이터 증가를 고려하여 필요 시 구현

---

## 📚 참고 사항

### 데이터 수집 방식

**daily-stats 계산 로직**:

1. Article_Logs에서 user_id, initial_at(또는 resolve_at) 기준 일별 집계
2. 각 (user_id, article_id)마다 Incorrect_Quiz 레코드의 quiz1~quiz5 합산
3. 일별 정답률 계산: `SUM(correct) / COUNT(*)`

**category-progress 계산 로직**:

1. User_Category_Stats 테이블에서 바로 조회
2. 각 행별 정답률 = correct_quizzes / total_quizzes

---

## 🚀 API 준비 체크리스트

- [ ] 각 엔드포인트 구현 완료
- [ ] 에러 핸들링 적용
- [ ] 권한 검증 (JWT) 추가
- [ ] 응답 형식 통일 (code, message, data, timestamp)
- [ ] 계산식 검증 (프론트 ↔ 백엔드 일치)
- [ ] 성능 테스트 완료 (특히 daily-stats)
- [ ] Feedback API MongoDB 컬렉션 생성
- [ ] Feedback API 입력값 유효성 검사
- [ ] Feedback API 요청 제한(Rate Limiting) 설정
- [ ] 문서화 최종 검토
