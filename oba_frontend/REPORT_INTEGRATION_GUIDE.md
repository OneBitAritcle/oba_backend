# OBA Report 기능 - 백엔드 연동 완벽 가이드

> 학습 리포트 화면의 UI 구현 및 백엔드 연동 매뉴얼

---

## 📋 목차

1. [프로젝트 구조](#프로젝트-구조)
2. [데이터 흐름도](#데이터-흐름도)
3. [API 명세서](#api-명세서)
4. [컴포넌트 상세 설명](#컴포넌트-상세-설명)
5. [백엔드 연동 가이드](#백엔드-연동-가이드)
6. [주의사항 & 체크리스트](#주의사항--체크리스트)

---

## 🗂️ 프로젝트 구조

```
oba_frontend/
├── BACKEND_API_SPEC.md                          ← 📍 API 명세 문서
├── REPORT_INTEGRATION_GUIDE.md                  ← 이 파일
├── app/(tabs)/report/
│   └── index.tsx                                ← 메인 리포트 페이지
│       └── 1️⃣ ReportStats (인라인 컴포넌트)
│       └── 2️⃣ ProgressBar (인라인 컴포넌트)
│       └── 3️⃣ DailyChart (외부 임포트)
│       └── 4️⃣ CategoryProgress (외부 임포트)
│
└── app/components/report/
    ├── ReportStats.tsx                          ← 통계 카드 (현재 미사용)
    ├── ProgressBar.tsx                          ← 진도바 (현재 미사용)
    ├── DailyChart.tsx                           ← 요일별 정답률 차트
    └── CategoryProgress.tsx                     ← 카테고리별 진행률

src/api/
└── apiClient.ts                                 ← Axios 인스턴스
```

---

## 📊 데이터 흐름도

```
┌─────────────────────────────────────────────────────────────────┐
│                    Report Page (index.tsx)                       │
│                    ↓                                              │
│           fetchReportData() 호출                               │
│                    ↓                                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│  백엔드 API 호출 (병렬 처리)                                  │
│  ├─ GET /api/report/stats                                     │
│  ├─ GET /api/report/progress                                 │
│  ├─ GET /api/report/daily-stats                              │
│  └─ GET /api/report/category-progress                        │
│                                                                   │
├─────────────────────────────────────────────────────────────────┤
│                    응답 데이터 통합                              │
│          setReportData({...}) → React State                    │
│                                                                   │
├─────────────────────────────────────────────────────────────────┤
│                 각 컴포넌트에 Props 전달                         │
│                                                                   │
│  state.consecutiveDays --→ ReportStats                         │
│  state.solvedCount ------→ ProgressBar                         │
│  state.dailyStats ------→ DailyChart (내부 fetch)           │
│  state.categoryProgress → CategoryProgress (내부 fetch)     │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

---

## 📝 API 명세서

> 상세 명세는 `/BACKEND_API_SPEC.md` 참고
> 
> **⚠️ 중요**: 모든 API는 JWT 토큰에서 user_id를 자동으로 추출합니다.
> Query Parameter에 user_id를 전달하지 마세요!

### 엔드포인트 요약

| # | 메서드 | 엔드포인트 | 필수 파라미터 | 설명 | 대응 컴포넌트 | DB 테이블 |
|---|--------|----------|------------|------|------------|----------|
| 1 | GET | `/api/report/stats` | Authorization | 통계 정보 (연속일, 최고기록, 퍼펙트) | ReportStats | User_Stats |
| 2 | GET | `/api/report/progress` | Authorization | 전체 진도 (푼 문제/전체 수) | ProgressBar | User_Category_Stats |
| 3 | GET | `/api/report/daily-stats` | Authorization +(days) | 요일별 정답률 (최근 7일) | DailyChart | Article_Logs + Incorrect_Quiz |
| 4 | GET | `/api/report/category-progress` | Authorization | 카테고리별 정답률 | CategoryProgress | User_Category_Stats |

**Legend**:
- Authorization: JWT 토큰 필수 (자동으로 user_id 추출)
- (days): 선택사항 (기본값: 7)

### 응답 데이터 형식 (공통)

```json
{
  "code": "SUCCESS",
  "message": "설명 메시지",
  "data": { /* ... */ },
  "timestamp": "2026-02-12T10:30:00Z"
}
```

## 🔐 인증 체계

### 사용자 식별 방식

- ✅ **JWT 토큰 기반**: Authorization 헤더에 Bearer 토큰 포함
- ✅ **사용자 ID 자동 추출**: 백엔드에서 JWT 디코딩 → user_id 추출
- ✅ **Query Parameter 불필요**: 모든 API에서 user_id 전달 X
- ✅ **권한 검증**: JWT 검증으로 인증되지 않은 사용자 접근 차단

### 프론트엔드 요청 형식

```typescript
// ✅ 올바른 방식
const response = await apiClient.get("/api/report/stats");
// Header 자동 추가: Authorization: Bearer {JWT_TOKEN}

// ❌ 잘못된 방식 (Query Parameter로 user_id 전달)
const response = await apiClient.get("/api/report/stats?user_id=123");
```

---

### 1️⃣ ReportStats (통계 카드)

**위치**: `app/(tabs)/report/index.tsx` (인라인 구현)

**역할**: 사용자의 3가지 주요 통계 표시
- 연속 학습일 (current_streak)
- 최고 연속 학습일 (max_streak)
- 누적 퍼펙트 데이 (total_perfect_days)

**Props**:
```typescript
{
  consecutiveDays: number;      // 현재 연속일
  maxConsecutiveDays: number;   // 최고 기록
  perfectDays: number;          // 퍼펙트 데이
}
```

**API 연동**:
```typescript
// 명세: /BACKEND_API_SPEC.md - "1️⃣ 사용자 통계 조회"
// 엔드포인트: GET /api/report/stats

response.data = {
  consecutiveDays: 12,
  maxConsecutiveDays: 28,
  perfectDays: 16,
  lastLearnedAt: "2026-02-12"
}
```

---

### 2️⃣ ProgressBar (진도바)

**위치**: `app/(tabs)/report/index.tsx` (인라인 구현)

**역할**: 전체 학습 진도 시각화
- 진행률 바
- 진행된 문제 수 / 전체 문제 수
- 진도율 백분위

**Props**:
```typescript
{
  solvedCount: number;   // 푼 문제 수
  totalCount: number;    // 전체 문제 수
}
```

**API 연동**:
```typescript
// 명세: /BACKEND_API_SPEC.md - "2️⃣ 전체 학습 진도 조회"
// 엔드포인트: GET /api/report/progress

response.data = {
  solvedCount: 150,
  totalCount: 200,
  progressPercentage: 75
}
```

---

### 3️⃣ DailyChart (요일별 정답률)

**위치**: `app/components/report/DailyChart.tsx`

**역할**: 최근 7일간 요일별 정답률 차트
- 라인 차트 (SVG)
- Y축: 0~100 (정답률)
- X축: Mon~Sun (요일)
- 범례 및 데이터 테이블 포함

**Props**: 없음 (현재 내부 fetch)

**API 연동**:
```typescript
// 명세: /BACKEND_API_SPEC.md - "3️⃣ 요일별 정답률 조회"
// 엔드포인트: GET /api/report/daily-stats?days=7

response.data = [
  {
    date: "2026-02-09",
    day: "Mon",
    accuracy: 60,
    attemptedQuizzes: 5,
    correctQuizzes: 3
  },
  // ... 7개 항목
]
```

**내부 구현 (주석 해제 지점)**:
```typescript
// /app/components/report/DailyChart.tsx - Line ~28
// 주석 해제:
// const response = await apiClient.get("/api/report/daily-stats?days=7");
// setChartData(response.data);
```

---

### 4️⃣ CategoryProgress (카테고리별 정답률)

**위치**: `app/components/report/CategoryProgress.tsx`

**역할**: 모든 카테고리의 정답률 진행바 표시
- 카테고리별 색상 구분
- 정답률 백분위 표시
- 풀이 문제 수

**Props**: 없음 (현재 내부 fetch)

**API 연동**:
```typescript
// 명세: /BACKEND_API_SPEC.md - "4️⃣ 카테고리별 정답률 조회"
// 엔드포인트: GET /api/report/category-progress

response.data = [
  {
    categoryId: 1,
    category: "Tech",
    progress: 72,
    totalQuizzes: 50,
    correctQuizzes: 36,
    color: "#87CEEB"
  },
  // ... 5개 카테고리
]
```

**내부 구현 (주석 해제 지점)**:
```typescript
// /app/components/report/CategoryProgress.tsx - Line ~40
// 주석 해제:
// const response = await apiClient.get("/api/report/category-progress");
// setCategories(response.data);
```

---

## 🚀 백엔드 연동 가이드

### Phase 1: UI 검증 (현재 상태)

✅ **현재 상황**:
- 모든 UI 컴포넌트 완성
- Dummy 데이터로 테스트 중
- 각 컴포넌트에 API 주석 작성

✅ **할 일**:
1. 프론트엔드 팀: UI/UX 검증
2. 백엔드 팀: API 스펙 검토 및 구현 시작

---

### Phase 2: 백엔드 구현

**필요한 백엔드 작업**:

```
📌 각 엔드포인트별 구현:

1. GET /api/report/stats
   └─ User_Stats 테이블 조회
   └─ 응답: { consecutiveDays, maxConsecutiveDays, perfectDays, lastLearnedAt }

2. GET /api/report/progress
   └─ User_Category_Stats 통합 집계
   └─ 응답: { solvedCount, totalCount, progressPercentage }

3. GET /api/report/daily-stats
   └─ Article_Logs + Incorrect_Quiz 일별 집계
   └─ 응답: [{ date, day, accuracy, attemptedQuizzes, correctQuizzes }]

4. GET /api/report/category-progress
   └─ User_Category_Stats 조회
   └─ 응답: [{ categoryId, category, progress, totalQuizzes, correctQuizzes, color }]
```

---

### Phase 3: 프론트엔드 API 연동

#### Step 1: FetchReportData 수정 (권장)

**파일**: `app/(tabs)/report/index.tsx`

**현재 코드** (Line ~128-150):
```typescript
const fetchReportData = async () => {
  try {
    setLoading(true);
    setReportData(DUMMY_REPORT_DATA);  // ← 변경 필요
  } catch (error) {
    console.error("데이터 로드 실패:", error);
    setReportData(DUMMY_REPORT_DATA);  // ← 변경 필요
  } finally {
    setLoading(false);
  }
};
```

**변경 후**:
```typescript
import { apiClient } from "../../src/api/apiClient";

const fetchReportData = async () => {
  try {
    setLoading(true);

    // 병렬 요청 (권장)
    // ✅ 주의: user_id를 Query Parameter로 전달하지 않음
    // JWT 토큰에서 자동으로 추출됨
    const [statsRes, progressRes, dailyRes, categoryRes] = await Promise.all([
      apiClient.get("/api/report/stats"),                    // user_id 자동 추출
      apiClient.get("/api/report/progress"),                // user_id 자동 추출
      apiClient.get("/api/report/daily-stats?days=7"),      // user_id 자동 추출, days만 전달
      apiClient.get("/api/report/category-progress"),       // user_id 자동 추출
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

  } catch (error) {
    console.error("❌ [Report] 데이터 로드 실패:", error);
    // 에러 처리: 사용자 알림 또는 폴백
    if (error.response?.status === 401) {
      // JWT 만료 또는 로그인 필요
      Alert.alert("인증 필요", "다시 로그인해주세요.");
      // router.push("/(auth)/login");
    } else {
      Alert.alert("오류", "리포트 데이터를 불러올 수 없습니다.");
    }
  } finally {
    setLoading(false);
  }
};
```

#### Step 2: DailyChart 내부 fetch 수정

**파일**: `app/components/report/DailyChart.tsx`

**현재 코드** (Line ~35):
```typescript
// 현재: Dummy 데이터만 사용
const mockData: DailyData[] = [
  { day: "Mon", accuracy: 60 },
  // ...
];
setChartData(mockData);
```

**변경 후**:
```typescript
import { apiClient } from "../../../src/api/apiClient";

// 아래 코드 주석 해제:
const response = await apiClient.get("/api/report/daily-stats");
setChartData(response.data);
```

#### Step 3: CategoryProgress 내부 fetch 수정

**파일**: `app/components/report/CategoryProgress.tsx`

**현재 코드** (Line ~40):
```typescript
// 현재: Dummy 데이터만 사용
const mockData: CategoryData[] = [
  { category: "Tech", progress: 72, color: "#87CEEB" },
  // ...
];
setCategories(mockData);
```

**변경 후**:
```typescript
import { apiClient } from "../../../src/api/apiClient";

// 아래 코드 주석 해제:
const response = await apiClient.get("/api/report/category-progress");
setCategories(response.data);
```

---

### Phase 4: 테스트 및 최적화

**테스트 체크리스트**:

- [ ] 각 API 응답 검증
- [ ] 로딩 상태 UI 테스트
- [ ] 에러 상황 처리 테스트
- [ ] 데이터 포맷 일치 확인
- [ ] 성능 측정 (특히 API 응답 시간)
- [ ] 새로고침/재방문 시 데이터 업데이트 동작
- [ ] 오프라인 상황 처리

**최적화 권장사항**:

```typescript
// 1. 캐싱 적용
const [cache, setCache] = useState<ReportData | null>(null);
const [lastFetchTime, setLastFetchTime] = useState<number>(0);

if (Date.now() - lastFetchTime < 5 * 60 * 1000) {
  setReportData(cache);
  return;
}

// 2. 부분 업데이트 (통합 API 대신 항목별 업데이트)
// 예: 사용자가 특정 카테고리만 본다면?

// 3. 에러 Retry 로직
const retryFetch = async (fn, retries = 3) => {
  for (let i = 0; i < retries; i++) {
    try {
      return await fn();
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, 1000 * Math.pow(2, i)));
    }
  }
};
```

---

## ⚠️ 주의사항 & 체크리스트

### 기술적 주의사항

1. **사용자 인증**: 모든 API는 JWT 토큰 필수
   ```typescript
   // ✅ 올바른 방식
   apiClient.get("/api/report/stats");
   // Header에 자동 추가: Authorization: Bearer {token}
   
   // ❌ 잘못된 방식 (User ID를 Query로 전달)
   apiClient.get("/api/report/stats?user_id=123");  // 불필요!
   ```

2. **JWT 토큰 관리**:
   - apiClient에서 자동으로 Authorization 헤더 추가
   - 토큰 만료 시 401 응답 → 로그인 페이지로 리다이렉트
   - 토큰 갱신 로직 필요 (interceptor 사용 권장)

3. **타입 정합성**: 백엔드 응답이 명세와 정확히 일치해야 함
   ```typescript
   // ❌ 부정확한 예
   response.data.consecutiveDays = "12";  // String이면 안됨!
   
   // ✅ 정확한 예
   response.data.consecutiveDays: 12;  // Number
   ```

2. **Timezone 처리**: 모든 날짜/시간은 UTC 기준
   ```typescript
   // 예: "2026-02-12T10:30:00Z"
   ```

3. **Null/Undefined 처리**:
   ```typescript
   const accuracy = data?.accuracy ?? 0;  // 안전한 접근
   ```

4. **라우팅 경로**:
   - 현재 뒤로가기 경로: `router.push("/(tabs)")` (탭 으로)
   - 필요시 특정 탭으로 수정: `router.push("/(tabs)/index")` (홈)

---

### 구현 체크리스트

**백엔드 팀**:
- [ ] JWT 토큰 검증 로직 구현 (Authorization 헤더)
- [ ] JWT 디코딩하여 user_id 자동 추출
- [ ] 4개 API 엔드포인트 구현 완료
- [ ] 모든 API에 JWT 검증 미들웨어 적용
- [ ] 응답 형식 명세 준수 확인
- [ ] 에러 핸들링 구현 (401: JWT 무효/만료, 404, 500 등)
- [ ] JWT 만료 시 명확한 401 응답
- [ ] 데이터베이스 쿼리 최적화 (성능 테스트)
- [ ] API 문서 작성 완료

**프론트엔드 팀**:
- [ ] UI/UX 최종 검증
- [ ] API 마이그레이션 코드 작성
- [ ] 에러 핸들링 추가 (Alert, Toast 등)
- [ ] 로딩 상태 UX 개선
- [ ] 새로고침 기능 추가 (Pull-to-Refresh) (선택)
- [ ] 데이터 무효화 로직 (캐시 관리) (선택)

---

### 성능 기준

| 항목 | 기준값 | 측정 방법 |
|-----|-------|---------|
| API 응답 시간 | < 1,000ms | Network 탭 |
| 로딩 UI 시작 | 즉시 | 페이지 진입 시 |
| 차트 렌더링 | < 500ms | React Profiler |
| 전체 페이지 로드 | < 2,000ms | Lighthouse |

---

---

## 🔗 apiClient 설정 (JWT 자동 추가)

### 현재 apiClient 구조

**파일**: `src/api/apiClient.ts`

```typescript
// apiClient는 Axios 인스턴스로 자동으로 Authorization 헤더 추가
import axios from "axios";

export const apiClient = axios.create({
  baseURL: process.env.EXPO_PUBLIC_API_URL,
});

// Request Interceptor에서 JWT 토큰 자동 추가
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem("jwt_token"); // 또는 AsyncStorage
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Response Interceptor에서 401 에러 처리 (토큰 만료)
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      // 토큰 갱신 또는 로그인 페이지로 리다이렉트
    }
    return Promise.reject(error);
  }
);
```

이러한 설정 덕분에 프론트엔드에서는 사용자 ID를 신경 쓰지 않고도 API를 호출할 수 있습니다.

---

## 🔗 관련 문서

- **API 명세서**: `/BACKEND_API_SPEC.md`
- **ERD 다이어그램**: (별도 파일)
- **프로젝트 README**: `/README.md`

---

## 📞 지원

**문제 발생 시 확인 사항**:

1. API 응답 형식 검증
   ```bash
   curl -H "Authorization: Bearer {token}" \
        https://api.oba.com/api/report/stats
   ```

2. 콘솔 로그 확인
   ```typescript
   console.log("📊 [Report]", JSON.stringify(responseData, null, 2));
   ```

3. 네트워크 탭 확인 (DevTools)
   - 요청 헤더 (Authorization, Content-Type)
   - 응답 상태 및 타이밍
   - 에러 메시지

---

**마지막 업데이트**: 2026-02-12
**문서 버전**: 1.0
