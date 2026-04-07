
# 🚀 한입기사 프론트엔드 실행 가이드 
## 1️⃣ 프로젝트 클론

```bash
git clone https://github.com/OneBiteArticle/oba_frontend.git
cd oba_frontend
```

---

## 2️⃣ 필수 패키지 설치

(※ `expo-blur` 포함 — 앱 UI 구성에 필요합니다.)

```bash
npm install
npx expo install expo-blur
```

---

## 3️⃣ 자동 실행 스크립트

### 🪟 Windows

```bash
setup.bat
```

더블클릭으로 실행해도 됩니다.
**Expo CLI 설치 → 패키지 설치 → 앱 실행**이 자동으로 진행됩니다.

---

### 🍎 macOS

```bash
chmod +x setup.sh
./setup.sh
```

환경 구성부터 앱 실행까지 한 번에 완료됩니다.

---

## 4️⃣ 수동 실행 (원할 때)

자동 스크립트 대신 직접 실행하려면:

```bash
npm install
npm start
npx expo install expo-blur
```

또는

```bash
npx expo start
```

---

## 5️⃣ 실행

터미널에 표시되는 QR 코드를
스마트폰의 **Expo Go 앱**으로 스캔해 접속합니다.

> PC와 스마트폰이 **같은 Wi-Fi**를 사용해야 접속할 수 있습니다.
