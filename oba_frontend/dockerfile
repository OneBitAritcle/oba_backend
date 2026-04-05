FROM node:20-bullseye AS builder

WORKDIR /app

# 1) package.json만 복사
COPY package.json ./

# 2) npm install
RUN npm install --legacy-peer-deps

# 3) 나머지 전체 소스 복사
COPY . .

# 4) Expo 웹 정적 파일 빌드
RUN npx expo export --platform web

# ─── 프로덕션 단계 ───
FROM node:20-bullseye-slim

WORKDIR /app

# serve 설치 (정적 파일 서빙용)
RUN npm install -g serve

# 빌드된 정적 파일 복사
COPY --from=builder /app/dist ./dist

EXPOSE 8081

CMD ["serve", "-s", "dist", "-l", "8081"]
