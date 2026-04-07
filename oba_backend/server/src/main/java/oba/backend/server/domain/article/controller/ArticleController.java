package oba.backend.server.domain.article.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.dto.ArticleDetailResponse;
import oba.backend.server.domain.article.dto.ArticleSummaryResponse;
import oba.backend.server.domain.article.service.ArticleDetailService;
import oba.backend.server.domain.article.service.ArticleSummaryService;
import oba.backend.server.global.auth.jwt.JwtProvider;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/articles")
@RequiredArgsConstructor
public class ArticleController {

    private final ArticleSummaryService summaryService;
    private final ArticleDetailService detailService;
    private final JwtProvider jwtProvider;

    @GetMapping("/latest") // 최종주소: /api/articles/latest
    public ResponseEntity<List<ArticleSummaryResponse>> getLatestArticles(
            @RequestParam(defaultValue = "10") int limit
    ) {
        return ResponseEntity.ok(summaryService.getLatestArticles(limit));
    }

    @GetMapping("/{id}") // 최종주소: /api/articles/{id}
    public ResponseEntity<ArticleDetailResponse> getArticleDetail(
            @PathVariable String id,
            @RequestHeader(value = "Authorization", required = false) String token
    ) {
        Long userId = null;
        if (token != null && token.startsWith("Bearer ")) {
            String jwt = token.substring(7);
            if (jwtProvider.validateToken(jwt)) {
                userId = jwtProvider.getUserId(jwt);
            }
        }
        return ResponseEntity.ok(detailService.getArticleDetail(id, userId));
    }
}