package oba.backend.server.domain.article.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.domain.article.dto.ArticleDetailResponse;
import oba.backend.server.domain.article.dto.ArticleSummaryResponse;
import oba.backend.server.domain.article.service.ArticleDetailService;
import oba.backend.server.domain.article.service.ArticleSummaryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/articles")
@RequiredArgsConstructor
public class ArticleController {

    private final ArticleSummaryService summaryService;
    private final ArticleDetailService detailService;

    @GetMapping("/latest")
    public ResponseEntity<List<ArticleSummaryResponse>> getLatest(
            @RequestParam(defaultValue = "5") int limit
    ) {
        return ResponseEntity.ok(summaryService.getLatestArticles(limit));
    }

    @GetMapping("/{id}")
    public ResponseEntity<ArticleDetailResponse> getDetail(@PathVariable Long id) {
        return ResponseEntity.ok(detailService.getArticleDetail(id));
    }
}
