package oba.backend.server.controller;

import lombok.RequiredArgsConstructor;
import oba.backend.server.service.ArticleDetailService;
import oba.backend.server.service.ArticleSummaryService;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/articles")
@RequiredArgsConstructor
public class ArticleController {

    private final ArticleSummaryService summaryService;
    private final ArticleDetailService detailService;

    @GetMapping("/latest")
    public ResponseEntity<?> getLatest() {
        return ResponseEntity.ok(summaryService.getLatestArticles(5));
    }

    @GetMapping("/{id}")
    public ResponseEntity<?> getDetail(@PathVariable Long id) {
        return ResponseEntity.ok(detailService.getArticleDetail(id));
    }
}
