package oba.backend.server.dto;

import lombok.Builder;
import lombok.Data;
import oba.backend.server.entity.mongo.GptDocument;
import oba.backend.server.entity.mysql.Article;

import java.util.List;

@Data
@Builder
public class ArticleDetailResponse {

    private Long id;
    private List<String> category;
    private String title;
    private String date;
    private String url;

    private Object content;
    private Object subtitle;

    private String summary;
    private List<?> keywords;
    private List<?> quizzes;

    public static ArticleDetailResponse of(Article a, List<String> c, GptDocument d) {

        return ArticleDetailResponse.builder()
                .id(a.getArticleId())
                .category(c)
                .title(d.getTitle())
                .date(d.getPublishTime())
                .url(a.getUrl())
                .content(d.getContentCol())
                .subtitle(d.getSubCol())
                .summary(d.getGptResult().getSummary())
                .keywords(d.getGptResult().getKeywords())
                .quizzes(d.getGptResult().getQuizzes())
                .build();
    }
}
