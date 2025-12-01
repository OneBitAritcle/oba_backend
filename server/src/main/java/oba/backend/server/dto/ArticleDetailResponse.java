package oba.backend.server.dto;

import lombok.Builder;
import lombok.Data;
import oba.backend.server.entity.mongo.GptDocument;

import java.util.List;

@Data
@Builder
public class ArticleDetailResponse {

    private Long articleId;
    private String title;
    private String publishTime;
    private String servingDate;

    private Object content;
    private Object subtitle;

    private String summary;
    private List<GptDocument.GptResult.Keyword> keywords;
    private List<GptDocument.GptResult.Quiz> quizzes;
}
