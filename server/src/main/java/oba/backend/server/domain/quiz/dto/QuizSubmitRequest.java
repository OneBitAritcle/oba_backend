package oba.backend.server.domain.quiz.dto;

import lombok.Getter;
import lombok.Setter;
import java.util.List;

@Getter
@Setter
public class QuizSubmitRequest {
    private String articleId;
    private List<Integer> answers; // 사용자가 선택한 보기 인덱스들
}