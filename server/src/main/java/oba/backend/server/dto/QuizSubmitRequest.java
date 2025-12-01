package oba.backend.server.dto;

import lombok.Data;
import java.util.List;

@Data
public class QuizSubmitRequest {
    private Long articleId;
    private List<Boolean> answers;     // quiz1~quiz5 순서
}
