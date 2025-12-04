package oba.backend.server.domain.quiz;

import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import oba.backend.server.common.jwt.JwtProvider;
import oba.backend.server.domain.quiz.dto.QuizResultRequest;
import oba.backend.server.domain.user.User;
import oba.backend.server.repository.user.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
public class QuizResultService {

    private final JwtProvider jwtProvider;
    private final UserRepository userRepository;
    private final IncorrectQuizRepository incorrectQuizRepository;
    private final IncorrectArticlesRepository incorrectArticlesRepository;

    @Transactional
    public void saveQuizResult(String jwt, QuizResultRequest request) {

        Claims claims = jwtProvider.getClaims(jwt);
        String identifier = claims.getSubject();

        User user = userRepository.findByIdentifier(identifier)
                .orElseThrow(() -> new RuntimeException("User not found"));
        Long userId = user.getId();

        boolean[] results = request.getQuizResults();

        incorrectQuizRepository.deleteByUserIdAndArticleId(userId, request.getArticleId());

        IncorrectQuiz quiz = IncorrectQuiz.builder()
                .userId(userId)
                .articleId(request.getArticleId())
                .quiz1(results.length > 0 ? results[0] : null)
                .quiz2(results.length > 1 ? results[1] : null)
                .quiz3(results.length > 2 ? results[2] : null)
                .quiz4(results.length > 3 ? results[3] : null)
                .quiz5(results.length > 4 ? results[4] : null)
                .build();

        incorrectQuizRepository.save(quiz);
    }
}
