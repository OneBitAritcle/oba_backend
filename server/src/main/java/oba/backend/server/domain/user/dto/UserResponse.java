package oba.backend.server.domain.user.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import oba.backend.server.domain.user.entity.User;

import java.util.List;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserResponse {
    private Long userId;
    private String email;
    private String name;
    private String picture;
    private String authProvider;
    private int consecutiveDays;
    private List<Boolean> weeklyLog;

    public static UserResponse from(User user, List<Boolean> weeklyLog) {
        int streak = (user.getUserStats() != null) ? user.getUserStats().getCurrentStreak() : 0;

        return UserResponse.builder()
                .userId(user.getId())
                .email(user.getEmail())
                .name(user.getName())
                .picture(user.getPicture())
                .authProvider(user.getAuthProvider() != null ?
                        user.getAuthProvider().name() : "UNKNOWN")
                .consecutiveDays(streak)
                .weeklyLog(weeklyLog)
                .build();
    }
}