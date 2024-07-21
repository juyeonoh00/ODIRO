package odiro.config.oauth2;

import lombok.Builder;
import lombok.Getter;

import java.util.Map;

@Getter
@Builder
public class OAuthAttributes {
    private Map<String, Object> attributes;
    private String oAuthId;     // OAuth2.0에서 사용하는 PK
    private String nickName;    // 닉네임 정보
    private String email;       // 이메일 주소
    private SocialType socialType;
    public static OAuthAttributes ofKakao(SocialType userNameAttributeName, Map<String, Object> attributes) {

        Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
        Map<String, Object> profile = (Map<String, Object>) kakaoAccount.get("profile");

        String nickname = (String) profile.get("nickname");
        String email = (String) kakaoAccount.get("email");

        // 리소스 서버별 사용자 식별하는 값입니다.
        String oAuthId = String.valueOf(attributes.get(userNameAttributeName));

        return OAuthAttributes.builder()
                .oAuthId(oAuthId)
                .email(email)
                .nickName(nickname)
                .attributes(attributes)
                .socialType(SocialType.KAKAO)
                .build();
    }
}