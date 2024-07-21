//package odiro.config.jwt;
//
//import com.auth0.jwt.JWT;
//import com.auth0.jwt.algorithms.Algorithm;
//import com.auth0.jwt.exceptions.JWTVerificationException;
//import lombok.RequiredArgsConstructor;
//import odiro.domain.member.Member;
//import odiro.repository.member.MemberRepository;
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.beans.factory.annotation.Value;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.RequestHeader;
//import org.springframework.web.bind.annotation.RestController;
//
//import java.util.Date;
//
//@RequiredArgsConstructor
//@RestController
//public class TokenController {
//
//    @Autowired
//    private final MemberRepository memberRepository;
//
//    @Value("${jwt.secret}")
////    private String secretKey="7ae96706cd6e6aade43a3b843bb3317f823ab927b64beb8d45558b3ac29f079dd36afe40f1646af31c334ccbb568cfe64b9e4e54a47aa5a5077796eca1e58075";
//    private String secretKey;
//    @PostMapping("/token/refresh")
//    public ResponseEntity<?> refreshAccessToken(@RequestHeader("Refresh-Token") String refreshToken) {
//        System.out.println("refreshAccessToken : 진입"+refreshToken);
//        if (refreshToken != null && refreshToken.startsWith(JwtProperties.TOKEN_PREFIX)) {
//            refreshToken = refreshToken.replace(JwtProperties.TOKEN_PREFIX, "");
//
//            try {
//                String username = JWT.require(Algorithm.HMAC512(secretKey))
//                        .build()
//                        .verify(refreshToken)
//                        .getSubject();
//
//                if (username != null) {
//                    Member user = memberRepository.findByusername(username).orElseThrow();
//                    String newAccessToken = JWT.create()
//                            .withSubject(user.getUsername())
//                            .withExpiresAt(new Date(System.currentTimeMillis() + JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME))
//                            .withClaim("id", user.getId())
//                            .withClaim("username", user.getUsername())
//                            .sign(Algorithm.HMAC512(secretKey));
//
//                    return ResponseEntity.ok("{\"accessToken\": \"" + JwtProperties.TOKEN_PREFIX + newAccessToken + "\"}");
//                }
//            } catch (JWTVerificationException exception) {
//                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid refresh token");
//            }
//        }else{
//            System.out.println("refreshAccessToken : NULL");
//        }
//        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Refresh token missing");
//    }
//}