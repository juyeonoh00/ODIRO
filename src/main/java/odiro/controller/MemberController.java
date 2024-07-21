package odiro.controller;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import odiro.config.jwt.JwtTokenService;
import odiro.config.jwt.TokenDto;
import odiro.domain.member.Member;
import odiro.dto.member.SignInRequestDto;
import odiro.dto.member.SignUpDto;
import odiro.dto.member.SignUpResponseDto;
import odiro.repository.member.MemberRepository;
import odiro.service.member.MemberService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@Slf4j
@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class MemberController {

    private final MemberRepository memberRepository;
    private final MemberService memberService;
    private final JwtTokenService jwtTokenService;
    @Autowired
    private AuthenticationManager authenticationManager;


    @Operation(summary = "회원가입", description = "회원가입")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK")
    })
        @PostMapping(value = "/signup")
        public ResponseEntity<SignUpResponseDto> singUp (@RequestBody SignUpDto signUpDto){
            System.out.println("---------------------------------------");
            Member member = memberService.signUp(signUpDto);
            SignUpResponseDto res = SignUpResponseDto.toDto(member);
            //response 전달을 위한 dto 변환

            return ResponseEntity.status(HttpStatus.CREATED).body(res);
        }

    @Operation(summary = "로그인", description = "로그인후, access/refresh Token 발행")
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "OK")
    })
//    @PostMapping("/auth/login")
//    public ResponseEntity<TokenDto> login(@RequestBody MemberLoginRequestDto memberRequestDto) {
//        return ResponseEntity.ok(memberService.login(memberRequestDto));
//    }
    @PostMapping("/signin")
    public ResponseEntity<TokenDto> signIn(@RequestBody SignInRequestDto signInRequestDto) {
        System.out.println("---------------------------------------");

        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(signInRequestDto.getUsername(), signInRequestDto.getPassword()));
            System.out.println("signIn : 인증 성공");

            // 여기서 토큰 생성 로직 추가
            // 예시: TokenDto tokenDto = tokenService.createToken(authentication);

            // 반환할 토큰 DTO 생성
            TokenDto tokenDto = jwtTokenService.generateToken(authentication);
            System.out.println("signIn : 인증 성공");
            // tokenDto.setAccessToken(accessToken);
            // tokenDto.setRefreshToken(refreshToken);

            return ResponseEntity.ok(tokenDto);
        } catch (AuthenticationException e) {
            System.out.println("signIn : 인증 실패");
            e.printStackTrace();
            return ResponseEntity.status(HttpServletResponse.SC_UNAUTHORIZED).body(null);
        }
    }
//        @Operation(summary = "회원가입", description = "회원가입")
//        @ApiResponses(value = {
//                @ApiResponse(responseCode = "200", description = "OK")
//        })
//        @GetMapping("/kakao")
//        public ResponseEntity<> kakaoLogin(@RequestParam("code") String code){
//            OauthToken oauthToken = userService.getAccessToken(code);
//
//            //(2)
//            // 발급 받은 accessToken 으로 카카오 회원 정보 DB 저장 후 JWT 를 생성
//            String jwtToken = userService.SaveUserAndGetToken(oauthToken.getAccess_token());
//            //(3)
//            HttpHeaders headers = new HttpHeaders();
//            headers.add(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);
//
//            //(4)
//            return ResponseEntity.ok().headers(headers).body("success");
//
//        }
        @Operation(summary = "카카오 로그인", description = "카카오 로그인")
        @ApiResponses(value = {
                @ApiResponse(responseCode = "200", description = "OK")
        })
        @PostMapping(value = "/kakao")
        public ResponseEntity<> kakaoLogin(@RequestParam("code") String code){
            OauthToken oauthToken = userService.getAccessToken(code);

            //(2)
            // 발급 받은 accessToken 으로 카카오 회원 정보 DB 저장 후 JWT 를 생성
            String jwtToken = userService.SaveUserAndGetToken(oauthToken.getAccess_token());
            //(3)
            HttpHeaders headers = new HttpHeaders();
            headers.add(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX + jwtToken);

            //(4)
            return ResponseEntity.ok().headers(headers).body("success");
        }

//        Authentication authentication = authenticationManager.authenticate(
//                new UsernamePasswordAuthenticationToken(signInRequestDto.getUsername(), signInRequestDto.getPassword()));
//        return ResponseEntity.ok().build();






}
