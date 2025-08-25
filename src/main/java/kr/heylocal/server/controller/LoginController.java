package kr.heylocal.server.controller;

import kr.heylocal.server.dto.ResponseDto;
import kr.heylocal.server.dto.login.*;
import kr.heylocal.server.service.LoginService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@Slf4j
public class LoginController {
    private final LoginService loginService;
    //Access Token 재발급 받기
    @PostMapping("refresh-token")
    public ResponseDto<ResponseTokenDto> refreshToken(@RequestBody RefreshTokenBodyDto bodyDto) {
        return loginService.refreshToken(bodyDto);
    }

    //Access Token 받기
    @PostMapping("generate-token")
    public ResponseDto<ResponseTokenDto> generateToken(@RequestBody GenerateTokenBodyDto bodyDto) {
        return loginService.generateToken(bodyDto);
    }

    //userKey로 로그인 연결 끊기
    @PostMapping("remove-by-user-key")
    public ResponseDto<ResponseUserKeyDto> removeByUserKey(@RequestBody RemoveByUserKeyBodyDto bodyDto) {
        return loginService.removeByUserKey(bodyDto);
    }

    //Access Token으로 로그인 연결 끊기
    @PostMapping("remove-by-access-token")
    public ResponseDto<ResponseUserKeyDto> removeByAccessToken(@RequestHeader RemoveByAccessTokenHeaderDto headerDto) {
        return loginService.removeByAccessToken(headerDto);
    }

    //사용자 정보 받기
    @GetMapping("login-me")
    public ResponseDto<ResponseUserDto> loginMe(@RequestHeader LoginMeHeaderDto headerDto) {
        return loginService.loginMe(headerDto);
    }
}
