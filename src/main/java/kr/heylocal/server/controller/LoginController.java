package kr.heylocal.server.controller;

import kr.heylocal.server.dto.ResponseDto;
import kr.heylocal.server.dto.login.*;
import kr.heylocal.server.util.TLSClientUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@Slf4j
public class LoginController {
    //Access Token 재발급 받기
    @PostMapping("refresh-token")
    public ResponseEntity<ResponseDto<ResponseTokenDto>> refreshToken(@RequestBody RefreshTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = TLSClientUtil.callTossPostApi("/user/oauth2/refresh-token", bodyDto, ResponseDto.class, null);
        return ResponseEntity.ok(result);
    }

    //Access Token 받기
    @PostMapping("generate-token")
    public ResponseEntity<ResponseDto<ResponseTokenDto>> generateToken(@RequestBody GenerateTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = TLSClientUtil.callTossPostApi("/user/oauth2/generate-token", bodyDto, ResponseDto.class,null);
        return ResponseEntity.ok(result);
    }

    //userKey로 로그인 연결 끊기
    @PostMapping("remove-by-user-key")
    public ResponseEntity<ResponseDto<ResponseUserKeyDto>> removeByUserKey(@RequestBody RemoveByUserKeyBodyDto bodyDto) {
        ResponseDto<ResponseUserKeyDto> result = TLSClientUtil.callTossPostApi("/user/oauth2/remove-by-user-key", bodyDto,ResponseDto.class, null);
        return ResponseEntity.ok(result);
    }

    //Access Token으로 로그인 연결 끊기
    @PostMapping("remove-by-access-token")
    public ResponseEntity<ResponseDto<ResponseUserKeyDto>> removeByAccessToken(@RequestHeader RemoveByAccessTokenHeaderDto headerDto) {
        ResponseDto<ResponseUserKeyDto> result = TLSClientUtil.callTossPostApi("/user/oauth2/remove-by-access-token", null, ResponseDto.class, headerDto);
        return ResponseEntity.ok(result);
    }

    //사용자 정보 받기
    @GetMapping("login-me")
    public ResponseEntity<ResponseDto<ResponseUserDto>> loginMe(@RequestHeader LoginMeHeaderDto headerDto) {
        ResponseDto<ResponseUserDto> result = TLSClientUtil.callTossGetApi("/user/oauth2/login-me", ResponseDto.class, headerDto);
        return ResponseEntity.ok(result);
    }
}
