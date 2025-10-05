package kr.heylocal.server.service;

import kr.heylocal.server.dto.ResponseDto;
import kr.heylocal.server.dto.login.*;
import kr.heylocal.server.util.TLSClientUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final TLSClientUtil tlsClientUtil;
    //Access Token 재발급 받기
    public ResponseDto<ResponseTokenDto> refreshToken(@RequestBody RefreshTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi("/user/oauth2/refresh-token", bodyDto, ResponseDto.class, null);
        return result;
    }

    //Access Token 받기
    public ResponseDto<ResponseTokenDto> generateToken(@RequestBody GenerateTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi("/user/oauth2/generate-token", bodyDto, ResponseDto.class,null);
        return result;
    }

    //userKey로 로그인 연결 끊기
    public ResponseDto<ResponseUserKeyDto> removeByUserKey(@RequestBody RemoveByUserKeyBodyDto bodyDto) {
        ResponseDto<ResponseUserKeyDto> result = tlsClientUtil.callTossPostApi("/user/oauth2/remove-by-user-key", bodyDto,ResponseDto.class, null);
        return result;
    }

    //Access Token으로 로그인 연결 끊기
    public ResponseDto<ResponseUserKeyDto> removeByAccessToken(@RequestHeader RemoveByAccessTokenHeaderDto headerDto) {
        ResponseDto<ResponseUserKeyDto> result = tlsClientUtil.callTossPostApi("/user/oauth2/remove-by-access-token", null, ResponseDto.class, headerDto);
        return result;
    }

    //사용자 정보 받기
    public ResponseDto<ResponseUserDto> loginMe(@RequestHeader LoginMeHeaderDto headerDto) {
        ResponseDto<ResponseUserDto> result = tlsClientUtil.callTossGetApi("/user/oauth2/login-me", ResponseDto.class, headerDto);
        return result;
    }
}
