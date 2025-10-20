package kr.heylocal.server.service;

import kr.heylocal.server.common.AppInTossEndPoint;
import kr.heylocal.server.dto.ResponseDto;
import kr.heylocal.server.dto.login.*;
import kr.heylocal.server.util.TLSClientUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final TLSClientUtil tlsClientUtil;
    //Access Token 재발급 받기
    public ResponseDto<ResponseTokenDto> refreshToken(RefreshTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REFRESH_TOKEN.getPath(), bodyDto, ResponseDto.class, null);
        return result;
    }

    //Access Token 받기
    public ResponseDto<ResponseTokenDto> generateToken(GenerateTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.GENERATE_TOKEN.getPath(), bodyDto, ResponseDto.class,null);
        return result;
    }

    //userKey로 로그인 연결 끊기
    public ResponseDto<ResponseUserKeyDto> removeByUserKey(RemoveByUserKeyBodyDto bodyDto) {
        ResponseDto<ResponseUserKeyDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REMOVE_BY_USER_KEY.getPath(), bodyDto,ResponseDto.class, null);
        return result;
    }

    //Access Token으로 로그인 연결 끊기
    public ResponseDto<ResponseUserKeyDto> removeByAccessToken(HttpHeaders headerDto) {
        ResponseDto<ResponseUserKeyDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REMOVE_BY_ACCESS_TOKEN.getPath(), null, ResponseDto.class, headerDto);
        return result;
    }

    //사용자 정보 받기
    public ResponseDto<ResponseUserDto> loginMe(HttpHeaders headerDto) {
        ResponseDto<ResponseUserDto> result = tlsClientUtil.callTossGetApi(AppInTossEndPoint.LOGIN_ME.getPath(), ResponseDto.class, headerDto);
        return result;
    }
}
