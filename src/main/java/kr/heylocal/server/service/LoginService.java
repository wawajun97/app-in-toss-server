package kr.heylocal.server.service;

import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.UserRecord;
import kr.heylocal.server.common.AppInTossEndPoint;
import kr.heylocal.server.dto.ResponseDto;
import kr.heylocal.server.dto.ResponseErrorDto;
import kr.heylocal.server.dto.login.*;
import kr.heylocal.server.util.TLSClientUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final TLSClientUtil tlsClientUtil;
    private final FirebaseAuth firebaseAuth;
    @Value("${base64.encoded.aes.key}")
    private String base64EncodedAesKey;

    //Access Token 재발급 받기
    public ResponseDto<ResponseTokenDto> refreshToken(RefreshTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REFRESH_TOKEN.getPath(), bodyDto, new ParameterizedTypeReference<ResponseDto<ResponseTokenDto>>() {}, null);
        return result;
    }

    //Access Token 받기
    public ResponseDto<ResponseTokenDto> generateToken(GenerateTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.GENERATE_TOKEN.getPath(), bodyDto, new ParameterizedTypeReference<ResponseDto<ResponseTokenDto>>() {},null);

        return result;
    }

    //userKey로 로그인 연결 끊기
    public ResponseDto<ResponseUserKeyDto> removeByUserKey(RemoveByUserKeyBodyDto bodyDto) {
        ResponseDto<ResponseUserKeyDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REMOVE_BY_USER_KEY.getPath(), bodyDto,new ParameterizedTypeReference<ResponseDto<ResponseUserKeyDto>>() {}, null);
        return result;
    }

    //Access Token으로 로그인 연결 끊기
    public ResponseDto<ResponseUserKeyDto> removeByAccessToken(String authorization) {
        ResponseDto<ResponseUserKeyDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REMOVE_BY_ACCESS_TOKEN.getPath(), null, new ParameterizedTypeReference<ResponseDto<ResponseUserKeyDto>>() {}, authorization);
        return result;
    }

    //사용자 정보 받기
    public ResponseDto<ResponseUserDto> loginMe(String authorization) {
        ResponseDto<ResponseUserDto> result = tlsClientUtil.callTossGetApi(AppInTossEndPoint.LOGIN_ME.getPath(), new ParameterizedTypeReference<ResponseDto<ResponseUserDto>>() {}, authorization);
        return result;
    }

    public ResponseDto<String> tossAuth(GenerateTokenBodyDto bodyDto) {
        //generate-token 호출
        ResponseDto<ResponseTokenDto> generateTokenResult = this.generateToken(bodyDto);

        log.info("generateTokenResult : {}", generateTokenResult);

        //generate-token 실패 예외처리
        if(null != generateTokenResult && "FAIL".equals(generateTokenResult.getResultType())) {
            return getTossAuthResponse(null, generateTokenResult.getError().getReason());
        }

        //login-me 호출
        ResponseDto<ResponseUserDto> loginMeResult = this.loginMe("Bearer " + generateTokenResult.getSuccess().getAccessToken());

        //login-me 실패 예외처리
        if(null != loginMeResult && "FAIL".equals(loginMeResult.getResultType())) {
            return getTossAuthResponse(null, loginMeResult.getError().getReason());
        }

        log.info("loginMeResult : {}", loginMeResult);

        String decPhone = null;
        String decEmail = null;
        String decCallingCode = null;

        try {
            decPhone = decrypted(loginMeResult.getSuccess().getPhone());
            decEmail = decrypted(loginMeResult.getSuccess().getEmail());
            decCallingCode = decrypted(loginMeResult.getSuccess().getCallingCode());
        } catch (Exception e) {
            return getTossAuthResponse(null,"decoded error");
        }

        log.info("decPhone : {}", decPhone);
        log.info("decEmail : {}", decEmail);
        log.info("decCallingCode : {}", decCallingCode);

        UserRecord.CreateRequest createRequest = new UserRecord.CreateRequest();
        //이메일이 있으면 추가
        if(null != decEmail) {
            createRequest.setEmail(decEmail);
            createRequest.setEmailVerified(true);
        } else {
            createRequest.setEmailVerified(false);
        }

        //전화번호가 있으면 추가
        if(null != decPhone) {
            createRequest.setPhoneNumber(decCallingCode + decPhone.replaceFirst("^0", ""));
        }
        createRequest.setUid(loginMeResult.getSuccess().getUserKey());

        String customToken = null;
        try {
            UserRecord userRecord = this.firebaseAuth.createUser(createRequest);

            log.info("userRecord : {}", userRecord);

            if(null == userRecord) {
                return getTossAuthResponse(null,"userRecord error");
            }

            customToken = this.firebaseAuth.createCustomToken(userRecord.getUid());
        } catch(Exception e) {
            return getTossAuthResponse(null, "firebase error");
        }

        log.info("customToken : {}", customToken);

        return getTossAuthResponse(customToken, null);
    }

    private ResponseDto<String> getTossAuthResponse(String customToken, String errorMsg) {
        ResponseDto<String> result = new ResponseDto<>();

        if(null != customToken) {
            result.setResultType("SUCCESS");
            result.setSuccess(customToken);
        } else {
            result.setResultType("FAIL");
            ResponseErrorDto errorDto = new ResponseErrorDto().builder()
                    .reason(errorMsg)
                    .build();
            result.setError(errorDto);
        }

        return result;
    }

    public String decrypted(String encryptedText) throws Exception {
        String aad = "TOSS";

        if(null != encryptedText) {
            final int IV_LENGTH = 12;
            byte[] decoded = Base64.getDecoder().decode(encryptedText);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            byte[] keyByteArray = Base64.getDecoder().decode(base64EncodedAesKey);
            SecretKeySpec key = new SecretKeySpec(keyByteArray, "AES");
            byte[] iv = new byte[IV_LENGTH];
            System.arraycopy(decoded, 0, iv, 0, IV_LENGTH);
            GCMParameterSpec nonceSpec = new GCMParameterSpec(16 * Byte.SIZE, iv);

            cipher.init(Cipher.DECRYPT_MODE, key, nonceSpec);
            cipher.updateAAD(aad.getBytes());

            byte[] decrypted = cipher.doFinal(decoded, IV_LENGTH, decoded.length - IV_LENGTH);
            return new String(decrypted);
        }

        return null;
    }
}
