package kr.heylocal.server.service;

import com.google.common.base.Strings;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.cloud.FirestoreClient;
import kr.heylocal.server.common.AppInTossEndPoint;
import kr.heylocal.server.common.UserType;
import kr.heylocal.server.dto.ResponseDto;
import kr.heylocal.server.dto.ResponseErrorDto;
import kr.heylocal.server.dto.login.*;
import kr.heylocal.server.util.SupabaseClientUtil;
import kr.heylocal.server.util.TLSClientUtil;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final TLSClientUtil tlsClientUtil;
    private final SupabaseClientUtil supabaseClientUtil;
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
        if(!Strings.isNullOrEmpty(decEmail)) {
            createRequest.setEmail(decEmail);
            createRequest.setEmailVerified(true);
        } else {
            createRequest.setEmailVerified(false);
        }

        //전화번호가 있으면 추가
        if(!Strings.isNullOrEmpty(decPhone)) {
            createRequest.setPhoneNumber("+" + decCallingCode + decPhone.replaceFirst("^0", ""));
        }
        createRequest.setUid(loginMeResult.getSuccess().getUserKey());

        try {
            // Firebase에 유저가 있는지 검사 후 없으면 생성
            UserRecord userRecord;
            try {
                userRecord = firebaseAuth.getUser(loginMeResult.getSuccess().getUserKey());
            } catch (FirebaseAuthException fe) {
                userRecord = firebaseAuth.createUser(createRequest);
            }

            // Custom Token 생성
            String customToken = firebaseAuth.createCustomToken(userRecord.getUid());

            // 성공 처리 로직
            return getTossAuthResponse(customToken, null);

        } catch (Exception e) {
            return getTossAuthResponse(null, e.getMessage());
        }
    }

    public ResponseDto<String> logoutByCallback(CallbackLogoutDto dto) {
        //supabase에서 유저 타입 검색
        ArrayList<Map<String,String>> user = supabaseClientUtil.callSupabaseApi("/rest/v1/users?id=eq." + dto.getUserKey()+ "&select=user_type",HttpMethod.GET, new HashMap<>(), new ParameterizedTypeReference<ArrayList>() {});

        String userType = UserType.fromName(user.get(0).get("user_type")).toDeleted().getName();

        //파이어베이스 데이터 삭제
        try {
            firebaseAuth.deleteUser(dto.getUserKey().toString());
        } catch (Exception e) {
            log.error("delete firebase data error : {}", e.getMessage());
        }

        //supabase 데이터 삭제
        Map<String,String> body = new HashMap<>();
        body.put("user_type",userType);
        body.put("username","탈퇴한 사용자");
        body.put("image_url",null);

        supabaseClientUtil.callSupabaseApi("/rest/v1/users?id=eq." + dto.getUserKey(), HttpMethod.PATCH, body, new ParameterizedTypeReference<>() {});

        try {
            //fcm 토큰 제거
            //Firestore 배지 카운트 초기화
            //lastUpdated 수정
            Map<String, Object> updateData = new HashMap<>();
            updateData.put("fcmTokens", new ArrayList<>());
            updateData.put("badgeCount", 0);
            updateData.put("lastUpdated", new Timestamp(System.currentTimeMillis()));

            FirestoreClient.getFirestore()
                    .collection("users")
                    .document(dto.getUserKey().toString())
                    .update(updateData)
                    .get();

        } catch (InterruptedException | ExecutionException e) {
            log.error("Firestore 배지 초기화 실패 {}", e.getMessage());
        }

        return null;
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
