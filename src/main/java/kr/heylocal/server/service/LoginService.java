package kr.heylocal.server.service;

import com.google.common.base.Strings;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import com.google.firebase.cloud.FirestoreClient;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
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
import java.util.Base64;

@Service
@Slf4j
@RequiredArgsConstructor
public class LoginService {
    private final TLSClientUtil tlsClientUtil;
    private final FirebaseAuth firebaseAuth;
    private final SupabaseClientUtil supabaseClientUtil;
    @Value("${base64.encoded.aes.key}")
    private String base64EncodedAesKey;

    private static final String RESULT_TYPE_FAIL = "FAIL";
    private static final String DECODE_ERROR_MESSAGE = "Failed to decode user information";
    private static final String BEARER_PREFIX = "Bearer ";

    //Access Token 재발급 받기
    public ResponseDto<ResponseTokenDto> refreshToken(RefreshTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.REFRESH_TOKEN.getPath(), bodyDto, new ParameterizedTypeReference<ResponseDto<ResponseTokenDto>>() {}, null);
        return result;
    }

    //Access Token 받기
    public ResponseDto<ResponseTokenDto> generateToken(GenerateTokenBodyDto bodyDto) {
        ResponseDto<ResponseTokenDto> result = tlsClientUtil.callTossPostApi(AppInTossEndPoint.GENERATE_TOKEN.getPath(), bodyDto, new ParameterizedTypeReference<ResponseDto<ResponseTokenDto>>() {},null);
        if(result != null && result.getSuccess() != null) {
            log.info("geeeee : {}", result.getSuccess().getAccessToken());
        }

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
        // 1. 토큰 생성
        ResponseDto<ResponseTokenDto> tokenResponse = generateToken(bodyDto);
        if (isFailedResponse(tokenResponse)) {
            return createErrorResponse(tokenResponse.getError().getReason());
        }

        // 2. 사용자 정보 조회
        String accessToken = tokenResponse.getSuccess().getAccessToken();
        ResponseDto<ResponseUserDto> userResponse = loginMe(BEARER_PREFIX + accessToken);
        if (isFailedResponse(userResponse)) {
            return createErrorResponse(userResponse.getError().getReason());
        }

        // 3. 사용자 정보 복호화
        DecryptedUserInfoDto decryptedInfo = decryptUserInfo(userResponse.getSuccess());
        if (decryptedInfo == null) {
            return createErrorResponse(DECODE_ERROR_MESSAGE);
        }

        // 4. Firebase 커스텀 토큰 생성
        try {
            String customToken = createFirebaseCustomToken(
                    userResponse.getSuccess().getUserKey(),
                    decryptedInfo
            );
            return createSuccessResponse(customToken);
        } catch (Exception e) {
            log.error("Firebase authentication failed", e);
            return createErrorResponse(e.getMessage());
        }
    }

    private boolean isFailedResponse(ResponseDto<?> response) {
        return response != null && RESULT_TYPE_FAIL.equals(response.getResultType());
    }

    private DecryptedUserInfoDto decryptUserInfo(ResponseUserDto userDto) {
        try {
            String phone = decrypted(userDto.getPhone());
            String email = decrypted(userDto.getEmail());
            String callingCode = decrypted(userDto.getCallingCode());
            return new DecryptedUserInfoDto(phone, email, callingCode);
        } catch (Exception e) {
            log.error("Failed to decrypt user information", e);
            return null;
        }
    }

    private String createFirebaseCustomToken(String userKey, DecryptedUserInfoDto info)
            throws FirebaseAuthException {
        UserRecord.CreateRequest createRequest = buildCreateRequest(userKey, info);
        UserRecord userRecord = getOrCreateFirebaseUser(userKey, createRequest);
        return firebaseAuth.createCustomToken(userRecord.getUid());
    }

    private UserRecord.CreateRequest buildCreateRequest(String userKey, DecryptedUserInfoDto info) {
        UserRecord.CreateRequest request = new UserRecord.CreateRequest();
        request.setUid(userKey);

        // 이메일 설정
        if (!Strings.isNullOrEmpty(info.getEmail())) {
            request.setEmail(info.getEmail());
            request.setEmailVerified(true);
        } else {
            request.setEmailVerified(false);
        }

        // 전화번호 설정
        if (!Strings.isNullOrEmpty(info.getPhone())) {
            String formattedPhone = formatPhoneNumber(info.getCallingCode(), info.getPhone());
            request.setPhoneNumber(formattedPhone);
        }

        return request;
    }

    private String formatPhoneNumber(String callingCode, String phone) {
        String normalizedPhone = phone.replaceFirst("^0", "");
        return "+" + callingCode + normalizedPhone;
    }

    private UserRecord getOrCreateFirebaseUser(String uid, UserRecord.CreateRequest createRequest)
            throws FirebaseAuthException {
        try {
            return firebaseAuth.getUser(uid);
        } catch (FirebaseAuthException e) {
            log.info("User not found, creating new user: {}", uid);
            return firebaseAuth.createUser(createRequest);
        }
    }

    private ResponseDto<String> createSuccessResponse(String customToken) {
        return getTossAuthResponse(customToken, null);
    }

    private ResponseDto<String> createErrorResponse(String errorMessage) {
        return getTossAuthResponse(null, errorMessage);
    }

    public ResponseDto<String> logoutByCallback(CallbackLogoutDto dto) {
        ResponseDto<String> result = new ResponseDto<>();
        String userKey = dto.getUserKey().toString();

        try {
            // 1. 사용자 타입 조회 및 변경
            String deletedUserType = getDeletedUserType(userKey);

            // 2. Firebase Auth 사용자 삭제
            deleteFirebaseUser(userKey);

            // 3. Supabase 사용자 데이터 업데이트 (탈퇴 처리)
            updateSupabaseUserAsDeleted(userKey, deletedUserType);

            // 4. Firestore 데이터 초기화
            cleanupFirestoreData(userKey);

            result.setResultType("success");
        } catch (Exception e) {
            log.error("로그아웃 처리 중 오류 발생 - userId: {}, error: {}", userKey, e.getMessage(), e);
            result.setResultType("error : " + e.getMessage());
        }

        return result;
    }

    private String getDeletedUserType(String userKey) {
        ArrayList<Map<String, String>> users = supabaseClientUtil.callSupabaseApi(
                "/rest/v1/users?id=eq." + userKey + "&select=user_type",
                HttpMethod.GET,
                new HashMap<>(),
                new ParameterizedTypeReference<ArrayList>() {}
        );

        if (users.isEmpty()) {
            throw new IllegalStateException("사용자를 찾을 수 없습니다: " + userKey);
        }

        String userType = users.get(0).get("user_type");
        return UserType.fromName(userType).toDeleted().getName();
    }

    private void deleteFirebaseUser(String userKey) {
        try {
            firebaseAuth.deleteUser(userKey.toString());
            log.info("Firebase 사용자 삭제 완료 - userId: {}", userKey);
        } catch (Exception e) {
            log.error("Firebase 사용자 삭제 실패 - userId: {}, error: {}", userKey, e.getMessage());
        }
    }

    private void updateSupabaseUserAsDeleted(String userKey, String deletedUserType) {
        Map<String, String> body = new HashMap<>();
        body.put("user_type", deletedUserType);
        body.put("username", "탈퇴한 사용자");
        body.put("image_url", null);

        supabaseClientUtil.callSupabaseApi(
                "/rest/v1/users?id=eq." + userKey,
                HttpMethod.PATCH,
                body,
                new ParameterizedTypeReference<>() {}
        );

        log.info("Supabase 사용자 데이터 업데이트 완료 - userId: {}", userKey);
    }

    private void cleanupFirestoreData(String userKey) {
        try {
            Map<String, Object> updateData = new HashMap<>();
            updateData.put("fcmTokens", new ArrayList<>());
            updateData.put("badgeCount", 0);
            updateData.put("lastUpdated", new Timestamp(System.currentTimeMillis()));

            FirestoreClient.getFirestore()
                    .collection("users")
                    .document(userKey)
                    .update(updateData)
                    .get();

            log.info("Firestore 데이터 초기화 완료 - userId: {}", userKey);
        } catch (InterruptedException | ExecutionException e) {
            log.error("Firestore 데이터 초기화 실패 - userId: {}, error: {}", userKey, e.getMessage());
            Thread.currentThread().interrupt(); // InterruptedException 발생 시 인터럽트 상태 복원
            // Firestore 초기화 실패는 치명적이지 않으므로 계속 진행
        }
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
