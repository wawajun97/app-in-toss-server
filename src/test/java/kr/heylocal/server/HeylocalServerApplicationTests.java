package kr.heylocal.server;

import kr.heylocal.server.service.LoginService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

@SpringBootTest
class HeylocalServerApplicationTests {
	@Autowired
	private LoginService loginService;
	@Test
	void contextLoads() throws Exception {
		System.out.println(loginService.decrypted("bcHzRiFd97TpHaGRKZ/3AOnH0J4IPwwBPxN+LFFhB9V/uzuHUg=="));
	}

	@Test
	void test() throws Exception {
		String base64EncodedAesKey = "lMzOg9UJY3UBCD/s66haRa0l6x9XRUvDMabHUDhMrPE=";
		String aad = "TOSS";
		byte[] keyByteArray = Base64.getDecoder().decode(base64EncodedAesKey);
		SecretKeySpec key = new SecretKeySpec(keyByteArray, "AES");

		Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		cipher.updateAAD(aad.getBytes());

		byte[] iv = cipher.getIV();  // 12바이트 자동 생성됨
		byte[] encrypted = cipher.doFinal("박기택".getBytes());

// IV + 암호문+태그 합쳐서 Base64 인코딩
		byte[] combined = new byte[iv.length + encrypted.length];
		System.arraycopy(iv, 0, combined, 0, iv.length);
		System.arraycopy(encrypted, 0, combined, iv.length, encrypted.length);

		String encryptedText = Base64.getEncoder().encodeToString(combined);
		System.out.println(encryptedText);
	}

	@Test
	public void djsfkl() {
		System.out.println("eyJraWQiOiJjZXJ0IiwiYWxnIjoiUlMyNTYifQ.eyJzdWIiOiJuMHVhMHh4YWlLQUpkZG9iVUlSZjJJcW9Lcm9Sdjg4PSIsImF1ZCI6ImFtdnk4bjUzdXFpMXlxcTlsbnZmb3JtejJjYm5reml6IiwibmJmIjoxNzYxMjM0NzY4LCJzY29wZSI6WyJ1c2VyX2NpIiwidXNlcl9iaXJ0aGRheSIsInVzZXJfbmF0aW9uYWxpdHkiLCJ1c2VyX2VtYWlsIiwidXNlcl9uYW1lIiwidXNlcl9waG9uZSIsInVzZXJfZ2VuZGVyIl0sImlzcyI6Imh0dHBzOi8vY2VydC50b3NzLmltIiwiZXhwIjoxNzYxMjM4MzY4LCJpYXQiOjE3NjEyMzQ3NjgsImp0aSI6IjMzY2M5MmU0LTk0ZmUtNGQ5ZS05NWMzLTJmNDljMjk5YTkxNCJ9.De5opvOzygWj1VJbFLHI0OmIvynYRDBuMEyq5X4EXo38X_Vl9YoEnGKA_17pN3iMZXCoSjbKiBIe0adt1-GOzo2oBxf_8ag5bd-ETZmeINIdL4wL5MbdY8t5gM7P5XTDG592X5Tvj99YHqrg9eZNEUTFdx5uI4rkUfn2nKAy-yO0qfFiyL52nseiaRB_gMTTyk5DVcMX_5ypx2a_vkp0kIf0HyJS6Ld9c9G47_v9J03PBirPZi0HLvW8yMNlgne4ZOS8G6uaazTVkzT0XFqks3gcmEJm06MxsqS9kJszWH1OgAjqJSfMH3w_-i1DKlKPBFcvUw66eoWytf9bkO-nJA".replaceAll(" ",""));
	}
}
