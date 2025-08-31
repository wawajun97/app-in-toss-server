package kr.heylocal.server.util;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import kr.heylocal.server.dto.HeaderDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

@Slf4j
public class TLSClientUtil {
    private static final String CERT_PATH = "/Users/junseo/Downloads/mTLS_인증서_20250817/heylocal-key_public.crt";
    private static final String KEY_PATH = "/Users/junseo/Downloads/mTLS_인증서_20250817/heylocal-key_private.key";

    private static final String BASE_URL = "https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss";

    private static final SslContext context;
    private static HttpClient httpClient;

    static {
        try {
            context = createSSLContext(CERT_PATH, KEY_PATH);

            httpClient = HttpClient.create()
                    .secure(ssl -> ssl.sslContext(context));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static final WebClient webClient = WebClient.builder()
            .clientConnector(new ReactorClientHttpConnector(httpClient)).build();

    public static <T, U extends HeaderDto> T callTossGetApi(String uri, Class<T> responseDtoClass, U headerDto) {
        try {
            return makeGetRequest(BASE_URL + uri, responseDtoClass, headerDto);
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    public static <T, U extends HeaderDto, V> T callTossPostApi(String uri, V bodyDto, Class<T> responseDtoClass, U headerDto) {
        try {
            return makePostRequest(BASE_URL + uri, bodyDto, responseDtoClass, headerDto);
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    private static SslContext createSSLContext(String certPath, String keyPath) throws Exception {
        X509Certificate cert = loadCertificate(certPath);
        PrivateKey key = loadPrivateKey(keyPath);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("client-cert", cert);
        keyStore.setKeyEntry("client-key", key, "".toCharArray(), new Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "".toCharArray());

        return SslContextBuilder.forClient()
                .keyManager(key, cert)  // 클라이언트 인증서 + 키
                .build();
    }

    private static X509Certificate loadCertificate(String path) throws Exception {
        String content = Files.readString(Paths.get(path))
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(content);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(bytes));
    }

    private static PrivateKey loadPrivateKey(String path) throws Exception {
        String content = Files.readString(Paths.get(path))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(content);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static String makeRequest(String url, String method, SSLContext context) throws IOException {
        HttpsURLConnection connection = (HttpsURLConnection) new URL(url).openConnection();
        connection.setSSLSocketFactory(context.getSocketFactory());
        connection.setRequestMethod(method);
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        } finally {
            connection.disconnect();
        }
    }

    public static <T, U extends HeaderDto> T makeGetRequest(String uri, Class<T> responseDtoClass, U headerDto) {
        if(null == headerDto) {
            return webClient.method(HttpMethod.GET)
                    .uri(uri)
                    .retrieve()
                    .bodyToMono(responseDtoClass)
                    .block();
        } else {
            return webClient.method(HttpMethod.GET)
                    .uri(uri)
                    .headers(headerDto.toHeader())
                    .retrieve()
                    .bodyToMono(responseDtoClass)
                    .block();
        }
    }

    public static <T, U extends HeaderDto, V> T makePostRequest(String uri, V requestDto, Class<T> responseDtoClass, U headerDto) {
        if(null == headerDto) {
            return webClient.method(HttpMethod.POST)
                    .uri(uri)
                    .bodyValue(requestDto)
                    .retrieve()
                    .bodyToMono(responseDtoClass)
                    .block();
        } else {
            return webClient.method(HttpMethod.POST)
                    .uri(uri)
                    .headers(headerDto.toHeader())
                    .bodyValue(requestDto)
                    .retrieve()
                    .bodyToMono(responseDtoClass)
                    .block();
        }
    }

}
