package kr.heylocal.server.util;

import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import jakarta.annotation.PostConstruct;
import java.nio.file.Path;
import kr.heylocal.server.dto.CertDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import javax.net.ssl.KeyManagerFactory;
import java.io.ByteArrayInputStream;
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
import java.util.Map;

@Component
@Slf4j
public class TLSClientUtil {
    private final String CERT_PATH = "/opt/keyfile/mTLS_인증서_20250817/heylocal-key_public.crt";
    private final String KEY_PATH = "/opt/keyfile/mTLS_인증서_20250817/heylocal-key_private.key";

    private final String BASE_URL = "https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss";

    private SslContext sslContext;
    private HttpClient httpClient;
    private WebClient webClient;

    @PostConstruct
    public void init() {
        try {
            Path certPath = Paths.get(CERT_PATH);
            Path keyPath = Paths.get(KEY_PATH);
            if (!Files.exists(certPath) || !Files.exists(keyPath)) {
                log.warn("Private key not found, skipping initialization...");
                return;
            }

            this.sslContext = createSSLContext(CERT_PATH, KEY_PATH);

            this.httpClient = HttpClient.create()
                    .secure(ssl -> ssl.sslContext(this.sslContext));

            this.webClient = WebClient.builder()
                    .clientConnector(new ReactorClientHttpConnector(this.httpClient))
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("TLSClientUtil initialization failed.", e);
        }
    }

    public <T> T callTossGetApi(String uri, ParameterizedTypeReference<T> responseDtoClass, String authorization) {
        try {
            return makeGetRequest(BASE_URL + uri, responseDtoClass, authorization);
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    public <T, V> T callTossPostApi(String uri, V bodyDto, ParameterizedTypeReference<T> responseDtoClass, String authorization) {
        try {
            return makePostRequest(BASE_URL + uri, bodyDto, responseDtoClass, authorization);
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    private SslContext createSSLContext(String certPath, String keyPath) throws Exception {
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

    private X509Certificate loadCertificate(String path) throws Exception {
        String content = Files.readString(Paths.get(path))
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(content);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(bytes));
    }

    private PrivateKey loadPrivateKey(String path) throws Exception {
        String content = Files.readString(Paths.get(path))
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(content);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    public <T> T makeGetRequest(String uri, ParameterizedTypeReference<T> responseDtoClass, String authorization) {
        WebClient.RequestBodySpec requestSpec = webClient.method(HttpMethod.GET)
                .uri(uri)
                .accept(MediaType.APPLICATION_JSON);

        if (authorization != null) {
            requestSpec = requestSpec.header("Authorization", authorization);
        }

        return requestSpec.retrieve()
                .bodyToMono(responseDtoClass)
                .block();
    }

    public <T, V> T makePostRequest(String uri, V requestDto, ParameterizedTypeReference<T> responseDtoClass, String authorization) {
        WebClient.RequestBodySpec requestSpec = webClient.method(HttpMethod.POST)
                .uri(uri)
                .accept(MediaType.APPLICATION_JSON);

        if (authorization != null) {
            requestSpec = requestSpec.header("Authorization", authorization);
        }

        if (requestDto != null) {
            requestSpec = (WebClient.RequestBodySpec) requestSpec.bodyValue(requestDto);
        }

        return requestSpec.retrieve()
                .bodyToMono(responseDtoClass)
                .block();
    }
}
