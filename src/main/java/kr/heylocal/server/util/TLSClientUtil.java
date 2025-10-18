package kr.heylocal.server.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import jakarta.annotation.PostConstruct;
import kr.heylocal.server.dto.HeaderDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Map;

@Slf4j
@Component
public class TLSClientUtil {
//    @Value("${heylocal.key}")
    private String HEYLOCAL_KEY;

//    @Value("${heylocal.crt}")
    private String HEYLOCAL_CRT;

    @Value("${toss.base.url}")
    private String BASE_URL;

    private SslContext sslContext;
    private HttpClient httpClient;
    private WebClient webClient;

    @PostConstruct
    public void init() {
        try {
            getSecretManager();
            this.sslContext = createSSLContext();

            this.httpClient = HttpClient.create()
                    .secure(ssl -> ssl.sslContext(this.sslContext));

            this.webClient = WebClient.builder()
                    .clientConnector(new ReactorClientHttpConnector(this.httpClient))
                    .build();
        } catch (Exception e) {
            throw new RuntimeException("TLSClientUtil initialization failed.", e);
        }
    }

    public <T, U extends HeaderDto> T callTossGetApi(String uri, Class<T> responseDtoClass, U headerDto) {
        try {
            return makeGetRequest(BASE_URL + uri, responseDtoClass, headerDto);
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    public <T, U extends HeaderDto, V> T callTossPostApi(String uri, V bodyDto, Class<T> responseDtoClass, U headerDto) {
        try {
            return makePostRequest(BASE_URL + uri, bodyDto, responseDtoClass, headerDto);
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    private SslContext createSSLContext() throws Exception {
        X509Certificate cert = loadCertificate();
        PrivateKey key = loadPrivateKey();

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

    private X509Certificate loadCertificate() throws Exception {
        String content = HEYLOCAL_CRT
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(content);
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(bytes));
    }

    private PrivateKey loadPrivateKey() throws Exception {
        String content = HEYLOCAL_KEY
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] bytes = Base64.getDecoder().decode(content);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(bytes);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private String makeRequest(String url, String method, SSLContext context) throws IOException {
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

    public <T, U extends HeaderDto> T makeGetRequest(String uri, Class<T> responseDtoClass, U headerDto) {
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

    public <T, U extends HeaderDto, V> T makePostRequest(String uri, V requestDto, Class<T> responseDtoClass, U headerDto) {
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

    private void getSecretManager() throws JsonProcessingException {
        String secretName = "heylocal/dev";
        Region region = Region.of("ap-southeast-2");

        // Create a Secrets Manager client
        SecretsManagerClient client = SecretsManagerClient.builder()
                .region(region)
                .build();

        GetSecretValueRequest getSecretValueRequest = GetSecretValueRequest.builder()
                .secretId(secretName)
                .build();

        GetSecretValueResponse getSecretValueResponse;

        try {
            getSecretValueResponse = client.getSecretValue(getSecretValueRequest);
            ObjectMapper objectMapper = new ObjectMapper();
            Map<String,String> map = objectMapper.readValue(getSecretValueResponse.secretString(), Map.class);
            HEYLOCAL_KEY = map.get("heylocal.key");
            HEYLOCAL_CRT = map.get("heylocal.crt");
        } catch (Exception e) {
            // For a list of exceptions thrown, see
            // https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html
            throw e;
        }
    }
}
