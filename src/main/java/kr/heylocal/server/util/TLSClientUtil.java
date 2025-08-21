package kr.heylocal.server.util;

import kr.heylocal.server.dto.HeaderDto;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpMethod;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;
import reactor.netty.tcp.SslProvider;

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
    private static WebClient webClient;

    private static final String CERT_PATH = "/Users/junseo/Downloads/mTLS_인증서_20250817/heylocal-key_public.crt";
    private static final String KEY_PATH = "/Users/junseo/Downloads/mTLS_인증서_20250817/heylocal-key_private.key";

    private static final String BASE_URL = "https://apps-in-toss-api.toss.im/api-partner/v1/apps-in-toss";

    //생성자에서 sslContext 추가
    public TLSClientUtil() throws Exception {
        SSLContext context = createSSLContext(CERT_PATH, KEY_PATH);
        HttpClient httpClient = HttpClient.create().secure(provider -> provider.sslContext((SslProvider.GenericSslContextSpec<?>) context));

        webClient = WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(httpClient)).build();
    }

    public static <T, U extends HeaderDto> T callTossGetApi(String uri, Class<T> responseDtoClass, U headerDto) {
        try {
            return makeGetRequest(BASE_URL + uri, responseDtoClass, headerDto) ;
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    public static <T, U extends HeaderDto, V> T callTossPostApi(String uri, V bodyDto, Class<T> responseDtoClass, U headerDto) {
        try {
            return makePostRequest(BASE_URL + uri, bodyDto, responseDtoClass, headerDto) ;
        } catch (Exception e) {
            log.error("error : {}",e.getMessage());
            return null;
        }
    }

    private static SSLContext createSSLContext(String certPath, String keyPath) throws Exception {
        X509Certificate cert = loadCertificate(certPath);
        PrivateKey key = loadPrivateKey(keyPath);

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(null, null);
        keyStore.setCertificateEntry("client-cert", cert);
        keyStore.setKeyEntry("client-key", key, "".toCharArray(), new Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, "".toCharArray());

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), null, null);
        return sslContext;
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

//    private static Mono<ResponseDto> makeGetRequest(String uri, Map<String,String> params, Map<String,String> headers) {
//        return webClient.get()
//                .uri(uriBuilder -> {
//                    // uriBuilder를 사용하여 Map에 있는 모든 파라미터를 쿼리 파라미터로 추가
//                    uriBuilder.path(uri);
//                    params.forEach(uriBuilder::queryParam);
//                    return uriBuilder.build();
//                })
//                .headers(httpHeaders -> {
//                    // 람다식을 사용해 Map에 있는 모든 헤더를 HttpHeaders에 추가
//                    headers.forEach(httpHeaders::add);
//                })
//                .retrieve()
//                .bodyToMono(ResponseDto.class);
//    }
//
//    private static Mono<ResponseDto> makePostRequest(String uri, Map<String,String> body, Map<String,String> headers) {
//        return webClient.post()
//                .uri(uri)
//                .headers(httpHeaders -> {
//                    // 람다식을 사용해 Map에 있는 모든 헤더를 HttpHeaders에 추가
//                    headers.forEach(httpHeaders::add);
//                })
//                .bodyValue(body)
//                .retrieve()
//                .bodyToMono(ResponseDto.class);
//    }

    public static <T, U extends HeaderDto> T makeGetRequest(String uri, Class<T> responseDtoClass, U headerDto) {
        return webClient.method(HttpMethod.GET)
                .uri(uri)
                .headers(headerDto.toHeader())
                .retrieve()
                .bodyToMono(responseDtoClass)
                .block();
    }

    public static <T, U extends HeaderDto, V> T makePostRequest(String uri, V requestDto, Class<T> responseDtoClass, U headerDto) {
        return webClient.method(HttpMethod.POST)
                .uri(uri)
                .headers(headerDto.toHeader())
                .bodyValue(requestDto)
                .retrieve()
                .bodyToMono(responseDtoClass)
                .block();
    }

}
