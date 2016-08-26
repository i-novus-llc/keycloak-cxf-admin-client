package org.keycloak.admin.client;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Optional;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.apache.cxf.configuration.jsse.TLSClientParameters;
import org.apache.cxf.jaxrs.client.ClientConfiguration;
import org.apache.cxf.jaxrs.client.WebClient;
import org.apache.cxf.transport.http.HTTPConduit;

/**
 * CXF WebClient supporting SSL security.
 * 
 * @author Christian Lutz
 *
 */
public class KeycloakWebClientFactory {

    public static WebClient create(String url, List<Object> providers, Optional<String> trustStoreLocation) 
            throws Exception {
        final WebClient client = WebClient.create(url, providers);
        secure(client, trustStoreLocation);
        return client;
    }

    private static void secure(WebClient client, Optional<String> trustStoreLoc) throws Exception {

        final ClientConfiguration config = WebClient.getConfig(client);
        final HTTPConduit http = (HTTPConduit) config.getConduit();

        /**
         * Provide the keystore containing the public key of the server, if a secure 
         * https connection is required
         */
        if (trustStoreLoc.isPresent()) {

            final TLSClientParameters tlsParams = new TLSClientParameters(); // TLS is default!
            tlsParams.setDisableCNCheck(true);

            final KeyStore trustStore = KeyStore.getInstance("JKS");

            if(!new File(trustStoreLoc.get()).exists()){
                throw new Exception("Connot load certificate");
            }

            try (FileInputStream fileInputStream = new FileInputStream(trustStoreLoc.get())) {
                trustStore.load(fileInputStream, null);
            }

            final TrustManager[] myTrustStoreKeyManagers = getTrustManagers(trustStore);
            tlsParams.setTrustManagers(myTrustStoreKeyManagers);
            http.setTlsClientParameters(tlsParams);
        }
    }

    private static TrustManager[] getTrustManagers(KeyStore trustStore) throws NoSuchAlgorithmException, 
            KeyStoreException {
        final String alg = KeyManagerFactory.getDefaultAlgorithm();
        final TrustManagerFactory fac = TrustManagerFactory.getInstance(alg);
        fac.init(trustStore);
        return fac.getTrustManagers();
    }
}
