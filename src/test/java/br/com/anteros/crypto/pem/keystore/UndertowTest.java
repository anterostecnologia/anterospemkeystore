/*******************************************************************************
 *  Copyright 2017 Anteros Tecnologia
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  	http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *******************************************************************************/

package br.com.anteros.crypto.pem.keystore;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.SecureRandom;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import com.google.common.io.ByteSource;

import io.undertow.Undertow;
import io.undertow.server.HttpHandler;
import io.undertow.server.HttpServerExchange;
import io.undertow.util.Headers;

public class UndertowTest {

    @Test
    public void testTls() throws Exception {

        final int port = 8080;

        final KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());

        final KeyStore ks = KeyStore.getInstance("PEMCFG", new AnterosPemKeyStoreProvider());
        try (FileInputStream stream = new FileInputStream("src/test/resources/tls.properties")) {
            ks.load(stream, new char[0]);
        }

        kmf.init(ks, new char[0]);

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        final Undertow server = Undertow.builder()
                .addHttpsListener(port, "localhost", kmf.getKeyManagers(), tmf.getTrustManagers())
                .setHandler(new HttpHandler() {

                    @Override
                    public void handleRequest(final HttpServerExchange exchange) throws Exception {
                        exchange.getResponseHeaders().put(Headers.CONTENT_TYPE, "text/plain");
                        exchange.getResponseSender().send("Foo");
                    }
                })
                .build();

        try {
            server.start();

            final String content = testGet("https://localhost:" + port);
            Assertions.assertEquals("Foo", content);

        } finally {
            server.stop();
        }
    }

    private String testGet(final String url) throws Exception {

        final KeyStore ks = KeyStore.getInstance("PEMCA", new AnterosPemKeyStoreProvider());
        try (FileInputStream stream = new FileInputStream("src/test/resources/ca.crt")) {
            ks.load(stream, new char[0]);
        }

        final TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);

        final SSLContext ctx = SSLContext.getInstance("TLSv1.2");
        ctx.init(null, tmf.getTrustManagers(), new SecureRandom());

        final HttpsURLConnection con = (HttpsURLConnection) new URL(url).openConnection();
        con.setSSLSocketFactory(ctx.getSocketFactory());
        con.setHostnameVerifier(new HostnameVerifier() {

            @Override
            public boolean verify(final String hostname, final SSLSession session) {
                return true;
            }
        });

        return new ByteSource() {

            @Override
            public InputStream openStream() throws IOException {
                return con.getInputStream();
            }
        }.asCharSource(StandardCharsets.UTF_8).read();

    }

}
