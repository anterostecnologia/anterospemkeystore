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

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;


import org.junit.jupiter.api.Test;

public class LetsEncryptPemCertificateTest {

    @Test
    public void testLetsEncryptPemCertificateTest() throws Exception {

        final KeyStore ks = KeyStore.getInstance("PEMCFG", new AnterosPemKeyStoreProvider());

        try (FileInputStream stream = new FileInputStream("src/test/resources/pem_tls.properties")) {
            ks.load(stream, new char[] {});
        }

        final java.security.cert.Certificate cert = ks.getCertificate("letsencrypt");
        final X509Certificate x509 = (X509Certificate) cert;
        final Key key = ks.getKey("letsencrypt", new char[] {});

        assertEquals(x509.getSubjectAlternativeNames().size(), 2);

        assertThat(key)
                .isNotNull()
                .isInstanceOf(RSAPrivateKey.class);

        final Certificate[] chain = ks.getCertificateChain("letsencrypt");
        assertNotNull(chain);
        assertEquals(2, chain.length);
    }
}
