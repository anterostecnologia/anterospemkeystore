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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import java.io.File;
import java.io.FileInputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.Certificate;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class PemConfigKeyStoreTest {

    @BeforeAll
    public static void setup() {
        Security.addProvider(new AnterosPemKeyStoreProvider());
    }

    @AfterAll
    public static void cleanup() {
        Security.removeProvider("PEM");
    }

    @Test
    public void test1() throws Exception {

        final KeyStore ks = KeyStore.getInstance("PEMCFG");
        try (FileInputStream stream = new FileInputStream(new File("src/test/resources/tls.properties"))) {
            ks.load(stream, new char[0]);
        }

        final Certificate[] chain = ks.getCertificateChain("keycert");
        final Certificate cert = ks.getCertificate("keycert");
        final Key key = ks.getKey("keycert", new char[0]);

        assertNotNull(chain);
        assertEquals(2, chain.length);

        assertNotNull(cert);
        assertNotNull(key);

    }
}
