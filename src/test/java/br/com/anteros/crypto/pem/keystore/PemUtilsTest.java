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

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Map;

import org.junit.jupiter.api.Test;

class PemUtilsTest {

    @Test
    void loadFromConfigurationClasspath() throws CertificateException, IOException {
        Map<String, AbstractPemKeyStore.Entry> map = PemUtils.loadFromConfiguration(getClass().getResourceAsStream("/classpath_tls.properties"));
        AbstractPemKeyStore.Entry entry = map.get("keycert");
        assertThat(entry.getKey()).isNotNull();
        assertThat(entry.getCertificate()).isNotNull();
    }

    @Test
    void loadFromConfigurationFileUrl() throws CertificateException, IOException {
        Map<String, AbstractPemKeyStore.Entry> map = PemUtils.loadFromConfiguration(getClass().getResourceAsStream("/file_url_tls.properties"));
        AbstractPemKeyStore.Entry entry = map.get("keycert");
        assertThat(entry.getKey()).isNotNull();
        assertThat(entry.getCertificate()).isNotNull();
    }

    @Test
    void loadFromConfigurationFile() throws CertificateException, IOException {
        Map<String, AbstractPemKeyStore.Entry> map = PemUtils.loadFromConfiguration(getClass().getResourceAsStream("/file_tls.properties"));
        AbstractPemKeyStore.Entry entry = map.get("keycert");
        assertThat(entry.getKey()).isNotNull();
        assertThat(entry.getCertificate()).isNotNull();
    }
}
