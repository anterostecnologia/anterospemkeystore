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

import java.io.IOException;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Collections;
import java.util.Map;

/**
 * Uma implementação abstrata de {@link KeyStoreSpi}, implementando apenas operações mutantes como "não suportadas". <br>
 * A ideia por trás desta implementação, é fornecer uma classe base que implementa todas as operações, que mudariam
 * o estado do armazenamento de chaves, gerando uma "operação sem suporte". Isso permite que as subclasses desta implementação
 * foco na implementação apenas dos métodos de estilo "get".
 */
public abstract class AbstractReadOnlyKeyStore extends AbstractPemKeyStore {

    @Override
    protected Map<String, Entry> initializeEmpty() {
        return Collections.emptyMap();
    }

    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
            throws KeyStoreException {
        throw new KeyStoreException("Operação não suportada");
    }

    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain)
            throws KeyStoreException {
        throw new KeyStoreException("Operação não suportada");
    }

    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {
        throw new KeyStoreException("Operação não suportada");
    }

    @Override
    public void engineDeleteEntry(final String alias) throws KeyStoreException {
        throw new KeyStoreException("Operação não suportada");
    }

    @Override
    public void engineStore(final OutputStream stream, final char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {

        throw new IOException("Operação não suportada");
    }

}
