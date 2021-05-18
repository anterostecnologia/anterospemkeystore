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
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Classe que implementa alguns métodos de mutação no armazenamento de chaves. <br>
 * É abstrato permitir que as subclasses escolham como carregar suas chaves e certificados.
 * <p>
 * Esta é uma implementação mutável, mas não peristável, de um armazenamento de chaves. Destina-se a casos de uso em que um
 * o aplicativo espera que o keystore seja mutável e, portanto, tentamos dar o nosso melhor para atender a essa expectativa. Contudo
 * não implementamos os métodos de "armazenamento".
 * </p>
 */
public abstract class AbstractMutablePemKeyStore extends AbstractPemKeyStore {

    @Override
    protected Map<String, Entry> initializeEmpty() {
        return new HashMap<>();
    }

    @Override
    public void engineSetKeyEntry(final String alias, final Key key, final char[] password, final Certificate[] chain)
            throws KeyStoreException {

        Objects.requireNonNull(alias);
        Objects.requireNonNull(key);

        final Entry entry = new Entry(key, chain.clone());
        this.entries.put(alias, entry);

    }

    @Override
    public void engineSetKeyEntry(final String alias, final byte[] key, final Certificate[] chain)
            throws KeyStoreException {

        // Na verdade, devemos implementar esta operação, mas atualmente não

        throw new KeyStoreException("Operação não suportada");

    }

    @Override
    public void engineSetCertificateEntry(final String alias, final Certificate cert) throws KeyStoreException {

        Objects.requireNonNull(alias);
        Objects.requireNonNull(cert);

        final Entry entry = new Entry(null, new Certificate[] { cert });
        this.entries.put(alias, entry);

    }

    @Override
    public void engineDeleteEntry(final String alias) throws KeyStoreException {

        this.entries.remove(alias);

    }

    @Override
    public void engineStore(final OutputStream stream, final char[] password)
            throws IOException, NoSuchAlgorithmException, CertificateException {
        throw new IOException("Operação não suportada");
    }

}
