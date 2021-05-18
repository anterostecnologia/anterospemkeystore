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

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Provider;

public class AnterosPemKeyStoreProvider extends Provider {

    private static final long serialVersionUID = 1L;

    public AnterosPemKeyStoreProvider() {
        super("PEM", 1, "Fornece KeyStores baseados em PEM");
        setup();
    }

    private void setup() {
        AccessController.doPrivileged(new PrivilegedAction<Void>() {

            @Override
            public Void run() {
                performSetup();
                return null;
            }
        });
    }

    private void performSetup() {
        put("KeyStore.PEM", "br.com.anteros.crypto.pem.keystore.PemKeyStore$Immutable");
        put("KeyStore.PEM.MOD", "br.com.anteros.crypto.pem.keystore.PemKeyStore$Mutable");

        put("KeyStore.PEMCFG", "br.com.anteros.crypto.pem.keystore.PemConfigKeyStore$Immutable");
        put("KeyStore.PEMCFG.MOD", "br.com.anteros.crypto.pem.keystore.PemConfigKeyStore$Mutable");

        put("KeyStore.PEMCA", "br.com.anteros.crypto.pem.keystore.PemBundleKeyStore$Immutable");
        put("KeyStore.PEMCA.MOD", "br.com.anteros.crypto.pem.keystore.PemBundleKeyStore$Mutable");

    }
}
