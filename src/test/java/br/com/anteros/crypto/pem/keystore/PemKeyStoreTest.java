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

import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Security;

import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

public class PemKeyStoreTest {

    @BeforeAll
    public static void setup() {
    }

    protected void testWithProvider(final ThrowingCallable callable) throws Throwable {

        // before running the test, there should be no "PEM" provider yet

        assertThatThrownBy(() -> KeyStore.getInstance("PEM")).isInstanceOf(KeyStoreException.class);

        Security.addProvider(new AnterosPemKeyStoreProvider());

        try {
            callable.call();
        } finally {
            Security.removeProvider("PEM");
        }

        // after running the test, there should again be no "PEM" provider any more

        assertThatThrownBy(() -> KeyStore.getInstance("PEM")).isInstanceOf(KeyStoreException.class);
    }

    @Test
    public void testGetInstance1() throws Throwable {

        testWithProvider(() -> {
            KeyStore.getInstance("PEM");
        });

    }

    @Test
    public void testGetInstance2() throws Throwable {

        testWithProvider(() -> {
            KeyStore.getInstance("PEM", "PEM");
        });

    }

    @Test
    public void testGetInstance3() throws Throwable {

        testWithProvider(() -> {
            KeyStore.getInstance("PEM", new AnterosPemKeyStoreProvider());
        });

    }

}
