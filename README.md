# Anteros PKCS #1 PEM KeyStore for Java 


## Adicionando a dependência

Inclua o projeto em seu aplicativo (por exemplo, com Maven):

~~~xml
<dependency>
  <groupId>br.com.anteros</groupId>
  <artifactId>Anteros-PEM-KeyStore</artifactId>
  <version>1.0.0</version> <!-- verifique a versão mais recente -->
</dependency>
~~~

## O provedor de segurança

O projeto atua como um provedor de segurança Java. Fornecendo apenas uma implementação
KeyStore. No entanto, você precisa informar o Java sobre o provedor de segurança.
Existem várias maneiras de fazer isso::

### Via invocação direta

Você pode especificar manualmente o provedor de segurança:

~~~java
KeyStore keyStore = KeyStore.getInstance("PEM", new AnterosPemKeyStoreProvider() );
~~~

Dessa forma, o provedor de segurança será usado apenas para esta única chamada.

### Via registro manual

Você pode registrar manualmente o provedor de segurança no início de seu aplicativo:

~~~java
Security.addProvider(new AnterosPemKeyStoreProvider());
KeyStore keyStore = KeyStore.getInstance("PEM");
~~~

Isso tornará o provedor disponível para todo o aplicativo. Como esse provedor atualmente 
é o único que oferece suporte PEM no momento, o pedido não é importante. Mas você sempre 
pode usar em seu lugar `Security.insertProviderAt`:

~~~java
Security.insertProviderAt(new PemKeyStoreProvider(), 10);
~~~

### Via configuração

Também é possível configurar o provedor no arquivo `<JRE>/conf/security/java.security`.
Consulte também: https://docs.oracle.com/javase/10/security/howtoimplaprovider.htm#GUID-831AA25F-F702-442D-A2E4-8DA6DEA16F33

## Usando isso

O uso básico do PEM KeyStore é:

~~~java
KeyStore keyStore = KeyStore.getInstance("PEM");
try ( InputStream in = … ) {
  keyStore.load ( in, null );
}

// Use X509Certificates from the KeyStore
~~~

Mas a realidade é mais complexa, é claro ;-)

### Lendo chave / certificado de dois arquivos

Às vezes, como ao usar o OpenShift, a chave e o certificado vêm em dois arquivos diferentes. 
No entanto, toda a construção "KeyStore" é construída em torno da ideia de que existe 
apenas um arquivo / recurso, que armazena as informações.

Para este caso, ou também para Let's Encrypt, você pode usar o PEMCFG tipo KeyStore. 
É uma variação da PEM store e inicialmente carrega uma propriedade Java, que então 
aponta para os diferentes arquivos a serem carregados.

Um arquivo de propriedades se parece com:

~~~
alias=alias-name
source.key=/etc/tls/tls.key
source.cert=/etc/tls/tls.crt
~~~

A propriedade alias define sob qual alias a chave / certificado será fornecido. 
Cada chave de propriedade começando com source. será usada um caminho do sistema de 
arquivos para carregar uma fonte adicional. Os certificados serão encadeados e 
apresentados junto com a chave.

O restante da chave, a parte após o `source`., será ignorado.

### Lendo um pacote CA

Os keystores Java podem armazenar uma ou mais cadeias de certificados. Java usa apenas 
a ponta da cadeia como um certificado confiável. Portanto, quando você tem um arquivo 
PEM PKCS # 1, não está claro se é uma cadeia de certificados ou um conjunto de 
certificados raiz para confiar.

Por padrão, os certificados são encadeados quando lidos. No entanto, o PEMCA Keystore 
armazenará certificados individualmente:

~~~java
KeyStore keyStore = KeyStore.getInstance("PEMCA");
try ( InputStream in = … ) {
  keyStore.load ( in, null );
}

// Use X509Certificates from the KeyStore
~~~

Neste caso, o alias será usado como prefixo, e as entradas serão nomeadas **<alias>-#**, 
onde #é um índice crescente, começando com 0(zero).
 
