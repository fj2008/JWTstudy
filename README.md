# Spring security 기반에 JWT토큰서버 구축해보기 공부

```
이 레파지토리에대해서 공부하고 정리한 내용은 제 블로그에 놀러오시면 정리 돼 있습니다 ㅎㅎ
```
- 📕 [저의 블로그 주소 입니다.](https://25gstory.tistory.com/)


## RSA 키 발급

```
openssl genrsa -out private_key.pem 2048
```
┖ 우선 BEGIN RSA PRIVATE KEY 로 시작하는 키를 생성합니다.

```
openssl pkcs8 -topk8 -inform PEM -in private_key.pem -out rsa_private_key.pem -nocrypt
```

#### 공개키 추출

```
openssl rsa -in private_key.pem -pubout -out public_key.pem 
```

### 자바코드로 메모리에 키쌍 생성

```
KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
generator.initialize(2048);
KeyPair pair = generator.generateKeyPair();
```
다음키로 공개키와 개인키 추출
```
PrivateKey privateKey = pair.getPrivate();
PublicKey publicKey = pair.getPublic();
```

#### 파일에 키 저장
키를 파일로 관리하고 싶을때
파일에 키를 저장하려면 기본 인코딩 형식으로 키 콘텐츠를 반환하는 getEncoded 메서드를 사용할 수 있습니다.
```
try (FileOutputStream fos = new FileOutputStream("public.key")) {
    fos.write(publicKey.getEncoded());
}
```
파일에서 키를 읽으려면 먼저 내용을 바이트 배열로 로드해야합니다
```
File publicKeyFile = new File("public.key");
byte[] publicKeyBytes = Files.readAllBytes(publicKeyFile.toPath());
```
그런 다음 KeyFactory 를 사용하여 실제 인스턴스를 다시 만듭니다.
```
KeyFactory keyFactory = KeyFactory.getInstance("RSA");
EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(publicKeyBytes);
keyFactory.generatePublic(publicKeySpec);
```