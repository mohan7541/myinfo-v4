package com.my.info;

import java.io.FileReader;
import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import jakarta.servlet.http.HttpSession;

@SpringBootApplication
@RestController
public class MyInfoRestDemoApplication {

	static MyInfoConnector connector = null;
	private final Set<String> sessionIds = new HashSet<>();

	public static void main(String[] args) throws MyInfoException {
		SpringApplication.run(MyInfoRestDemoApplication.class, args);
		connector = MyInfoConnector.getInstance("/Users/mohanraja/dev-samples/STS-WS/MyInfoRestDemo/src/main/resources/application.properties");
	}
	
	@GetMapping("/callback")
	public String callback(@RequestParam("code") String authCode, HttpSession session) throws MyInfoException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		System.out.println("authCode::"+authCode);
		System.out.println("verifier::"+session.getAttribute("verifier"));
		System.out.println("codeChallenge::"+session.getAttribute("codeChallenge"));
		String result = getPersonData(authCode, (String)session.getAttribute("verifier"));
		return result;
	}
	
	@PostMapping("/generateCodeChallenge")
	public Map<String, String> generateCodeChallenge(HttpSession session) throws MyInfoException {
		Map<String, String> result = new HashMap<>();
		String verifier = MyInfoSecurityHelper.createCodeVerifier();
		String codeChallenge = MyInfoSecurityHelper.createCodeChallenge(verifier);
		System.out.println("verifier::"+verifier);
		System.out.println("codeChallenge::"+codeChallenge);
		result.put("code_challenge", codeChallenge);
		System.out.println(result);
		session.setAttribute("verifier", verifier);
		session.setAttribute("codeChallenge", codeChallenge);
		return result;
	}
	@GetMapping("/getPersonData")
	public String getPersonData(String authCode, String verifier) throws MyInfoException, NoSuchAlgorithmException, InvalidKeySpecException, IOException {
		ECPrivateKey ecPrivateSigningKey = getECPrivateKey("/Users/mohanraja/dev-samples/STS-WS/MyInfoRestDemo/src/main/resources/cert/your-sample-app-signing-private-key.pem");
		ECPrivateKey ecPrivateEncryptionKey = getECPrivateKey("/Users/mohanraja/dev-samples/STS-WS/MyInfoRestDemo/src/main/resources/cert/encryption-private-keys/your-sample-app-encryption-private-key.pem");
		System.out.println("=======::getPersonData::START");
		System.out.println("authCode::"+authCode);
		System.out.println("verifier::"+verifier);
		System.out.println("ecPrivateSigningKey::"+ecPrivateSigningKey);
		System.out.println("ecPrivateEncryptionKey::"+ecPrivateEncryptionKey);
		String personalData = connector.getMyInfoPersonData(authCode,verifier,ecPrivateSigningKey,ecPrivateEncryptionKey);
		System.out.println("personalData::"+personalData);
		System.out.println("=======::getPersonData::END");
		return personalData;
	}

	private ECPrivateKey getECPrivateKey(String filePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		ECPrivateKey privateKey = null;
		try (FileReader reader = new FileReader(filePath);
				PEMParser pemParser = new PEMParser(reader)) {

				Object object = pemParser.readObject();
	
				if (object instanceof PEMKeyPair) {
					PEMKeyPair pemKeyPair = (PEMKeyPair) object;
					KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
					privateKey = (ECPrivateKey) keyPair.getPrivate();
	
					System.out.println(privateKey);
				} else {
					throw new IllegalArgumentException("Invalid PEM file: Not an EC private key");
				}
		}

		return privateKey;
	}
	

}
