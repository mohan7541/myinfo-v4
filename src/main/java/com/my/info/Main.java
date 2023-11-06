package com.my.info;

import java.io.FileReader;
import java.security.KeyPair;
import java.security.interfaces.ECPrivateKey;

import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;

public class Main {
	public static void main(String[] args) throws Exception {

		try (FileReader reader = new FileReader(
				"/Users/mohanraja/dev-samples/STS-WS/MyInfoRestDemo/src/main/resources/cert/your-sample-app-signing-private-key.pem");
				PEMParser pemParser = new PEMParser(reader)) {

				Object object = pemParser.readObject();
	
				if (object instanceof PEMKeyPair) {
					PEMKeyPair pemKeyPair = (PEMKeyPair) object;
					KeyPair keyPair = new JcaPEMKeyConverter().getKeyPair(pemKeyPair);
					ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
	
					// Use the EC private key as needed
					System.out.println(privateKey);
				} else {
					throw new IllegalArgumentException("Invalid PEM file: Not an EC private key");
				}
		}

	}
}
