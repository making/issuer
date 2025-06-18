package am.ik.pemtojwks;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
@ConfigurationPropertiesScan
public class PemToJwksApplication {

	public static void main(String[] args) {
		SpringApplication.run(PemToJwksApplication.class, args);
	}

	@Bean
	InitializingBean keyPairVerifier(JwtProps jwtProps) {
		return () -> {
			var signer = new RSASSASigner(jwtProps.privateKey());
			var verifier = new RSASSAVerifier(jwtProps.publicKey());
			var claimsSet = new JWTClaimsSet.Builder().subject("test").build();
			var header = new JWSHeader.Builder(JWSAlgorithm.RS256)
				.keyID(JwksGenerator.keyIDFromPublicKey(jwtProps.publicKey()))
				.type(JOSEObjectType.JWT)
				.build();
			var signedJWT = new SignedJWT(header, claimsSet);
			try {
				signedJWT.sign(signer);
				signedJWT.verify(verifier);
			}
			catch (JOSEException e) {
				throw new IllegalStateException(e);
			}
		};
	}

}
