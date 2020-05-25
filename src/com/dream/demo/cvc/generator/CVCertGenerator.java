package com.dream.demo.cvc.generator;

import java.io.IOException;
import java.io.InvalidObjectException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.EACCertificateHolder;
import org.bouncycastle.eac.EACCertificateRequestHolder;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import org.bouncycastle.eac.operator.EACSignatureVerifier;
import org.bouncycastle.eac.operator.EACSigner;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignatureVerifierBuilder;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.dream.demo.cvc.exception.CVAuthorityRefNotValidException;
import com.dream.demo.cvc.exception.CVInvalidKeySourceException;
import com.dream.demo.cvc.exception.CVInvalidOidException;
import com.dream.demo.cvc.exception.CVKeyTypeNotSupportedException;
import com.dream.demo.cvc.exception.CVMissingKeyException;
import com.dream.demo.cvc.exception.CVSignOpKeyMismatchException;
import com.dream.demo.cvc.util.CommonUtil;

public class CVCertGenerator {

	private CVCertificatePolicy certificateDefinition;

	public CVCertGenerator(CVCertificatePolicy def) {
		this.certificateDefinition = def;
	}

	public CVCertificatePolicy getCVCertificateDefinition() {
		return this.certificateDefinition;
	}

	public CVCertificate issueCVCert(PrivateKey privateKey, String SigningAlgo) 
			throws CVAuthorityRefNotValidException,
			CVInvalidKeySourceException, CVSignOpKeyMismatchException, 
			CVInvalidOidException, CVMissingKeyException,
			CVKeyTypeNotSupportedException, OperatorCreationException, EACException {

		JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(new BouncyCastleProvider());

		EACSigner signer = signerBuilder.build(SigningAlgo, privateKey);

		// convert public key
		PublicKeyDataObject pubKeyDO = new JcaPublicKeyConverter().getPublicKeyDataObject(signer.getUsageIdentifier(),
				certificateDefinition.getPublicKey());

		EACCertificateBuilder certificateBuilder = new EACCertificateBuilder(
				certificateDefinition.getCertificationAuthorityReference(), pubKeyDO,
				certificateDefinition.getCertificateHolderReference(),
				certificateDefinition.getCertificateHolderAuthorization(), certificateDefinition.getValidFrom(),
				certificateDefinition.getValidTo());

		EACCertificateHolder eacCertificateHolder = certificateBuilder.build(signer);

		return eacCertificateHolder.toASN1Structure();
	}

	public CVCertificate issueCVCertFromRequest() {

		return null;
	}

	public boolean verifyCert(String cvCertPath) throws IOException, InvalidKeySpecException, 
		EACException, OperatorCreationException {
		
		EACCertificateHolder certHolder = new EACCertificateHolder(CommonUtil.readFromFile(cvCertPath));

		PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).
				getKey(certHolder.getPublicKeyDataObject());
		
		EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder()
				.build(certHolder.getPublicKeyDataObject().getUsage(), pubKey);

		return certHolder.isSignatureValid(verifier);
	}
	
	public EACCertificateRequestHolder loadRequestFile(String filename) throws IOException, 
		InvalidKeySpecException, EACException, OperatorCreationException {
        
        byte[] input = CommonUtil.readFromFile(filename);
   
        EACCertificateRequestHolder requestHolder = new EACCertificateRequestHolder(input);

        PublicKey pubKey = new JcaPublicKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME).
        		getKey(requestHolder.getPublicKeyDataObject());
        
        EACSignatureVerifier verifier = new JcaEACSignatureVerifierBuilder().build(requestHolder.
        		getPublicKeyDataObject().getUsage(), pubKey);

        if(requestHolder.isInnerSignatureValid(verifier)) {
        	throw new InvalidObjectException("Signature verification failed");
        }
       
        return requestHolder;
    }

}
