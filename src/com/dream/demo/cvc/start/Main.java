package com.dream.demo.cvc.start;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.Security;
import java.util.Date;
import java.util.Scanner;

import org.apache.commons.lang3.time.DateUtils;
import org.bouncycastle.asn1.eac.CVCertificate;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.dream.demo.cvc.core.Util;
import com.dream.demo.cvc.exception.CVAuthorityRefNotValidException;
import com.dream.demo.cvc.exception.CVCertificateHolderReferenceTooLong;
import com.dream.demo.cvc.exception.CVInvalidKeySourceException;
import com.dream.demo.cvc.exception.CVInvalidOidException;
import com.dream.demo.cvc.exception.CVKeyTypeNotSupportedException;
import com.dream.demo.cvc.exception.CVMissingKeyException;
import com.dream.demo.cvc.exception.CVSignOpKeyMismatchException;
import com.dream.demo.cvc.generator.CVCertGenerator;
import com.dream.demo.cvc.generator.CVCertificatePolicy;
import com.dream.demo.cvc.generator.CVCertificateRequestDefinition;
import com.dream.demo.cvc.generator.CVRequestGenerator;
import com.dream.demo.cvc.util.Constants;
import com.dream.demo.cvc.util.FileUtils;
import com.dream.demo.cvc.util.KeyGenerator;

public class Main {

	// max length 16
	private static final String CA_COUNTRY_CODE = "KR";
	private static final String CA_HOLDER_MNEMONIC = "CVCA-TEST";
	private static final String CA_SEQUENCE_NO = "00001";

	private static final String OTHER_CA_COUNTRY_CODE = "US";
	private static final String OTHER_CA_HOLDER_MNEMONIC = "CVCA-OTHR";
	private static final String OTHER_CA_SEQUENCE_NO = "00001";

	private static final String DV_COUNTRY_CODE = "KR";
	private static final String DV_HOLDER_MNEMONIC = "DVCA-TEST";
	private static final String DV_SEQUENCE_NO = "00001";
	
	private static final String IS_COUNTRY_CODE = "KR";
	private static final String IS_HOLDER_MNEMONIC = "KRIS-TEST";
	private static final String IS_SEQUENCE_NO = "KR001";

	public static void main(String[] args) {

		Security.addProvider(new BouncyCastleProvider());

		try {		
			
			// issue CSCA
			//issueCSCA();

			// DV req
			//issueDVCert();
			
			// IS
			//issueISCert();

			// link
			//issueCSCALink();
						
			// DV req
			issueDVRequest(); //TODO not working

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static void issueDVCert() throws Exception {

		KeyPair kp = KeyGenerator.generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy cvcaDef = new CVCertificatePolicy();
		cvcaDef.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderReference(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC,DV_SEQUENCE_NO);
		cvcaDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.DV_DOMESTIC | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		cvcaDef.setPublicKey(kp.getPublic());
		cvcaDef.setValidFrom(new Date());
		cvcaDef.setValidTo(DateUtils.addMonths(new Date(), 3));

		CVCertGenerator certGenerator = new CVCertGenerator(cvcaDef);
		CVCertificate cert = certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());
		
		
		saveFile("CVCAFiles/DVCert.ber", cert.getEncoded());
		
		System.out.println(new String(cert.getBody().toString()));

		Util.printCVCertificate(new File("CVCAFiles/DVCert.der"));
	}
	
	private static void issueISCert() throws Exception {

		KeyPair kp = KeyGenerator.generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy cvcaDef = new CVCertificatePolicy();
		cvcaDef.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderReference(IS_COUNTRY_CODE, IS_HOLDER_MNEMONIC,IS_SEQUENCE_NO);
		cvcaDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.IS | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		cvcaDef.setPublicKey(kp.getPublic());
		cvcaDef.setValidFrom(new Date());
		cvcaDef.setValidTo(DateUtils.addMonths(new Date(), 3));

		CVCertGenerator certGenerator = new CVCertGenerator(cvcaDef);
		CVCertificate cert = certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());

		saveFile("CVCAFiles/ISCert.ber", cert.getEncoded());	
		
		System.out.println(new String(cert.getBody().toString()));

		Util.printCVCertificate(new File("CVCAFiles/ISCert.der"));
	}

	private static void issueDVRequest() throws Exception {

		KeyPair kp = KeyGenerator.generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificateRequestDefinition def = new CVCertificateRequestDefinition();
		def.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		def.setCertificateHolderReference(DV_COUNTRY_CODE, DV_HOLDER_MNEMONIC, DV_SEQUENCE_NO);
		def.setPublicKey(kp.getPublic());
		def.setCertificationRequesterAuthorityReference(OTHER_CA_COUNTRY_CODE, OTHER_CA_HOLDER_MNEMONIC,
				OTHER_CA_SEQUENCE_NO);
		def.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport, CertificateHolderAuthorization.DV_DOMESTIC
				| CertificateHolderAuthorization.RADG3 | CertificateHolderAuthorization.RADG4);

		CVRequestGenerator gen = new CVRequestGenerator(def);
		
		CVCertificateRequest req = gen.issueCVCertRequest(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo(), null, null, null);
		
		saveFile("CVCAFiles/DVCertReq.ber", req.getEncoded());				
	}

	private static void issueCSCA() throws Exception {

		//Scanner cmd = new Scanner(System.in);		
		
		KeyPair kp = KeyGenerator.generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy cvcaDef = new CVCertificatePolicy();
		cvcaDef.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.CVCA | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		cvcaDef.setPublicKey(kp.getPublic());
		cvcaDef.setValidFrom(new Date());
		cvcaDef.setValidTo(DateUtils.addYears(new Date(), 1));

		CVCertGenerator certGenerator = new CVCertGenerator(cvcaDef);
		CVCertificate cert = certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());

		saveFile("CVCAFiles/CVCACert.ber", cert.getEncoded());
		

		System.out.println(new String(cert.getBody().toString()));

		Util.printCVCertificate(new File("CVCAFiles/CVCACert.der"));
	}
	
	private static void issueCSCALink() throws Exception {

		KeyPair kp = KeyGenerator.generateECPair(Constants.ECCurves.secp256r1.getValue());
		KeyPair newkp = KeyGenerator.generateECPair(Constants.ECCurves.secp256r1.getValue());

		CVCertificatePolicy cvcaDef = new CVCertificatePolicy();
		cvcaDef.setCertificationAuthorityReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderReference(CA_COUNTRY_CODE, CA_HOLDER_MNEMONIC, CA_SEQUENCE_NO);
		cvcaDef.setCertificateHolderAuthorization(EACObjectIdentifiers.id_EAC_ePassport,
				CertificateHolderAuthorization.CVCA | CertificateHolderAuthorization.RADG3
						| CertificateHolderAuthorization.RADG4);
		cvcaDef.setPublicKey(newkp.getPublic());
		cvcaDef.setValidFrom(new Date());
		cvcaDef.setValidTo(DateUtils.addYears(new Date(), 1));

		CVCertGenerator certGenerator = new CVCertGenerator(cvcaDef);
		CVCertificate cert = certGenerator.issueCVCert(kp.getPrivate(), Constants.SigningAlgo.SHA1WITHECDSA.getAlgo());
		
		saveFile("CVCAFiles/LinkCVCACert.ber", cert.getEncoded());
		
		System.out.println(new String(cert.getBody().toString()));
		
		Util.printCVCertificate(new File("CVCAFiles/LinkCVCACert.der"));
	}
	
	public static void saveFile(String name, byte[] data) throws IOException {
		OutputStream os = new FileOutputStream(name);
		os.write(data);
		os.flush();
		os.close();
	}
}
