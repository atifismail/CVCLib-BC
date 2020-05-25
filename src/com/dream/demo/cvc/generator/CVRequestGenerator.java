package com.dream.demo.cvc.generator;

import java.io.IOException;
import java.io.OutputStream;
import java.security.PrivateKey;
import java.sql.Savepoint;
import java.util.Date;

import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERApplicationSpecific;
import org.bouncycastle.asn1.eac.CVCertificateRequest;
import org.bouncycastle.asn1.eac.CertificateBody;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.EACObjectIdentifiers;
import org.bouncycastle.asn1.eac.EACTags;
import org.bouncycastle.asn1.eac.PackedDate;
import org.bouncycastle.asn1.eac.PublicKeyDataObject;
import org.bouncycastle.eac.EACCertificateBuilder;
import org.bouncycastle.eac.EACCertificateHolder;
import org.bouncycastle.eac.EACCertificateRequestHolder;
import org.bouncycastle.eac.EACException;
import org.bouncycastle.eac.jcajce.JcaPublicKeyConverter;
import org.bouncycastle.eac.operator.EACSigner;
import org.bouncycastle.eac.operator.jcajce.JcaEACSignerBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;

import com.dream.demo.cvc.core.CVCertificate;
import com.dream.demo.cvc.exception.CVAuthorityRefNotValidException;
import com.dream.demo.cvc.exception.CVInvalidKeySourceException;
import com.dream.demo.cvc.exception.CVInvalidOidException;
import com.dream.demo.cvc.exception.CVKeyTypeNotSupportedException;
import com.dream.demo.cvc.exception.CVMissingKeyException;
import com.dream.demo.cvc.exception.CVSignOpKeyMismatchException;
import com.dream.demo.cvc.util.FileUtils;

public class CVRequestGenerator {
	
	private CVCertificateRequestDefinition definition;	
	
	public CVRequestGenerator(CVCertificateRequestDefinition def) {
		this.definition = def;
	}
	
	public void setCVCertificateRequestDefinition(CVCertificateRequestDefinition def) {
		this.definition = def;		
	}
	
	public CVCertificateRequestDefinition getCVCertificateRequestDefinition() {
		return this.definition;
	}	
	
	public CVCertificateRequest issueCVCertRequest(PrivateKey signingPrivateKey, String SigningAlgo, 
			PrivateKey authPrivateKey, String authSigningAlgo, CertificationAuthorityReference authRef) 
			throws CVAuthorityRefNotValidException, CVInvalidKeySourceException, 
		CVSignOpKeyMismatchException, CVInvalidOidException, CVMissingKeyException, 
		CVKeyTypeNotSupportedException, IOException, OperatorCreationException, EACException {
				
		JcaEACSignerBuilder signerBuilder = new JcaEACSignerBuilder().setProvider(new BouncyCastleProvider());

        EACSigner signer = signerBuilder.build(SigningAlgo, signingPrivateKey);

        // convert public key
        PublicKeyDataObject pubKeyDO = new JcaPublicKeyConverter().
        		getPublicKeyDataObject(signer.getUsageIdentifier(), this.definition.getPublicKey());
                      
        /*EACCertificateBuilder certificateBuilder = 
        		new EACCertificateBuilder(definition.getCertificationAuthorityReference(), 
        		pubKeyDO, definition.getCertificateHolderReference(),  
        		definition.getCertificateHolderAuthorization(), new PackedDate(new Date()), new PackedDate(new Date()));
        
        EACCertificateHolder ch = certificateBuilder.build(signer);*/        
        
        CertificateBody b = new CertificateBody(new DERApplicationSpecific(EACTags.INTERCHANGE_PROFILE, new byte [] {0}),
        		definition.getCertificationAuthorityReference(), pubKeyDO, definition.getCertificateHolderReference()
        		, definition.getCertificateHolderAuthorization(), new PackedDate(new Date()), new PackedDate(new Date()));
               
        OutputStream vOut = signer.getOutputStream();

        vOut.write(b.getEncoded(ASN1Encoding.DER));

        vOut.close();
                
        org.bouncycastle.asn1.eac.CVCertificate c = new org.bouncycastle.asn1.eac.CVCertificate(b,signer.getSignature());
                
        DERApplicationSpecific obj = new DERApplicationSpecific(true, EACTags.AUTHENTIFICATION_DATA, c);
        
        return CVCertificateRequest.getInstance(obj);                 
	}	
}
