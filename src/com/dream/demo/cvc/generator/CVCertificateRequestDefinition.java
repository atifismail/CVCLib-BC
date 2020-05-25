package com.dream.demo.cvc.generator;

import java.io.IOException;
import java.security.PublicKey;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;

public class CVCertificateRequestDefinition {

	private CertificationAuthorityReference certificationIssuingAuthorityReference;
	private CertificationAuthorityReference certificationRequesterAuthorityReference;
	private CertificateHolderReference certificateHolderReference;	
	private CertificateHolderAuthorization certificateHolderAuthorization;
	private PublicKey publicKey;
	
	public CVCertificateRequestDefinition() {

	}

	public void setCertificationAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificationIssuingAuthorityReference = new CertificationAuthorityReference(countryCode, holderMnemonic,
				sequenceNumber);
	}

	public CertificationAuthorityReference getCertificationAuthorityReference() {
		return this.certificationIssuingAuthorityReference;
	}

	public void setPublicKey(PublicKey publicKey) {
		this.publicKey = publicKey;
	}

	public PublicKey getPublicKey() {
		return this.publicKey;
	}

	public void setCertificateHolderReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificateHolderReference = new CertificateHolderReference(countryCode, holderMnemonic, sequenceNumber);
	}
	
	public CertificateHolderReference getCertificateHolderReference() {
		return this.certificateHolderReference;
	}
	
	public void setCertificationRequesterAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificationRequesterAuthorityReference = new CertificationAuthorityReference(countryCode, holderMnemonic,
				sequenceNumber);
	}
	
	public CertificationAuthorityReference getCertificationRequesterAuthorityReference() {
		return certificationRequesterAuthorityReference;
	}

	public void setCertificateHolderAuthorization(ASN1ObjectIdentifier EACTags, int roleAndRights) throws IOException {
		this.certificateHolderAuthorization = new CertificateHolderAuthorization(EACTags, roleAndRights);
	}
	
	public CertificateHolderAuthorization getCertificateHolderAuthorization() {
		return this.certificateHolderAuthorization;
	}
}
