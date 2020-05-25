package com.dream.demo.cvc.generator;

import java.io.IOException;
import java.security.PublicKey;
import java.util.Date;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.eac.CertificateHolderAuthorization;
import org.bouncycastle.asn1.eac.CertificateHolderReference;
import org.bouncycastle.asn1.eac.CertificationAuthorityReference;
import org.bouncycastle.asn1.eac.PackedDate;

public class CVCertificatePolicy {

	private CertificationAuthorityReference certificationAuthorityReference;
	private CertificateHolderReference certificateHolderReference;
	private CertificateHolderAuthorization certificateHolderAuthorization;
	private PublicKey publicKey;
	private PackedDate certificateEffectiveDate;
	private PackedDate certificateExpirationDate;

	public CVCertificatePolicy() {

	}

	public void setCertificationAuthorityReference(String countryCode, String holderMnemonic, String sequenceNumber) {
		this.certificationAuthorityReference = new CertificationAuthorityReference(countryCode, holderMnemonic,
				sequenceNumber);
	}

	public CertificationAuthorityReference getCertificationAuthorityReference() {
		return this.certificationAuthorityReference;
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

	public void setCertificateHolderAuthorization(ASN1ObjectIdentifier EACTags, int roleAndRights) throws IOException {
		this.certificateHolderAuthorization = new CertificateHolderAuthorization(EACTags, roleAndRights);
	}
	
	public CertificateHolderAuthorization getCertificateHolderAuthorization() {
		return this.certificateHolderAuthorization;
	}

	public void setValidFrom(Date effectiveDate) {
		this.certificateEffectiveDate = new PackedDate(effectiveDate);
	}
	
	public PackedDate getValidFrom() {
		return this.certificateEffectiveDate;
	}

	public void setValidTo(Date expirationDate) {
		this.certificateExpirationDate = new PackedDate(expirationDate);
	}
	
	public PackedDate getValidTo() {
		return this.certificateExpirationDate;
	}

}
