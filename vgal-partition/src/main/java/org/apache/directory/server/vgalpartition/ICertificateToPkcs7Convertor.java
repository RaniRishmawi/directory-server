package org.apache.directory.server.vgalpartition;

import java.io.IOException;
import java.security.cert.CertificateException;

import org.bouncycastle.cms.CMSException;


public interface ICertificateToPkcs7Convertor {

	public byte[] convert(byte[] x509CertificateAsBytes) throws CertificateException, IOException, CMSException  ;
}
