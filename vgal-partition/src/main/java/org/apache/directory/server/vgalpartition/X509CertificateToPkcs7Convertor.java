package org.apache.directory.server.vgalpartition;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.util.Store;


public class X509CertificateToPkcs7Convertor implements ICertificateToPkcs7Convertor {

	@Override
	public byte[] convert(byte[] x509CertificateAsBytes) throws CertificateException, IOException, CMSException {

		if (x509CertificateAsBytes == null)
			throw new IllegalArgumentException("x509CertificateAsBytes");

		CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

		InputStream in = null;
		try {
			in = new ByteArrayInputStream(x509CertificateAsBytes);

			X509Certificate cert = (X509Certificate) certFactory.generateCertificate(in);

			List<X509CertificateHolder> certList = new ArrayList<X509CertificateHolder>();

			certList.add(new X509CertificateHolder(cert.getEncoded()));

			Store<?> certStore = new JcaCertStore(certList);

			CMSTypedData msg = new CMSProcessableByteArray("Hello World".getBytes());

			CMSSignedDataGenerator gen = new CMSSignedDataGenerator();

			gen.addCertificates(certStore);

			CMSSignedData data = gen.generate(msg, true);

			return data.getEncoded();
		} finally {
			try {
				if (in != null) {
					in.close();
				}
			} catch (IOException ioe) {
				// ignore
			}
		}
	}
}
