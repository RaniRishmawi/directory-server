package org.apache.directory.server.ldap.handlers.sasl.external;

import java.security.cert.Certificate;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.security.sasl.SaslException;

import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.util.Strings;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.OperationEnum;
import org.apache.directory.server.core.api.OperationManager;
import org.apache.directory.server.core.api.interceptor.context.BindOperationContext;
import org.apache.directory.server.i18n.I18n;
import org.apache.directory.server.ldap.LdapSession;
import org.apache.directory.server.ldap.handlers.sasl.AbstractSaslServer;
import org.apache.mina.core.session.IoSession;
import org.apache.mina.filter.ssl.SslFilter;

public class ExternalSaslServer extends AbstractSaslServer {

	private static final int SUBALTNAME_RFC822NAME = 1;

	public ExternalSaslServer(LdapSession ldapSession, CoreSession adminSession, BindRequest bindRequest) {
		super(ldapSession, adminSession, bindRequest);
		_complete = false;
	}

	public static final String MECHANISM = "EXTERNAL";
	private boolean _complete = false;

	@Override
	public String getMechanismName() {
		return MECHANISM;
	}

	@Override
	public byte[] evaluateResponse(byte[] response) throws SaslException {

		CoreSession userSession;
		try {
			userSession = authenticate();

		} catch (LdapException e) {
			throw new SaslException(I18n.err(I18n.ERR_676, ""));
		}

		getLdapSession().setCoreSession(userSession);

		_complete = true;
		return Strings.EMPTY_BYTES;
	}

	private CoreSession authenticate() throws LdapException {

		LdapSession ldapSession = getLdapSession();
		CoreSession adminSession = getAdminSession();
		DirectoryService directoryService = adminSession.getDirectoryService();
		OperationManager operationManager = directoryService.getOperationManager();

		Certificate[] certificates = getClientCertificates(ldapSession.getIoSession());

		if (certificates == null)
			throw new LdapException(I18n.err(I18n.ERR_676, "No certificate is provided"));

		BindOperationContext bindContext = new BindOperationContext(ldapSession.getCoreSession());

		bindContext.setDn(new Dn("uid=admin", "ou=system"));
		bindContext.setCredentials(Strings.getBytesUtf8("secret"));
		bindContext.setIoSession(ldapSession.getIoSession());
		bindContext.setInterceptors(directoryService.getInterceptors(OperationEnum.BIND));

		operationManager.bind(bindContext);

		CoreSession userSession = bindContext.getSession();

		LdapPrincipal ldapPrincipal = userSession.getAuthenticatedPrincipal();

		if (certificates != null && certificates.length > 0) {

			try {
				ldapPrincipal.setCertificateEmail(ExtractEmailFromCertificate((X509Certificate) certificates[0]));
			} catch (InvalidNameException e) {
				// OK
			} catch (CertificateParsingException e) {
				// OK
			}
		}

		return userSession;
	}

	private String ExtractEmailFromCertificate(X509Certificate certificate)
			throws InvalidNameException, CertificateParsingException {

		String dn = certificate.getSubjectDN().getName();
		LdapName ln = new LdapName(dn);

		for (Rdn rdn : ln.getRdns()) {
			if (rdn.getType().equalsIgnoreCase("E") || rdn.getType().equalsIgnoreCase("Email")
					|| rdn.getType().equalsIgnoreCase("EMAILADDRESS") || rdn.getType().equalsIgnoreCase("RFC822Name")) {
				return "" + rdn.getValue();
			}
		}

		Collection<List<?>> sans = certificate.getSubjectAlternativeNames();

		if (sans == null)
			return null;

		Iterator<List<?>> sansIterator = sans.iterator();

		while (sansIterator.hasNext()) {
			List<?> next = (List<?>) sansIterator.next();
			int OID = ((Integer) next.get(0)).intValue();

			switch (OID) {
			case SUBALTNAME_RFC822NAME:
				return (String) next.get(1);
			}
		}

		return null;
	}

	private Certificate[] getClientCertificates(IoSession session) {
		if (session.getFilterChain().contains("sslFilter")) {
			SslFilter sslFilter = (SslFilter) session.getFilterChain().get("sslFilter");

			SSLSession sslSession = sslFilter.getSslSession(session);

			if (sslSession != null) {
				try {
					return sslSession.getPeerCertificates();
				} catch (SSLPeerUnverifiedException e) {
					// ignore, certificate will not be available to the session
				}
			}
		}
		return null;
	}

	@Override
	public boolean isComplete() {
		return _complete;
	}

}
