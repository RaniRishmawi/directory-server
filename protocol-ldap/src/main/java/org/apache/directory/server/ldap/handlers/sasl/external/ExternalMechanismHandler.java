package org.apache.directory.server.ldap.handlers.sasl.external;

import javax.security.sasl.SaslServer;

import org.apache.directory.api.ldap.model.message.BindRequest;
import org.apache.directory.server.core.api.CoreSession;
import org.apache.directory.server.ldap.LdapSession;
import org.apache.directory.server.ldap.handlers.sasl.AbstractMechanismHandler;
import org.apache.directory.server.ldap.handlers.sasl.SaslConstants;

public class ExternalMechanismHandler extends AbstractMechanismHandler {

	@Override
	public SaslServer handleMechanism(LdapSession session, BindRequest bindRequest) 
			throws Exception {
		
		SaslServer ss = ( SaslServer ) session.getSaslProperty( SaslConstants.SASL_SERVER );

        if ( ss == null )
        {
            CoreSession adminSession = session.getLdapServer()
            		.getDirectoryService().getAdminSession();

            ss = new ExternalSaslServer( session, adminSession, bindRequest );
            session.putSaslProperty( SaslConstants.SASL_SERVER, ss );
        }
        return ss;
	}

	@Override
	public void init(LdapSession ldapSession) {
		
	}

	@Override
	public void cleanup(LdapSession ldapSession) {
		
	}

}
