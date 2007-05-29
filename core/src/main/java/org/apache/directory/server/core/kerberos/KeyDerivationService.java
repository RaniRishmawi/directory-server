/*
 *  Licensed to the Apache Software Foundation (ASF) under one
 *  or more contributor license agreements.  See the NOTICE file
 *  distributed with this work for additional information
 *  regarding copyright ownership.  The ASF licenses this file
 *  to you under the Apache License, Version 2.0 (the
 *  "License"); you may not use this file except in compliance
 *  with the License.  You may obtain a copy of the License at
 *  
 *    http://www.apache.org/licenses/LICENSE-2.0
 *  
 *  Unless required by applicable law or agreed to in writing,
 *  software distributed under the License is distributed on an
 *  "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 *  KIND, either express or implied.  See the License for the
 *  specific language governing permissions and limitations
 *  under the License. 
 *  
 */
package org.apache.directory.server.core.kerberos;


import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;

import org.apache.directory.server.core.authn.AuthenticationService;
import org.apache.directory.server.core.authz.AuthorizationService;
import org.apache.directory.server.core.authz.DefaultAuthorizationService;
import org.apache.directory.server.core.collective.CollectiveAttributeService;
import org.apache.directory.server.core.event.EventService;
import org.apache.directory.server.core.exception.ExceptionService;
import org.apache.directory.server.core.interceptor.BaseInterceptor;
import org.apache.directory.server.core.interceptor.Interceptor;
import org.apache.directory.server.core.interceptor.NextInterceptor;
import org.apache.directory.server.core.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.interceptor.context.OperationContext;
import org.apache.directory.server.core.invocation.Invocation;
import org.apache.directory.server.core.invocation.InvocationStack;
import org.apache.directory.server.core.normalization.NormalizationService;
import org.apache.directory.server.core.operational.OperationalAttributeService;
import org.apache.directory.server.core.partition.PartitionNexusProxy;
import org.apache.directory.server.core.referral.ReferralService;
import org.apache.directory.server.core.schema.SchemaService;
import org.apache.directory.server.core.subtree.SubentryService;
import org.apache.directory.server.core.trigger.TriggerService;
import org.apache.directory.server.kerberos.shared.crypto.encryption.EncryptionType;
import org.apache.directory.server.kerberos.shared.crypto.encryption.KerberosKeyFactory;
import org.apache.directory.server.kerberos.shared.crypto.encryption.RandomKeyFactory;
import org.apache.directory.server.kerberos.shared.exceptions.KerberosException;
import org.apache.directory.server.kerberos.shared.io.encoder.EncryptionKeyEncoder;
import org.apache.directory.server.kerberos.shared.messages.value.EncryptionKey;
import org.apache.directory.server.kerberos.shared.store.KerberosAttribute;
import org.apache.directory.shared.ldap.exception.LdapAuthenticationException;
import org.apache.directory.shared.ldap.message.AttributeImpl;
import org.apache.directory.shared.ldap.message.ModificationItemImpl;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.util.AttributeUtils;
import org.apache.directory.shared.ldap.util.StringTools;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * An {@link Interceptor} that creates symmetric Kerberos keys for users.  When a
 * userPassword is added or modified, the userPassword and krb5PrincipalName are used
 * to derive Kerberos keys.  If the userPassword is the special keyword 'randomKey',
 * a random key is generated and used as the Kerberos key.
 * 
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class KeyDerivationService extends BaseInterceptor
{
    /** The log for this class. */
    private static final Logger log = LoggerFactory.getLogger( KeyDerivationService.class );

    /** The service name. */
    public static final String NAME = "keyDerivationService";

    /**
     * Define the interceptors to bypass upon user lookup.
     */
    private static final Collection USERLOOKUP_BYPASS;
    static
    {
        Set<String> c = new HashSet<String>();
        c.add( NormalizationService.NAME );
        c.add( AuthenticationService.NAME );
        c.add( ReferralService.NAME );
        c.add( AuthorizationService.NAME );
        c.add( DefaultAuthorizationService.NAME );
        c.add( ExceptionService.NAME );
        c.add( OperationalAttributeService.NAME );
        c.add( SchemaService.NAME );
        c.add( SubentryService.NAME );
        c.add( CollectiveAttributeService.NAME );
        c.add( EventService.NAME );
        c.add( TriggerService.NAME );
        USERLOOKUP_BYPASS = Collections.unmodifiableCollection( c );
    }


    /**
     * Intercept the addition of the 'userPassword' and 'krb5PrincipalName' attributes.  Use the 'userPassword'
     * and 'krb5PrincipalName' attributes to derive Kerberos keys for the principal.  If the 'userPassword' is
     * the special keyword 'randomKey', set random keys for the principal.  Set the key version number (kvno)
     * to '0'.
     */
    public void add( NextInterceptor next, OperationContext addContext ) throws NamingException
    {
        LdapDN normName = addContext.getDn();

        Attributes entry = ( ( AddOperationContext ) addContext ).getEntry();

        if ( entry.get( "userPassword" ) != null && entry.get( KerberosAttribute.PRINCIPAL ) != null )
        {
            log.debug( "Adding the entry " + AttributeUtils.toString( entry ) + " for DN = '" + normName.getUpName()
                + "'" );

            Object firstValue = entry.get( "userPassword" ).get();

            if ( firstValue instanceof String )
            {
                log.debug( "Adding Attribute id : 'userPassword',  Values : ['" + firstValue + "']" );
            }
            else if ( firstValue instanceof byte[] )
            {
                String string = StringTools.utf8ToString( ( byte[] ) firstValue );

                StringBuffer sb = new StringBuffer();
                sb.append( "'" + string + "' ( " );
                sb.append( StringTools.dumpBytes( ( byte[] ) firstValue ).trim() );
                log.debug( "Adding Attribute id : 'userPassword',  Values : [ " + sb.toString() + " ) ]" );
                firstValue = string;
            }

            String userPassword = ( String ) firstValue;
            String principalName = ( String ) entry.get( KerberosAttribute.PRINCIPAL ).get();

            log.debug( "Got principal " + principalName + " with userPassword " + userPassword );

            Map<EncryptionType, EncryptionKey> keys = generateKeys( principalName, userPassword );

            entry.put( KerberosAttribute.PRINCIPAL, principalName );
            entry.put( KerberosAttribute.VERSION, Integer.toString( 0 ) );

            entry.put( getKeyAttribute( keys ) );

            log.debug( "Adding modified entry " + AttributeUtils.toString( entry ) + " for DN = '"
                + normName.getUpName() + "'" );

            // Optionally discard userPassword.
        }

        next.add( addContext );
    }


    /**
     * Intercept the modification of the 'userPassword' attribute.  Use the 'userPassword' and 'krb5PrincipalName'
     * attributes to derive Kerberos keys for the principal.  If the 'userPassword' is the special keyword
     * 'randomKey', set random keys for the principal.  Perform a lookup to check for an existing key version
     * number (kvno).  If a kvno exists, increment the kvno; otherwise, set the kvno to '0'.
     */
    public void modify( NextInterceptor next, OperationContext opContext ) throws NamingException
    {
        LdapDN name = opContext.getDn();
        ModifyOperationContext modContext = ( ModifyOperationContext ) opContext;

        ModificationItemImpl[] mods = modContext.getModItems();

        String userPassword = null;
        String principalName = null;

        // Loop over attributes being modified to pick out 'userPassword' and 'krb5PrincipalName'.
        for ( int ii = 0; ii < mods.length; ii++ )
        {
            Attribute attr = mods[ii].getAttribute();

            if ( log.isDebugEnabled() )
            {
                String operation = null;

                switch ( mods[ii].getModificationOp() )
                {
                    case DirContext.ADD_ATTRIBUTE:
                        operation = "Adding";
                        break;
                    case DirContext.REMOVE_ATTRIBUTE:
                        operation = "Removing";
                        break;
                    case DirContext.REPLACE_ATTRIBUTE:
                        operation = "Replacing";
                        break;
                }

                log.debug( operation + " for entry '" + name.getUpName() + "' the attribute " + attr );
            }

            String attrId = attr.getID();

            if ( attrId.equalsIgnoreCase( "userPassword" ) )
            {
                Object firstValue = attr.get();

                if ( firstValue instanceof String )
                {
                    log.debug( "Adding Attribute id : 'userPassword',  Values : ['" + firstValue + "']" );
                }
                else if ( firstValue instanceof byte[] )
                {
                    String string = StringTools.utf8ToString( ( byte[] ) firstValue );

                    StringBuffer sb = new StringBuffer();
                    sb.append( "'" + string + "' ( " );
                    sb.append( StringTools.dumpBytes( ( byte[] ) firstValue ).trim() );
                    log.debug( "Adding Attribute id : 'userPassword',  Values : [ " + sb.toString() + " ) ]" );
                    firstValue = string;
                }

                userPassword = ( String ) firstValue;
                log.debug( "Got userPassword " + userPassword + "." );
            }

            if ( attrId.equalsIgnoreCase( KerberosAttribute.PRINCIPAL ) )
            {
                principalName = ( String ) attr.get();
                log.debug( "Got principal " + principalName + "." );
            }
        }

        if ( userPassword != null && principalName != null )
        {
            log.debug( "Got principal " + principalName + " with userPassword " + userPassword );

            int kvno = lookupKeyVersionNumber( name );

            Map<EncryptionType, EncryptionKey> keys = generateKeys( principalName, userPassword );

            Set<ModificationItemImpl> newModsList = new HashSet<ModificationItemImpl>();

            // Make sure we preserve any other modification items.
            for ( int ii = 0; ii < mods.length; ii++ )
            {
                newModsList.add( mods[ii] );
            }

            // Add our modification items.
            newModsList.add( new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, new AttributeImpl(
                KerberosAttribute.PRINCIPAL, principalName ) ) );
            newModsList.add( new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, new AttributeImpl(
                KerberosAttribute.VERSION, Integer.toString( kvno ) ) ) );
            newModsList.add( new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, getKeyAttribute( keys ) ) );

            mods = newModsList.toArray( mods );

            modContext.setModItems( mods );
        }

        next.modify( opContext );
    }


    /**
     * Lookup the principal entry's krb5KeyVersionNumber attribute.
     *
     * @param principalDn
     * @return The principal entry's krb5KeyVersionNumber attribute.
     * @throws NamingException
     */
    protected int lookupKeyVersionNumber( LdapDN principalDn ) throws NamingException
    {
        Invocation invocation = InvocationStack.getInstance().peek();
        PartitionNexusProxy proxy = invocation.getProxy();
        Attributes userEntry;

        try
        {
            LookupOperationContext lookupContext = new LookupOperationContext( new String[]
                { KerberosAttribute.VERSION, KerberosAttribute.PRINCIPAL } );
            lookupContext.setDn( principalDn );

            userEntry = proxy.lookup( lookupContext, USERLOOKUP_BYPASS );

            if ( userEntry == null )
            {
                throw new LdapAuthenticationException( "Failed to lookup user for authentication: " + principalDn );
            }
        }
        catch ( Exception cause )
        {
            log.error( "Authentication error : " + cause.getMessage() );
            LdapAuthenticationException e = new LdapAuthenticationException();
            e.setRootCause( e );
            throw e;
        }

        int newKeyVersionNumber;

        Attribute keyVersionNumberAttr = userEntry.get( KerberosAttribute.VERSION );

        if ( keyVersionNumberAttr == null )
        {
            log.debug( "kvno was null, setting to 0." );
            newKeyVersionNumber = 0;
        }
        else
        {
            int oldKeyVersionNumber = Integer.valueOf( ( String ) keyVersionNumberAttr.get() );
            newKeyVersionNumber = oldKeyVersionNumber + 1;
            log.debug( "Found kvno '" + oldKeyVersionNumber + "', setting to '" + newKeyVersionNumber + "'." );
        }

        // TODO - We may wish to lookup the principal name if one is not present in the modification items.
        Attribute principalName = userEntry.get( KerberosAttribute.PRINCIPAL );
        log.debug( "Found principal = " + ( String ) principalName.get() );

        return newKeyVersionNumber;
    }


    private Attribute getKeyAttribute( Map<EncryptionType, EncryptionKey> keys )
    {
        Attribute keyAttribute = new AttributeImpl( KerberosAttribute.KEY );

        Iterator<EncryptionKey> it = keys.values().iterator();

        while ( it.hasNext() )
        {
            try
            {
                keyAttribute.add( EncryptionKeyEncoder.encode( it.next() ) );
            }
            catch ( IOException ioe )
            {
                log.error( "Error encoding EncryptionKey.", ioe );
            }
        }

        return keyAttribute;
    }


    private Map<EncryptionType, EncryptionKey> generateKeys( String principalName, String userPassword )
    {
        if ( userPassword.equalsIgnoreCase( "randomKey" ) )
        {
            // Generate random key.
            try
            {
                return RandomKeyFactory.getRandomKeys();
            }
            catch ( KerberosException ke )
            {
                log.debug( ke.getMessage(), ke );
                return null;
            }
        }
        else
        {
            // Derive key based on password and principal name.
            return KerberosKeyFactory.getKerberosKeys( principalName, userPassword );
        }
    }
}
