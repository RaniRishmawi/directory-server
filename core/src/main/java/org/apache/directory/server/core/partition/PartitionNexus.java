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
package org.apache.directory.server.core.partition;


import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;

import javax.naming.ConfigurationException;
import javax.naming.NameNotFoundException;
import javax.naming.directory.SearchControls;

import org.apache.directory.server.constants.ServerDNConstants;
import org.apache.directory.server.core.CoreSession;
import org.apache.directory.server.core.DefaultCoreSession;
import org.apache.directory.server.core.DirectoryService;
import org.apache.directory.server.core.authn.LdapPrincipal;
import org.apache.directory.server.core.entry.ClonedServerEntry;
import org.apache.directory.server.core.entry.DefaultServerAttribute;
import org.apache.directory.server.core.entry.DefaultServerEntry;
import org.apache.directory.server.core.entry.ServerEntry;
import org.apache.directory.server.core.filtering.BaseEntryFilteringCursor;
import org.apache.directory.server.core.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.interceptor.context.AddContextPartitionOperationContext;
import org.apache.directory.server.core.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.interceptor.context.BindOperationContext;
import org.apache.directory.server.core.interceptor.context.CompareOperationContext;
import org.apache.directory.server.core.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.interceptor.context.EntryOperationContext;
import org.apache.directory.server.core.interceptor.context.GetMatchedNameOperationContext;
import org.apache.directory.server.core.interceptor.context.GetRootDSEOperationContext;
import org.apache.directory.server.core.interceptor.context.GetSuffixOperationContext;
import org.apache.directory.server.core.interceptor.context.ListOperationContext;
import org.apache.directory.server.core.interceptor.context.ListSuffixOperationContext;
import org.apache.directory.server.core.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.interceptor.context.MoveAndRenameOperationContext;
import org.apache.directory.server.core.interceptor.context.MoveOperationContext;
import org.apache.directory.server.core.interceptor.context.RemoveContextPartitionOperationContext;
import org.apache.directory.server.core.interceptor.context.RenameOperationContext;
import org.apache.directory.server.core.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.interceptor.context.UnbindOperationContext;
import org.apache.directory.shared.ldap.MultiException;
import org.apache.directory.shared.ldap.NotImplementedException;
import org.apache.directory.shared.ldap.constants.AuthenticationLevel;
import org.apache.directory.shared.ldap.constants.SchemaConstants;
import org.apache.directory.shared.ldap.cursor.SingletonCursor;
import org.apache.directory.shared.ldap.entry.EntryAttribute;
import org.apache.directory.shared.ldap.entry.Value;
import org.apache.directory.shared.ldap.exception.LdapInvalidAttributeIdentifierException;
import org.apache.directory.shared.ldap.exception.LdapNameNotFoundException;
import org.apache.directory.shared.ldap.exception.LdapNoSuchAttributeException;
import org.apache.directory.shared.ldap.filter.ExprNode;
import org.apache.directory.shared.ldap.filter.PresenceNode;
import org.apache.directory.shared.ldap.message.control.CascadeControl;
import org.apache.directory.shared.ldap.message.control.EntryChangeControl;
import org.apache.directory.shared.ldap.message.control.ManageDsaITControl;
import org.apache.directory.shared.ldap.message.control.PagedSearchControl;
import org.apache.directory.shared.ldap.message.control.PersistentSearchControl;
import org.apache.directory.shared.ldap.message.control.SubentriesControl;
import org.apache.directory.shared.ldap.message.control.replication.SyncDoneValueControl;
import org.apache.directory.shared.ldap.message.control.replication.SyncInfoValueControl;
import org.apache.directory.shared.ldap.message.control.replication.SyncRequestValueControl;
import org.apache.directory.shared.ldap.message.control.replication.SyncStateValueControl;
import org.apache.directory.shared.ldap.message.extended.NoticeOfDisconnect;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.schema.AttributeType;
import org.apache.directory.shared.ldap.schema.Normalizer;
import org.apache.directory.shared.ldap.schema.SchemaUtils;
import org.apache.directory.shared.ldap.schema.UsageEnum;
import org.apache.directory.shared.ldap.schema.registries.AttributeTypeRegistry;
import org.apache.directory.shared.ldap.schema.registries.Registries;
import org.apache.directory.shared.ldap.util.DateUtils;
import org.apache.directory.shared.ldap.util.NamespaceTools;
import org.apache.directory.shared.ldap.util.StringTools;
import org.apache.directory.shared.ldap.util.tree.DnBranchNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A root {@link Partition} that contains all other partitions, and
 * routes all operations to the child partition that matches to its base suffixes.
 * It also provides some extended operations such as accessing rootDSE and
 * listing base suffixes.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$, $Date$
 */
public class PartitionNexus implements Partition
{
    /** A logger for this class */
    private static final Logger LOG = LoggerFactory.getLogger( PartitionNexus.class );

    /** Speedup for logs */
    private static final boolean IS_DEBUG = LOG.isDebugEnabled();

    /** the vendorName string proudly set to: Apache Software Foundation*/
    private static final String ASF = "Apache Software Foundation";

    /** the admin super user uid */
    public static final String ADMIN_UID = "admin";
    
    /** the initial admin passwd set on startup */
    public static final String ADMIN_PASSWORD_STRING = "secret";
    public static final byte[] ADMIN_PASSWORD_BYTES = StringTools.getBytesUtf8( ADMIN_PASSWORD_STRING );
    
    /** the read only rootDSE attributes */
    private final ServerEntry rootDSE;

    /** The DirectoryService instance */
    private DirectoryService directoryService;
    
    /** The global registries */
    private Registries registries;
    
    /** The attributeType registry */
    private AttributeTypeRegistry atRegistry;
    
    /** the partitions keyed by normalized suffix strings */
    private Map<String, Partition> partitions = new HashMap<String, Partition>();
    
    /** A structure to hold all the partitions */
    private DnBranchNode<Partition> partitionLookupTree = new DnBranchNode<Partition>();
    
    /** the system partition */
    private Partition system;

    /** the closed state of this partition */
    private boolean initialized;
    
   
    /**
     * Creates the root nexus singleton of the entire system.  The root DSE has
     * several attributes that are injected into it besides those that may
     * already exist.  As partitions are added to the system more namingContexts
     * attributes are added to the rootDSE.
     *
     * @see <a href="http://www.faqs.org/rfcs/rfc3045.html">Vendor Information</a>
     * @param rootDSE the root entry for the DSA
     * @throws javax.naming.Exception on failure to initialize
     */
    public PartitionNexus( ServerEntry rootDSE ) throws Exception
    {
        // setup that root DSE
        this.rootDSE = rootDSE;
        
        // Add the basic informations
        rootDSE.put( SchemaConstants.SUBSCHEMA_SUBENTRY_AT, ServerDNConstants.CN_SCHEMA_DN );
        rootDSE.put( SchemaConstants.SUPPORTED_LDAP_VERSION_AT, "3" );
        rootDSE.put( SchemaConstants.SUPPORTED_FEATURES_AT, SchemaConstants.FEATURE_ALL_OPERATIONAL_ATTRIBUTES );
        rootDSE.put( SchemaConstants.SUPPORTED_EXTENSION_AT, NoticeOfDisconnect.EXTENSION_OID );

        // Add the supported controls
        rootDSE.put( 
            SchemaConstants.SUPPORTED_CONTROL_AT, 
            PersistentSearchControl.CONTROL_OID,
            EntryChangeControl.CONTROL_OID,
            SubentriesControl.CONTROL_OID,
            ManageDsaITControl.CONTROL_OID,
            CascadeControl.CONTROL_OID,
            PagedSearchControl.CONTROL_OID,
            // Replication controls
            SyncDoneValueControl.CONTROL_OID,
            SyncInfoValueControl.CONTROL_OID,
            SyncRequestValueControl.CONTROL_OID,
            SyncStateValueControl.CONTROL_OID 
        );

        // Add the objectClasses
        rootDSE.put( SchemaConstants.OBJECT_CLASS_AT,
            SchemaConstants.TOP_OC,
            SchemaConstants.EXTENSIBLE_OBJECT_OC );

        // Add the 'vendor' name and version infos
        rootDSE.put( SchemaConstants.VENDOR_NAME_AT, ASF );

        Properties props = new Properties();
        
        try
        {
            props.load( getClass().getResourceAsStream( "version.properties" ) );
        }
        catch ( IOException e )
        {
            LOG.error( "failed to LOG version properties" );
        }

        rootDSE.put( SchemaConstants.VENDOR_VERSION_AT, props.getProperty( "apacheds.version", "UNKNOWN" ) );
    }

    
    /**
     * {@inheritDoc}
     */
    public void init( DirectoryService directoryService ) throws Exception
    {
        // NOTE: We ignore ContextPartitionConfiguration parameter here.
        if ( initialized )
        {
            return;
        }
    
        //this.directoryService = directoryService;
        registries = directoryService.getRegistries();
        atRegistry = registries.getAttributeTypeRegistry();
        
        // Initialize and normalize the localy used DNs
        LdapDN adminDn = new LdapDN( ServerDNConstants.ADMIN_SYSTEM_DN );
        adminDn.normalize( atRegistry.getNormalizerMapping() );
            
        initializeSystemPartition( directoryService );
        
        List<Partition> initializedPartitions = new ArrayList<Partition>();
        initializedPartitions.add( 0, this.system );
    
        try
        {
            for ( Partition partition : directoryService.getPartitions() )
            {
                //adminDn.normalize( registries.getAttributeTypeRegistry().getNormalizerMapping() );
                CoreSession adminSession = new DefaultCoreSession( 
                    new LdapPrincipal( adminDn, AuthenticationLevel.STRONG ), directoryService );
    
                AddContextPartitionOperationContext opCtx = 
                    new AddContextPartitionOperationContext( adminSession, partition );
                addContextPartition( opCtx );
                initializedPartitions.add( opCtx.getPartition() );
            }
            
            initialized = true;
        }
        finally
        {
            if ( !initialized )
            {
                Iterator<Partition> i = initializedPartitions.iterator();
                while ( i.hasNext() )
                {
                    Partition partition = i.next();
                    i.remove();
                    try
                    {
                        partition.destroy();
                    }
                    catch ( Exception e )
                    {
                        LOG.warn( "Failed to destroy a partition: " + partition.getSuffix(), e );
                    }
                    finally
                    {
                        unregister( partition );
                    }
                }
            }
        }
    }


    private Partition initializeSystemPartition( DirectoryService directoryService ) throws Exception
    {
        // initialize system partition first
        Partition override = directoryService.getSystemPartition();
        
        if ( override != null )
        {
            
            // ---------------------------------------------------------------
            // check a few things to make sure users configured it properly
            // ---------------------------------------------------------------

            if ( ! override.getId().equals( "system" ) )
            {
                throw new ConfigurationException( "System partition has wrong name: should be 'system' not '"
                        + override.getId() + "'." );
            }
            

            system = override;
        }

        system.init( directoryService );
        
        
        // Add root context entry for system partition
        LdapDN systemSuffixDn = new LdapDN( ServerDNConstants.SYSTEM_DN );
        systemSuffixDn.normalize( registries.getAttributeTypeRegistry().getNormalizerMapping() );
        ServerEntry systemEntry = new DefaultServerEntry( registries, systemSuffixDn );

        // Add the ObjectClasses
        systemEntry.put( SchemaConstants.OBJECT_CLASS_AT,
            SchemaConstants.TOP_OC,
            SchemaConstants.ORGANIZATIONAL_UNIT_OC,
            SchemaConstants.EXTENSIBLE_OBJECT_OC
            );
        
        // Add some operational attributes
        systemEntry.put( SchemaConstants.CREATORS_NAME_AT, ServerDNConstants.ADMIN_SYSTEM_DN );
        systemEntry.put( SchemaConstants.CREATE_TIMESTAMP_AT, DateUtils.getGeneralizedTime() );
        systemEntry.add( SchemaConstants.ENTRY_CSN_AT, directoryService.getCSN().toString() );
        systemEntry.add( SchemaConstants.ENTRY_UUID_AT, SchemaUtils.uuidToBytes( UUID.randomUUID() ) );
        systemEntry.put( NamespaceTools.getRdnAttribute( ServerDNConstants.SYSTEM_DN ),
            NamespaceTools.getRdnValue( ServerDNConstants.SYSTEM_DN ) );
        LdapDN adminDn = new LdapDN( ServerDNConstants.ADMIN_SYSTEM_DN_NORMALIZED );
        adminDn.normalize( registries.getAttributeTypeRegistry().getNormalizerMapping() );
        CoreSession adminSession = new DefaultCoreSession( 
            new LdapPrincipal( adminDn, AuthenticationLevel.STRONG ), directoryService );
        AddOperationContext addOperationContext = new AddOperationContext( adminSession, systemEntry );
        
        if ( !system.hasEntry( new EntryOperationContext( adminSession, systemEntry.getDn() ) ) )
        {
            system.add( addOperationContext );
        }
        
        String key = system.getSuffix().getUpName();
        
        if ( partitions.containsKey( key ) )
        {
            throw new ConfigurationException( "Duplicate partition suffix: " + key );
        }
        
        synchronized ( partitionLookupTree )
        {
            partitions.put( key, system );
            partitionLookupTree.add( system.getSuffix(), system );
            EntryAttribute namingContexts = rootDSE.get( SchemaConstants.NAMING_CONTEXTS_AT );
            
            if ( namingContexts == null )
            {
                namingContexts = new DefaultServerAttribute( 
                    registries.getAttributeTypeRegistry().lookup( SchemaConstants.NAMING_CONTEXTS_AT ), 
                    system.getSuffix().getUpName() );
                rootDSE.put( namingContexts );
            }
            else
            {
                namingContexts.add( system.getSuffix().getUpName() );
            }
        }

        return system;
    }
    
    
    /**
     * {@inheritDoc}
     */
    public synchronized void destroy()
    {
        if ( !initialized )
        {
            return;
        }

        // make sure this loop is not fail fast so all backing stores can
        // have an attempt at closing down and synching their cached entries
        for ( String suffix : new HashSet<String>( this.partitions.keySet() ) )
        {
            try
            {
                LdapDN adminDn = new LdapDN( ServerDNConstants.ADMIN_SYSTEM_DN_NORMALIZED );
                adminDn.normalize( registries.getAttributeTypeRegistry().getNormalizerMapping() );
                CoreSession adminSession = new DefaultCoreSession( 
                    new LdapPrincipal( adminDn, AuthenticationLevel.STRONG ), directoryService );
                removeContextPartition( new RemoveContextPartitionOperationContext( 
                    adminSession, new LdapDN( suffix ) ) );
            }
            catch ( Exception e )
            {
                LOG.warn( "Failed to destroy a partition: " + suffix, e );
            }
        }

        initialized = false;
    }


    /**
     * Always returns the string "NEXUS".
     *
     * @return the string "NEXUS"
     */
    public String getId()
    {
        return "NEXUS";
    }


    /**
     * Not supported!
     *
     * @throws UnsupportedOperationException everytime
     */
    public void setId( String id )
    {
        throw new UnsupportedOperationException( "The id cannot be set for the partition nexus." );
    }

    
    /**
     * Always returns the empty String "".
     * @return the empty String ""
     */
    public LdapDN getSuffix()
    {
        return LdapDN.EMPTY_LDAPDN;
    }

    
    /**
     * Unsupported operation on the Nexus.
     * @throws UnsupportedOperationException everytime
     */
    public void setSuffix( String suffix )
    {
        throw new UnsupportedOperationException();
    }


    /**
     * {@inheritDoc}
     */
    public boolean isInitialized()
    {
        return initialized;
    }


    /**
     * Not supported!
     *
     * @throws UnsupportedOperationException always
     */
    public int getCacheSize()
    {
        throw new UnsupportedOperationException( "There is no cache size associated with the nexus" );
    }

    
    /**
     * Not support!
     */
    public void setCacheSize( int cacheSize )
    {
        throw new UnsupportedOperationException( "You cannot set the cache size of the nexus" );
    }


    /**
     * {@inheritDoc}
     */
    public void sync() throws Exception
    {
        MultiException error = null;

        for ( Partition partition : this.partitions.values() )
        {
            try
            {
                partition.sync();
            }
            catch ( Exception e )
            {
                LOG.warn( "Failed to flush partition data out.", e );
                if ( error == null )
                {
                    //noinspection ThrowableInstanceNeverThrown
                    error = new MultiException( "Grouping many exceptions on root nexus sync()" );
                }

                // @todo really need to send this info to a monitor
                error.addThrowable( e );
            }
        }

        if ( error != null )
        {
            throw error;
        }
    }
    
    // ------------------------------------------------------------------------
    // DirectoryPartition Interface Method Implementations
    // ------------------------------------------------------------------------
    /**
     * {@inheritDoc}
     */
    public void add( AddOperationContext addContext ) throws Exception
    {
        Partition backend = getPartition( addContext.getDn() );
        backend.add( addContext );
    }
    
    
    /**
     * {@inheritDoc}
     */
    public void bind( BindOperationContext bindContext ) throws Exception
    {
        Partition partition = getPartition( bindContext.getDn() );
        partition.bind( bindContext );
    }

    
    /**
     * Performs a comparison check to see if an attribute of an entry has
     * a specified value.
     *
     * @param compareContext the context used to compare
     * @return true if the entry contains an attribute with the value, false otherwise
     * @throws Exception if there is a problem accessing the entry and its values
     * @throws Exception 
     */
    public boolean compare( CompareOperationContext compareContext ) throws Exception
    {
        Partition partition = getPartition( compareContext.getDn() );
        AttributeTypeRegistry registry = registries.getAttributeTypeRegistry();
        
        // complain if we do not recognize the attribute being compared
        if ( !registry.contains( compareContext.getOid() ) )
        {
            throw new LdapInvalidAttributeIdentifierException( compareContext.getOid() + " not found within the attributeType registry" );
        }

        AttributeType attrType = registry.lookup( compareContext.getOid() );
        
        EntryAttribute attr = partition.lookup( compareContext.newLookupContext( 
            compareContext.getDn() ) ).get( attrType.getName() );

        // complain if the attribute being compared does not exist in the entry
        if ( attr == null )
        {
            throw new LdapNoSuchAttributeException();
        }

        // see first if simple match without normalization succeeds
        if ( attr.contains( (Value<?>)compareContext.getValue()  ) )
        {
            return true;
        }

        // now must apply normalization to all values (attr and in request) to compare

        /*
         * Get ahold of the normalizer for the attribute and normalize the request
         * assertion value for comparisons with normalized attribute values.  Loop
         * through all values looking for a match.
         */
        Normalizer normalizer = attrType.getEquality().getNormalizer();
        Value<?> reqVal = normalizer.normalize( compareContext.getValue() );

        for ( Value<?> value:attr )
        {
            Value<?> attrValObj = normalizer.normalize( value );
            
            if ( attrValObj.equals( reqVal ) )
            {
                return true;
            }
        }

        return false;
    }


    /**
     * {@inheritDoc}
     */
    public void delete( DeleteOperationContext deleteContext ) throws Exception
    {
        Partition backend = getPartition( deleteContext.getDn() );
        backend.delete( deleteContext );
    }


    /**
     * {@inheritDoc}
     */
    public boolean hasEntry( EntryOperationContext opContext ) throws Exception
    {
        LdapDN dn = opContext.getDn();
        
        if ( IS_DEBUG )
        {
            LOG.debug( "Check if DN '" + dn + "' exists." );
        }

        if ( dn.size() == 0 )
        {
            return true;
        }

        Partition backend = getPartition( dn );
        return backend.hasEntry( opContext );
    }


    /**
     * {@inheritDoc}
     */
    public EntryFilteringCursor list( ListOperationContext opContext ) throws Exception
    {
        Partition backend = getPartition( opContext.getDn() );
        return backend.list( opContext );
    }


    /**
     * {@inheritDoc}
     */
    public ClonedServerEntry lookup( LookupOperationContext opContext ) throws Exception
    {
        LdapDN dn = opContext.getDn();
        
        if ( dn.size() == 0 )
        {
            ClonedServerEntry retval = new ClonedServerEntry( rootDSE );
            Set<AttributeType> attributeTypes = rootDSE.getAttributeTypes();
     
            if ( opContext.getAttrsId() != null && ! opContext.getAttrsId().isEmpty() )
            {
                for ( AttributeType attributeType:attributeTypes )
                {
                    String oid = attributeType.getOid();
                    
                    if ( ! opContext.getAttrsId().contains( oid ) )
                    {
                        retval.removeAttributes( attributeType );
                    }
                }
                return retval;
            }
            else
            {
                return new ClonedServerEntry( rootDSE );
            }
        }

        Partition backend = getPartition( dn );
        return backend.lookup( opContext );
    }


    /**
     * Not Implemented. This method is only available for backend Partitions.
     */
    public ClonedServerEntry lookup( Long id ) throws Exception
    {
        // TODO not implemented until we can use id to figure out the partition using
        // the partition ID component of the 64 bit Long identifier
        throw new NotImplementedException();
    }

    
    /**
     * {@inheritDoc}
     */
    public void modify( ModifyOperationContext modifyContext ) throws Exception
    {
        // Special case : if we don't have any modification to apply, just return
        if ( modifyContext.getModItems().size() == 0 )
        {
            return;
        }
        
        Partition backend = getPartition( modifyContext.getDn() );
        backend.modify( modifyContext );
    }


    /**
     * {@inheritDoc}
     */
    public void move( MoveOperationContext opContext ) throws Exception
    {
        Partition backend = getPartition( opContext.getDn() );
        backend.move( opContext );
    }


    /**
     * {@inheritDoc}
     */
    public void moveAndRename( MoveAndRenameOperationContext opContext ) throws Exception
    {
        Partition backend = getPartition( opContext.getDn() );
        backend.moveAndRename( opContext );
    }


    /**
     * {@inheritDoc}
     */
    public void rename( RenameOperationContext opContext ) throws Exception
    {
        Partition backend = getPartition( opContext.getDn() );
        backend.rename( opContext );
    }


    /**
     * {@inheritDoc}
     */
    public EntryFilteringCursor search( SearchOperationContext opContext )
        throws Exception
    {
        LdapDN base = opContext.getDn();
        SearchControls searchCtls = opContext.getSearchControls();
        ExprNode filter = opContext.getFilter();
        
        // TODO since we're handling the *, and + in the EntryFilteringCursor
        // we may not need this code: we need see if this is actually the 
        // case and remove this code.
        if ( base.size() == 0 )
        {
            boolean isObjectScope = searchCtls.getSearchScope() == SearchControls.OBJECT_SCOPE;
            
            // test for (objectClass=*)
            boolean isSearchAll = false;
            
            // We have to be careful, as we may have a filter which is not a PresenceFilter
            if ( filter instanceof PresenceNode )
            {
                isSearchAll = ( ( PresenceNode ) filter ).getAttribute().equals( SchemaConstants.OBJECT_CLASS_AT_OID );
            }
    
            /*
             * if basedn is "", filter is "(objectclass=*)" and scope is object
             * then we have a request for the rootDSE
             */
            if ( filter instanceof PresenceNode && isObjectScope && isSearchAll )
            {
                String[] ids = searchCtls.getReturningAttributes();
    
                // -----------------------------------------------------------
                // If nothing is asked for then we just return the entry asis.
                // We let other mechanisms filter out operational attributes.
                // -----------------------------------------------------------
                if ( ( ids == null ) || ( ids.length == 0 ) )
                {
                    ServerEntry rootDSE = (ServerEntry)getRootDSE( null ).clone();
                    return new BaseEntryFilteringCursor( new SingletonCursor<ServerEntry>( rootDSE ), opContext );
                }
                
                // -----------------------------------------------------------
                // Collect all the real attributes besides 1.1, +, and * and
                // note if we've seen these special attributes as well.
                // -----------------------------------------------------------
    
                Set<String> realIds = new HashSet<String>();
                boolean containsAsterisk = false;
                boolean containsPlus = false;
                boolean containsOneDotOne = false;
                
                for ( String id:ids )
                {
                    String idTrimmed = id.trim();
                    
                    if ( idTrimmed.equals( SchemaConstants.ALL_USER_ATTRIBUTES ) )
                    {
                        containsAsterisk = true;
                    }
                    else if ( idTrimmed.equals( SchemaConstants.ALL_OPERATIONAL_ATTRIBUTES ) )
                    {
                        containsPlus = true;
                    }
                    else if ( idTrimmed.equals( SchemaConstants.NO_ATTRIBUTE ) )
                    {
                        containsOneDotOne = true;
                    }
                    else
                    {
                        try
                        {
                            realIds.add( atRegistry.getOidByName( idTrimmed ) );
                        }
                        catch ( Exception e )
                        {
                            realIds.add( idTrimmed );
                        }
                    }
                }
    
                // return nothing
                if ( containsOneDotOne )
                {
                    ServerEntry serverEntry = new DefaultServerEntry( registries, base );
                    return new BaseEntryFilteringCursor( new SingletonCursor<ServerEntry>( serverEntry ), opContext );
                }
                
                // return everything
                if ( containsAsterisk && containsPlus )
                {
                    ServerEntry rootDSE = (ServerEntry)getRootDSE( null ).clone();
                    return new BaseEntryFilteringCursor( new SingletonCursor<ServerEntry>( rootDSE ), opContext );
                }
                
                ServerEntry serverEntry = new DefaultServerEntry( registries, opContext.getDn() );
                
                ServerEntry rootDSE = getRootDSE( new GetRootDSEOperationContext( opContext.getSession() ) );
                
                for ( EntryAttribute attribute:rootDSE )
                {
                    AttributeType type = atRegistry.lookup( attribute.getUpId() );
                    
                    if ( realIds.contains( type.getOid() ) )
                    {
                        serverEntry.put( attribute );
                    }
                    else if ( containsAsterisk && ( type.getUsage() == UsageEnum.USER_APPLICATIONS ) )
                    {
                        serverEntry.put( attribute );
                    }
                    else if ( containsPlus && ( type.getUsage() != UsageEnum.USER_APPLICATIONS ) )
                    {
                        serverEntry.put( attribute );
                    }
                }
    
                return new BaseEntryFilteringCursor( new SingletonCursor<ServerEntry>( serverEntry ), opContext );
            }
    
            // TODO : handle searches based on the RootDSE
            throw new LdapNameNotFoundException();
        }
    
        Partition backend = getPartition( base );
        return backend.search( opContext );
    }


    /**
     * {@inheritDoc}
     */
    public void unbind( UnbindOperationContext unbindContext ) throws Exception
    {
        Partition partition = getPartition( unbindContext.getDn() );
        partition.unbind( unbindContext );
    }


    /**
     * Get's the RootDSE entry for the DSA.
     *
     * @return the attributes of the RootDSE
     */
    public ClonedServerEntry getRootDSE( GetRootDSEOperationContext getRootDSEContext )
    {
        return new ClonedServerEntry( rootDSE );
    }


    /**
     * Add a partition to the server.
     * 
     * @param opContext The Add Partition context
     * @throws Exception If the addition can't be done
     */
    public synchronized void addContextPartition( AddContextPartitionOperationContext opContext ) throws Exception
    {
        Partition partition = opContext.getPartition();

        // Turn on default indices
        String key = partition.getSuffix().getNormName();
        
        if ( partitions.containsKey( key ) )
        {
            throw new ConfigurationException( "Duplicate partition suffix: " + key );
        }

        if ( ! partition.isInitialized() )
        {
            partition.init( directoryService );
        }
        
        synchronized ( partitionLookupTree )
        {
            LdapDN partitionSuffix = partition.getSuffix();
            
            if ( partitionSuffix == null )
            {
                throw new ConfigurationException( "The current partition does not have any suffix: " + partition.getId() );
            }
            
            partitions.put( partitionSuffix.toString(), partition );
            partitionLookupTree.add( partition.getSuffix(), partition );

            EntryAttribute namingContexts = rootDSE.get( SchemaConstants.NAMING_CONTEXTS_AT );

            if ( namingContexts == null )
            {
                namingContexts = new DefaultServerAttribute( 
                    registries.getAttributeTypeRegistry().lookup( SchemaConstants.NAMING_CONTEXTS_AT ), partitionSuffix.getUpName() );
                rootDSE.put( namingContexts );
            }
            else
            {
                namingContexts.add( partitionSuffix.getUpName() );
            }
        }
    }


    /**
     * Remove a partition from the server.
     * 
     * @param opContext The Remove Partition context
     * @throws Exception If the removal can't be done
     */
    public synchronized void removeContextPartition( RemoveContextPartitionOperationContext removeContextPartition ) throws Exception
    {
        // Get the Partition name. It's a DN.
        String key = removeContextPartition.getDn().getNormName();
        
        // Retrieve this partition from the aprtition's table
        Partition partition = partitions.get( key );
        
        if ( partition == null )
        {
            String msg = "No partition with suffix: " + key;
            LOG.error( msg );
            throw new NameNotFoundException( msg );
        }
        
        String partitionSuffix = partition.getSuffix().getUpName();

        // Retrieve the namingContexts from the RootDSE : the partition
        // suffix must be present in those namingContexts
        EntryAttribute namingContexts = rootDSE.get( SchemaConstants.NAMING_CONTEXTS_AT );
        
        if ( namingContexts != null )
        {
            if ( namingContexts.contains( partitionSuffix ) )
            {
                namingContexts.remove( partitionSuffix );
            }
            else
            {
                String msg = "No partition with suffix '" + key + 
                                    "' can be found in the NamingContexts";
                LOG.error( msg );
                throw new NameNotFoundException( msg );
            }
        }

        // Update the partition tree
        partitionLookupTree.remove( partition );
        partitions.remove( key );
        partition.destroy();
    }


    /**
     * @return The ou=system partition 
     */
    public Partition getSystemPartition()
    {
        return system;
    }


    /**
     * Get's the partition corresponding to a distinguished name.  This 
     * name need not be the name of the partition suffix.  When used in 
     * conjunction with get suffix this can properly find the partition 
     * associated with the DN.  Make sure to use the normalized DN.
     * 
     * @param dn the normalized distinguished name to get a partition for
     * @return the partition containing the entry represented by the dn
     * @throws Exception if there is no partition for the dn
     */
    public Partition getPartition( LdapDN dn ) throws Exception
    {
        Partition parent = partitionLookupTree.getParentElement( dn );
        
        if ( parent == null )
        {
            throw new LdapNameNotFoundException( " Cannot find a partition for " + dn );
        }
        else
        {
            return parent;
        }
    }


    /**
     * Gets the most significant Dn that exists within the server for any Dn.
     *
     * @param getMatchedNameContext the context containing the  distinguished name 
     * to use for matching.
     * @return a distinguished name representing the matching portion of dn,
     * as originally provided by the user on creation of the matched entry or 
     * the empty string distinguished name if no match was found.
     * @throws Exception if there are any problems
     */
    public LdapDN getMatchedName( GetMatchedNameOperationContext matchedNameContext ) throws Exception
    {
        LdapDN dn = ( LdapDN ) matchedNameContext.getDn().clone();
        
        while ( dn.size() > 0 )
        {
            if ( hasEntry( new EntryOperationContext( matchedNameContext.getSession(), dn ) ) )
            {
                return dn;
            }

            dn.remove( dn.size() - 1 );
        }

        return dn;
    }


    /**
     * Gets the distinguished name of the suffix that would hold an entry with
     * the supplied distinguished name parameter.  If the DN argument does not
     * fall under a partition suffix then the empty string Dn is returned.
     *
     * @param suffixContext the Context containing normalized distinguished
     * name to use for finding a suffix.
     * @return the suffix portion of dn, or the valid empty string Dn if no
     * naming context was found for dn.
     * @throws Exception if there are any problems
     */
    public LdapDN getSuffix( GetSuffixOperationContext getSuffixContext ) throws Exception
    {
        Partition backend = getPartition( getSuffixContext.getDn() );
        return backend.getSuffix();
    }


    /**
     * Gets an iteration over the Name suffixes of the partitions managed by this
     * {@link PartitionNexus}.
     *
     * @return Iteration over ContextPartition suffix names as Names.
     * @throws Exception if there are any problems
     */
    public Set<String> listSuffixes( ListSuffixOperationContext emptyContext ) throws Exception
    {
        return Collections.unmodifiableSet( partitions.keySet() );
    }


    /**
     * Adds a set of supportedExtension (OID Strings) to the RootDSE.
     * 
     * @param extensionOids a set of OID strings to add to the supportedExtension 
     * attribute in the RootDSE
     */
    public void registerSupportedExtensions( Set<String> extensionOids ) throws Exception
    {
        EntryAttribute supportedExtension = rootDSE.get( SchemaConstants.SUPPORTED_EXTENSION_AT );

        if ( supportedExtension == null )
        {
            rootDSE.set( SchemaConstants.SUPPORTED_EXTENSION_AT );
            supportedExtension = rootDSE.get( SchemaConstants.SUPPORTED_EXTENSION_AT );
        }

        for ( String extensionOid : extensionOids )
        {
            supportedExtension.add( extensionOid );
        }
    }


    /**
     * Adds a set of supportedSaslMechanisms (OID Strings) to the RootDSE.
     * 
     * @param extensionOids a set of OID strings to add to the supportedSaslMechanisms 
     * attribute in the RootDSE
     */
    public void registerSupportedSaslMechanisms( Set<String> supportedSaslMechanisms ) throws Exception
    {
        EntryAttribute supportedSaslMechanismsAttribute = rootDSE.get( SchemaConstants.SUPPORTED_SASL_MECHANISMS_AT );

        if ( supportedSaslMechanismsAttribute == null )
        {
            rootDSE.set( SchemaConstants.SUPPORTED_SASL_MECHANISMS_AT );
            supportedSaslMechanismsAttribute = rootDSE.get( SchemaConstants.SUPPORTED_SASL_MECHANISMS_AT );
        }

        for ( String saslMechanism : supportedSaslMechanisms )
        {
            supportedSaslMechanismsAttribute.add( saslMechanism );
        }
    }


    /**
     * Unregisters an ContextPartition with this BackendManager.  Called for each
     * registered Backend right befor it is to be stopped.  This prevents
     * protocol server requests from reaching the Backend and effectively puts
     * the ContextPartition's naming context offline.
     *
     * Operations against the naming context should result in an LDAP BUSY
     * result code in the returnValue if the naming context is not online.
     *
     * @param partition ContextPartition component to unregister with this
     * BackendNexus.
     * @throws Exception if there are problems unregistering the partition
     */
    private void unregister( Partition partition ) throws Exception
    {
        EntryAttribute namingContexts = rootDSE.get( SchemaConstants.NAMING_CONTEXTS_AT );
        
        if ( namingContexts != null )
        {
            namingContexts.remove( partition.getSuffix().getUpName() );
        }
        
        partitions.remove( partition.getSuffix().getUpName() );
    }
}
