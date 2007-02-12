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
package org.apache.directory.server.core.schema;


import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import jdbm.helper.IntegerComparator;

import org.apache.directory.server.core.unit.AbstractAdminTestCase;
import org.apache.directory.shared.ldap.exception.LdapNameAlreadyBoundException;
import org.apache.directory.shared.ldap.exception.LdapOperationNotSupportedException;
import org.apache.directory.shared.ldap.message.AttributeImpl;
import org.apache.directory.shared.ldap.message.AttributesImpl;
import org.apache.directory.shared.ldap.message.ModificationItemImpl;
import org.apache.directory.shared.ldap.message.ResultCodeEnum;
import org.apache.directory.shared.ldap.name.LdapDN;
import org.apache.directory.shared.ldap.schema.AttributeType;
import org.apache.directory.shared.ldap.schema.DeepTrimNormalizer;
import org.apache.directory.shared.ldap.schema.syntax.AcceptAllSyntaxChecker;
import org.apache.directory.shared.ldap.schema.syntax.AttributeTypeDescription;
import org.apache.directory.shared.ldap.schema.syntax.ComparatorDescription;
import org.apache.directory.shared.ldap.schema.syntax.LdapSyntaxDescription;
import org.apache.directory.shared.ldap.schema.syntax.MatchingRuleDescription;
import org.apache.directory.shared.ldap.schema.syntax.NormalizerDescription;
import org.apache.directory.shared.ldap.schema.syntax.ObjectClassDescription;
import org.apache.directory.shared.ldap.schema.syntax.SyntaxChecker;
import org.apache.directory.shared.ldap.schema.syntax.SyntaxCheckerDescription;
import org.apache.directory.shared.ldap.schema.syntax.parser.AttributeTypeDescriptionSchemaParser;
import org.apache.directory.shared.ldap.schema.syntax.parser.ComparatorDescriptionSchemaParser;
import org.apache.directory.shared.ldap.schema.syntax.parser.LdapSyntaxDescriptionSchemaParser;
import org.apache.directory.shared.ldap.schema.syntax.parser.MatchingRuleDescriptionSchemaParser;
import org.apache.directory.shared.ldap.schema.syntax.parser.NormalizerDescriptionSchemaParser;
import org.apache.directory.shared.ldap.schema.syntax.parser.ObjectClassDescriptionSchemaParser;
import org.apache.directory.shared.ldap.schema.syntax.parser.SyntaxCheckerDescriptionSchemaParser;
import org.apache.directory.shared.ldap.util.Base64;


/**
 * An integration test class for performing various operations on the 
 * subschemaSubentry as listed in the rootDSE.
 *
 * @author <a href="mailto:dev@directory.apache.org">Apache Directory Project</a>
 * @version $Rev$
 */
public class SubschemaSubentryITest extends AbstractAdminTestCase
{
    private static final String GLOBAL_SUBSCHEMA_DN = "cn=schema";
    private static final String SUBSCHEMA_SUBENTRY = "subschemaSubentry";
    
    private static final SyntaxCheckerDescriptionSchemaParser syntaxCheckerDescriptionSchemaParser =
        new SyntaxCheckerDescriptionSchemaParser();
    private static final AttributeTypeDescriptionSchemaParser attributeTypeDescriptionSchemaParser = 
        new AttributeTypeDescriptionSchemaParser();
    private ComparatorDescriptionSchemaParser comparatorDescriptionSchemaParser =
        new ComparatorDescriptionSchemaParser();
    private NormalizerDescriptionSchemaParser normalizerDescriptionSchemaParser =
        new NormalizerDescriptionSchemaParser();
    private LdapSyntaxDescriptionSchemaParser ldapSyntaxDescriptionSchemaParser =
        new LdapSyntaxDescriptionSchemaParser();
    private MatchingRuleDescriptionSchemaParser matchingRuleDescriptionSchemaParser =
        new MatchingRuleDescriptionSchemaParser();
    private ObjectClassDescriptionSchemaParser objectClassDescriptionSchemaParser =
        new ObjectClassDescriptionSchemaParser();

    
    /**
     * Make sure the global subschemaSubentry is where it is expected to be. 
     */
    public void testRootDSEsSubschemaSubentry() throws NamingException
    {
        assertEquals( GLOBAL_SUBSCHEMA_DN, getSubschemaSubentryDN() );
        Attributes subschemaSubentryAttrs = getSubschemaSubentryAttributes();
        assertNotNull( subschemaSubentryAttrs );
    }
    
    
    /**
     * Tests the rejection of a delete operation on the SubschemaSubentry (SSSE).
     */
    public void testSSSEDeleteRejection() throws NamingException
    {
        try
        {
            rootDSE.destroySubcontext( getSubschemaSubentryDN() );
            fail( "You are not allowed to delete the global schema subentry" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
    }


    /**
     * Tests the rejection of an add operation for the SubschemaSubentry (SSSE).
     */
    public void testSSSEAddRejection() throws NamingException
    {
        try
        {
            rootDSE.createSubcontext( getSubschemaSubentryDN(), getSubschemaSubentryAttributes() );
            fail( "You are not allowed to add the global schema subentry which exists by default" );
        }
        catch( LdapNameAlreadyBoundException e )
        {
            assertEquals( ResultCodeEnum.ENTRY_ALREADY_EXISTS, e.getResultCode() );
        }
    }


    /**
     * Tests the rejection of rename (modifyDn) operation for the SubschemaSubentry (SSSE).
     */
    public void testSSSERenameRejection() throws NamingException
    {
        try
        {
            rootDSE.rename( getSubschemaSubentryDN(), "cn=schema,ou=system" );
            fail( "You are not allowed to rename the global schema subentry which is fixed" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
    }


    /**
     * Tests the rejection of move operation for the SubschemaSubentry (SSSE).
     */
    public void testSSSEMoveRejection() throws NamingException
    {
        try
        {
            rootDSE.rename( getSubschemaSubentryDN(), "cn=blah,ou=schema" );
            fail( "You are not allowed to move the global schema subentry which is fixed" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        try
        {
            rootDSE.rename( getSubschemaSubentryDN(), "cn=schema,ou=schema" );
            fail( "You are not allowed to move the global schema subentry which is fixed" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
    }
    
    
    // -----------------------------------------------------------------------
    // SyntaxChecker Tests
    // -----------------------------------------------------------------------

    
    private void checkSyntaxCheckerPresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "syntaxCheckers" );
        SyntaxCheckerDescription syntaxCheckerDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                syntaxCheckerDescription = syntaxCheckerDescriptionSchemaParser.parseSyntaxCheckerDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( syntaxCheckerDescription );
            assertEquals( oid, syntaxCheckerDescription.getNumericOid() );
        }
        else
        {
            assertNull( syntaxCheckerDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=syntaxCheckers,cn=" + schemaName );
            assertNotNull( attrs );
            SchemaEntityFactory factory = new SchemaEntityFactory( registries );
            SyntaxChecker syntaxChecker = factory.getSyntaxChecker( attrs, registries );
            assertEquals( oid, syntaxChecker.getSyntaxOid() );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=syntaxCheckers,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the syntaxCheckerRegistry
        // -------------------------------------------------------------------

        if ( isPresent )
        {
            assertTrue( registries.getSyntaxCheckerRegistry().hasSyntaxChecker( oid ) );
        }
        else
        {
            assertFalse( registries.getSyntaxCheckerRegistry().hasSyntaxChecker( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * a syntaxChecker on the schema subentry.
     */
    public void testAddRemoveReplaceSyntaxCheckers() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();
        
        // ( 1.3.6.1.4.1.18060.0.4.0.2.10000 DESC 'bogus desc' FQCN org.foo.Bar BYTECODE 14561234 )
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10000 DESC 'bogus desc' FQCN " 
            + AcceptAllSyntaxChecker.class.getName() + " X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10001 DESC 'bogus desc' FQCN " 
            + AcceptAllSyntaxChecker.class.getName() + " X-SCHEMA 'nis' )" );

        // -------------------------------------------------------------------
        // add and check
        // -------------------------------------------------------------------
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "syntaxCheckers" );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", true );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", true );

        // -------------------------------------------------------------------
        // remove and check
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "syntaxCheckers" );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", false );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", false );
        
        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "syntaxCheckers" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add with valid bytecode
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN DummySyntaxChecker BYTECODE " 
            +  getByteCode( "DummySyntaxChecker.bytecode" ) + " X-SCHEMA 'nis' )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "syntaxCheckers" );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", true );

        // -------------------------------------------------------------------
        // check remove with valid bytecode
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "syntaxCheckers" );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", false );

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN DummySyntaxChecker BYTECODE " 
            +  getByteCode( "DummySyntaxChecker.bytecode" ) + " )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "syntaxCheckers" );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "other", true );
    }
    
    
    // -----------------------------------------------------------------------
    // Comparator Tests
    // -----------------------------------------------------------------------
    
    
    private void checkComparatorPresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "comparators" );
        ComparatorDescription comparatorDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                comparatorDescription = comparatorDescriptionSchemaParser.parseComparatorDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( comparatorDescription );
            assertEquals( oid, comparatorDescription.getNumericOid() );
        }
        else
        {
            assertNull( comparatorDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=comparators,cn=" + schemaName );
            assertNotNull( attrs );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=comparators,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the comparatorRegistry
        // -------------------------------------------------------------------

        if ( isPresent )
        {
            assertTrue( registries.getComparatorRegistry().hasComparator( oid ) );
        }
        else
        {
            assertFalse( registries.getComparatorRegistry().hasComparator( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * comparators on the schema subentry.
     */
    public void testAddRemoveReplaceComparators() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();
        
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10000 DESC 'bogus desc' FQCN " 
            + IntegerComparator.class.getName() + " X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10001 DESC 'bogus desc' FQCN " 
            + IntegerComparator.class.getName() + " X-SCHEMA 'nis' )" );

        // -------------------------------------------------------------------
        // add and check
        // -------------------------------------------------------------------
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "comparators" );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", true );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", true );

        // -------------------------------------------------------------------
        // remove and check
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "comparators" );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", false );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", false );
        
        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "comparators" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add with valid bytecode
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN DummyComparator BYTECODE " 
            +  getByteCode( "DummyComparator.bytecode" ) + " X-SCHEMA 'nis' )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "comparators" );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", true );

        // -------------------------------------------------------------------
        // check remove with valid bytecode
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "comparators" );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", false );

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN DummyComparator BYTECODE " 
            +  getByteCode( "DummyComparator.bytecode" ) + " )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "comparators" );
        checkComparatorPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "other", true );
    }

    
    // -----------------------------------------------------------------------
    // Normalizer Tests
    // -----------------------------------------------------------------------
    
    
    private void checkNormalizerPresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "normalizers" );
        NormalizerDescription normalizerDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                normalizerDescription = normalizerDescriptionSchemaParser.parseNormalizerDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( normalizerDescription );
            assertEquals( oid, normalizerDescription.getNumericOid() );
        }
        else
        {
            assertNull( normalizerDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=normalizers,cn=" + schemaName );
            assertNotNull( attrs );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=normalizers,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the normalizerRegistry
        // -------------------------------------------------------------------
        
        if ( isPresent ) 
        { 
            assertTrue( registries.getNormalizerRegistry().hasNormalizer( oid ) );
        }
        else
        {
            assertFalse( registries.getNormalizerRegistry().hasNormalizer( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * normalizers on the schema subentry.
     */
    public void testAddRemoveReplaceNormalizers() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();
        
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10000 DESC 'bogus desc' FQCN " 
            + DeepTrimNormalizer.class.getName() + " X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10001 DESC 'bogus desc' FQCN " 
            + DeepTrimNormalizer.class.getName() + " X-SCHEMA 'nis' )" );

        // -------------------------------------------------------------------
        // add and check
        // -------------------------------------------------------------------
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "normalizers" );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", true );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", true );

        // -------------------------------------------------------------------
        // remove and check
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "normalizers" );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", false );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", false );
        
        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "normalizers" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add with valid bytecode
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN DummyNormalizer BYTECODE " 
            +  getByteCode( "DummyNormalizer.bytecode" ) + " X-SCHEMA 'nis' )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "normalizers" );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", true );

        // -------------------------------------------------------------------
        // check remove with valid bytecode
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "normalizers" );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", false );

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN DummyNormalizer BYTECODE " 
            +  getByteCode( "DummyNormalizer.bytecode" ) + " )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "normalizers" );
        checkNormalizerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "other", true );
    }

    
    // -----------------------------------------------------------------------
    // Syntax Tests
    // -----------------------------------------------------------------------
    
    
    private void checkSyntaxPresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "ldapSyntaxes" );
        LdapSyntaxDescription syntaxDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                syntaxDescription = ldapSyntaxDescriptionSchemaParser.parseLdapSyntaxDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( syntaxDescription );
            assertEquals( oid, syntaxDescription.getNumericOid() );
        }
        else
        {
            assertNull( syntaxDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=syntaxes,cn=" + schemaName );
            assertNotNull( attrs );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=syntaxes,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the syntaxRegistry
        // -------------------------------------------------------------------
        
        if ( isPresent ) 
        { 
            assertTrue( registries.getSyntaxRegistry().hasSyntax( oid ) );
        }
        else
        {
            assertFalse( registries.getSyntaxRegistry().hasSyntax( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * syntaxes on the schema subentry.
     */
    public void testAddRemoveReplaceSyntaxes() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();
        
        // -------------------------------------------------------------------
        // add of syntaxes without their syntax checkers should fail
        // -------------------------------------------------------------------
        
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10000 DESC 'bogus desc' X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10001 DESC 'bogus desc' X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "ldapSyntaxes" );
            fail( "should not be able to add syntaxes without their syntaxCheckers" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        // none of the syntaxes should be present
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", false );
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", false );

        // -------------------------------------------------------------------
        // first in order to add syntaxes we need their syntax checkers 
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10000 DESC 'bogus desc' FQCN " 
            + AcceptAllSyntaxChecker.class.getName() + " X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10001 DESC 'bogus desc' FQCN " 
            + AcceptAllSyntaxChecker.class.getName() + " X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' FQCN " 
            + AcceptAllSyntaxChecker.class.getName() + " X-SCHEMA 'nis' )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "syntaxCheckers" );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", true );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", true );
        checkSyntaxCheckerPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "nis", true );

        // -------------------------------------------------------------------
        // add and check
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10000 DESC 'bogus desc' X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10001 DESC 'bogus desc' X-SCHEMA 'nis' )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "ldapSyntaxes" );
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", true );
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", true );

        // -------------------------------------------------------------------
        // remove and check
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "ldapSyntaxes" );
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10000", "nis", false );
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10001", "nis", false );
        
        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "ldapSyntaxes" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.0.10002 DESC 'bogus desc' )" );
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "ldapSyntaxes" );
        checkSyntaxPresent( "1.3.6.1.4.1.18060.0.4.1.0.10002", "other", true );
    }
    
    
    // -----------------------------------------------------------------------
    // MatchingRule Tests
    // -----------------------------------------------------------------------
    
    
    private void checkMatchingRulePresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "matchingRules" );
        MatchingRuleDescription matchingRuleDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                matchingRuleDescription = matchingRuleDescriptionSchemaParser.parseMatchingRuleDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( matchingRuleDescription );
            assertEquals( oid, matchingRuleDescription.getNumericOid() );
        }
        else
        {
            assertNull( matchingRuleDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=matchingRules,cn=" + schemaName );
            assertNotNull( attrs );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=matchingRules,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the matchingRuleRegistry
        // -------------------------------------------------------------------
        
        if ( isPresent ) 
        { 
            assertTrue( registries.getMatchingRuleRegistry().hasMatchingRule( oid ) );
        }
        else
        {
            assertFalse( registries.getMatchingRuleRegistry().hasMatchingRule( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * matchingRules on the schema subentry.
     */
    public void testAddRemoveReplaceMatchingRules() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();

        // -------------------------------------------------------------------
        // test rejection with non-existant syntax
        // -------------------------------------------------------------------
        
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10000 DESC 'bogus desc' SYNTAX 1.2.3.4 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10001 DESC 'bogus desc' SYNTAX 1.2.3.4 X-SCHEMA 'nis' )" );

        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "matchingRules" );
            fail( "Cannot add matchingRule with bogus non-existant syntax" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", false );

        // -------------------------------------------------------------------
        // test add with existant syntax but no name and no desc
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10000 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10001 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "matchingRules" );
        
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", true );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add with existant syntax but no name 
        // -------------------------------------------------------------------
        
        // clear the matchingRules out now
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "matchingRules" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", false );

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10000 DESC 'bogus desc' " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10001 DESC 'bogus desc' " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "matchingRules" );
        
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", true );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add success with name
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "matchingRules" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10000 NAME 'blah0' DESC 'bogus desc' " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10001 NAME ( 'blah1' 'othername1' ) DESC 'bogus desc' " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "matchingRules" );
        
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", true );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add success full (with obsolete)
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "matchingRules" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10000 NAME 'blah0' DESC 'bogus desc' " +
                "OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10001 NAME ( 'blah1' 'othername1' ) DESC 'bogus desc' " +
                "OBSOLETE SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "matchingRules" );
        
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", true );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", true );

        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "matchingRules" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10001", "nis", false );
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "matchingRules" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.1.10002 DESC 'bogus desc' " +
        "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )" );
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "matchingRules" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.1.10002", "other", true );
    }

    
    // -----------------------------------------------------------------------
    // AttributeType Tests
    // -----------------------------------------------------------------------

    
    private void checkAttributeTypePresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "attributeTypes" );
        AttributeTypeDescription attributeTypeDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                attributeTypeDescription = attributeTypeDescriptionSchemaParser.parseAttributeTypeDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( attributeTypeDescription );
            assertEquals( oid, attributeTypeDescription.getNumericOid() );
        }
        else
        {
            assertNull( attributeTypeDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=attributeTypes,cn=" + schemaName );
            assertNotNull( attrs );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=attributeTypes,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the attributeTypeRegistry
        // -------------------------------------------------------------------
        
        if ( isPresent ) 
        { 
            assertTrue( registries.getAttributeTypeRegistry().hasAttributeType( oid ) );
        }
        else
        {
            assertFalse( registries.getAttributeTypeRegistry().hasAttributeType( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * attributeTypes on the schema subentry.
     */
    public void testAddRemoveReplaceAttributeTypes() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();

        // -------------------------------------------------------------------
        // test rejection with non-existant syntax
        // -------------------------------------------------------------------
        
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 DESC 'bogus desc' " +
                "SYNTAX 1.2.3.4 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 DESC 'bogus desc' " +
                "SYNTAX 1.2.3.4 X-SCHEMA 'nis' )" );

        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
            fail( "Cannot add attributeType with bogus non-existant syntax" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", false );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", false );

        // -------------------------------------------------------------------
        // test reject with non-existant super type
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 1.2.3.4 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 1.2.3.4 X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
            fail( "Cannot add attributeType with bogus non-existant syntax" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", false );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", false );

        // -------------------------------------------------------------------
        // test reject with non-existant equality matchingRule
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY 1.2.3.4 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 EQUALITY 1.2.3.4 X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
            fail( "Cannot add attributeType with bogus non-existant equality MatchingRule" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", false );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", false );

        // -------------------------------------------------------------------
        // test reject with non-existant ordering matchingRule
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 ORDERING 1.2.3.4 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 ORDERING 1.2.3.4 X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
            fail( "Cannot add attributeType with bogus non-existant ordering MatchingRule" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", false );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", false );

        // -------------------------------------------------------------------
        // test reject with non-existant substring matchingRule
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUBSTR 1.2.3.4 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUBSTR 1.2.3.4 X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
            fail( "Cannot add attributeType with bogus non-existant substrings MatchingRule" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", false );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", false );

        // -------------------------------------------------------------------
        // test success with valid superior, valid syntax but no name
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 2.5.4.41 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 2.5.4.41 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", true );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", true );

        // -------------------------------------------------------------------
        // test success with valid superior, valid syntax and names
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "attributeTypes" );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 NAME 'type0' " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 2.5.4.41 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 NAME ( 'type1' 'altName' ) " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 2.5.4.41 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", true );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", true );

        // -------------------------------------------------------------------
        // test success with everything
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "attributeTypes" );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 NAME 'type0' " +
                "OBSOLETE SUP 2.5.4.41 " +
                "EQUALITY caseExactIA5Match " +
                "ORDERING octetStringOrderingMatch " +
                "SUBSTR caseExactIA5SubstringsMatch COLLECTIVE " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 " +
                "SINGLE-VALUE USAGE userApplications X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 NAME ( 'type1' 'altName' ) " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 2.5.4.41 " +
                "NO-USER-MODIFICATION USAGE directoryOperation X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", true );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", true );

        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "attributeTypes" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "nis", false );
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "attributeTypes" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10000 NAME 'type0' " +
                "OBSOLETE SUP 2.5.4.41 " +
                "EQUALITY caseExactIA5Match " +
                "ORDERING octetStringOrderingMatch " +
                "SUBSTR caseExactIA5SubstringsMatch COLLECTIVE " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 " +
                "SINGLE-VALUE USAGE userApplications )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.2.10001 NAME ( 'type1' 'altName' ) " +
                "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SUP 2.5.4.41 " +
                "NO-USER-MODIFICATION USAGE directoryOperation )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "attributeTypes" );
        
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10000", "other", true );
        checkAttributeTypePresent( "1.3.6.1.4.1.18060.0.4.1.2.10001", "other", true );
    }

    
    /**
     * Tests the addition of a new attributeType via a modify ADD on the SSSE to disabled schema.
     */
    public void testAddAttributeTypeOnDisabledSchema() throws Exception
    {
        disableSchema( "nis" );
        LdapDN dn = new LdapDN( getSubschemaSubentryDN() );
        String substrate = "( 1.3.6.1.4.1.18060.0.4.0.2.10000 NAME ( 'bogus' 'bogusName' ) " +
            "DESC 'bogus description' SUP name SINGLE-VALUE X-SCHEMA 'nis' )";
        ModificationItemImpl[] mods = new ModificationItemImpl[1];
        mods[0] = new ModificationItemImpl( DirContext.ADD_ATTRIBUTE, 
            new AttributeImpl( "attributeTypes", substrate ) );
        
        rootDSE.modifyAttributes( dn, mods );
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "attributeTypes" );
        AttributeTypeDescription attributeTypeDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( "1.3.6.1.4.1.18060.0.4.0.2.10000" ) != -1 )
            {
                attributeTypeDescription = attributeTypeDescriptionSchemaParser.parseAttributeTypeDescription( desc );
                break;
            }
        }
        
        assertNull( attributeTypeDescription );

        attrs = null;
        attrs = schemaRoot.getAttributes( "m-oid=1.3.6.1.4.1.18060.0.4.0.2.10000,ou=attributeTypes,cn=nis" );
        assertNotNull( attrs );
        SchemaEntityFactory factory = new SchemaEntityFactory( registries );
        AttributeType at = factory.getAttributeType( attrs, registries, "nis" );
        assertEquals( "1.3.6.1.4.1.18060.0.4.0.2.10000", at.getOid() );
        assertEquals( "name", at.getSuperior().getName() );
        assertEquals( "bogus description", at.getDescription() );
        assertEquals( "bogus", at.getNames()[0] );
        assertEquals( "bogusName", at.getNames()[1] );
        assertEquals( true, at.isCanUserModify() );
        assertEquals( false, at.isCollective() );
        assertEquals( false, at.isObsolete() );
        assertEquals( true, at.isSingleValue() );
    }

    
    /**
     * Tests the addition of a new attributeType via a modify ADD on the SSSE to enabled schema.
     */
    public void testAddAttributeTypeOnEnabledSchema() throws Exception
    {
        enableSchema( "nis" );
        LdapDN dn = new LdapDN( getSubschemaSubentryDN() );
        String substrate = "( 1.3.6.1.4.1.18060.0.4.0.2.10000 NAME ( 'bogus' 'bogusName' ) " +
            "DESC 'bogus description' SUP name SINGLE-VALUE X-SCHEMA 'nis' )";
        ModificationItemImpl[] mods = new ModificationItemImpl[1];
        mods[0] = new ModificationItemImpl( DirContext.ADD_ATTRIBUTE, 
            new AttributeImpl( "attributeTypes", substrate ) );
        
        rootDSE.modifyAttributes( dn, mods );
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "attributeTypes" );
        AttributeTypeDescription attributeTypeDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( "1.3.6.1.4.1.18060.0.4.0.2.10000" ) != -1 )
            {
                attributeTypeDescription = attributeTypeDescriptionSchemaParser.parseAttributeTypeDescription( desc );
                break;
            }
        }
        
        assertNotNull( attributeTypeDescription );
        assertEquals( true, attributeTypeDescription.isSingleValued() );
        assertEquals( false, attributeTypeDescription.isCollective() );
        assertEquals( false, attributeTypeDescription.isObsolete() );
        assertEquals( true, attributeTypeDescription.isUserModifiable() );
        assertEquals( "bogus description", attributeTypeDescription.getDescription() );
        assertEquals( "bogus", attributeTypeDescription.getNames().get( 0 ) );
        assertEquals( "bogusName", attributeTypeDescription.getNames().get( 1 ) );
        assertEquals( "name", attributeTypeDescription.getSuperType() );
        
        attrs = null;
        attrs = schemaRoot.getAttributes( "m-oid=1.3.6.1.4.1.18060.0.4.0.2.10000,ou=attributeTypes,cn=nis" );
        assertNotNull( attrs );
        SchemaEntityFactory factory = new SchemaEntityFactory( registries );
        AttributeType at = factory.getAttributeType( attrs, registries, "nis" );
        assertEquals( "1.3.6.1.4.1.18060.0.4.0.2.10000", at.getOid() );
        assertEquals( "name", at.getSuperior().getName() );
        assertEquals( "bogus description", at.getDescription() );
        assertEquals( "bogus", at.getNames()[0] );
        assertEquals( "bogusName", at.getNames()[1] );
        assertEquals( true, at.isCanUserModify() );
        assertEquals( false, at.isCollective() );
        assertEquals( false, at.isObsolete() );
        assertEquals( true, at.isSingleValue() );
    }


    // -----------------------------------------------------------------------
    // ObjectClass Tests
    // -----------------------------------------------------------------------
    
    
    private void checkObjectClassPresent( String oid, String schemaName, boolean isPresent ) throws Exception
    {
        // -------------------------------------------------------------------
        // check first to see if it is present in the subschemaSubentry
        // -------------------------------------------------------------------
        
        Attributes attrs = getSubschemaSubentryAttributes();
        Attribute attrTypes = attrs.get( "objectClasses" );
        ObjectClassDescription objectClassDescription = null; 
        for ( int ii = 0; ii < attrTypes.size(); ii++ )
        {
            String desc = ( String ) attrTypes.get( ii );
            if ( desc.indexOf( oid ) != -1 )
            {
                objectClassDescription = objectClassDescriptionSchemaParser.parseObjectClassDescription( desc );
                break;
            }
        }
     
        if ( isPresent )
        {
            assertNotNull( objectClassDescription );
            assertEquals( oid, objectClassDescription.getNumericOid() );
        }
        else
        {
            assertNull( objectClassDescription );
        }

        // -------------------------------------------------------------------
        // check next to see if it is present in the schema partition
        // -------------------------------------------------------------------
        
        attrs = null;
        
        if ( isPresent )
        {
            attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=objectClasses,cn=" + schemaName );
            assertNotNull( attrs );
        }
        else
        {
            try
            {
                attrs = schemaRoot.getAttributes( "m-oid=" + oid + ",ou=objectClasses,cn=" + schemaName );
                fail( "should never get here" );
            }
            catch( NamingException e )
            {
            }
            assertNull( attrs );
        }
        
        // -------------------------------------------------------------------
        // check to see if it is present in the matchingRuleRegistry
        // -------------------------------------------------------------------
        
        if ( isPresent ) 
        { 
            assertTrue( registries.getObjectClassRegistry().hasObjectClass( oid ) );
        }
        else
        {
            assertFalse( registries.getObjectClassRegistry().hasObjectClass( oid ) );
        }
    }
    
    
    /**
     * Tests a number of modify add, remove and replace operation combinations for
     * objectClasses on the schema subentry.
     */
    public void testAddRemoveReplaceObjectClasses() throws Exception
    {
        enableSchema( "nis" );
        List<String> descriptions = new ArrayList<String>();

        // -------------------------------------------------------------------
        // test rejection with non-existant superclass
        // -------------------------------------------------------------------
        
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 SUP 1.2.3 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 SUP ( 1.2.3 $ 4.5.6 ) X-SCHEMA 'nis' )" );

        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
            fail( "Cannot add objectClass with bogus non-existant super" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );

        // -------------------------------------------------------------------
        // test add with existant superiors but no name and no desc
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "SUP 2.5.6.0 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "SUP 2.5.6.0 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add with existant superiors with names and no desc
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) SUP 2.5.6.0 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) SUP 2.5.6.0 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add with existant superiors with names and desc
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' SUP 2.5.6.0 X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' SUP 2.5.6.0 X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add with many existant superiors with names and desc
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' SUP ( 2.5.6.0 $ dynamicObject ) X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' SUP ( 2.5.6.0 $ domain ) X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test reject with non-existant attributeType in may list
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' SUP ( 2.5.6.0 $ dynamicObject ) " +
                "MAY ( blah0 $ cn ) X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' SUP ( 2.5.6.0 $ domain ) " +
                "MAY ( sn $ blah1 ) X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
            fail( "Cannot add objectClass with bogus non-existant attributeTypes" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );

        // -------------------------------------------------------------------
        // test reject with non-existant attributeType in must list
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' SUP ( 2.5.6.0 $ dynamicObject ) " +
                "MUST ( blah0 $ cn ) X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' SUP ( 2.5.6.0 $ domain ) " +
                "MUST ( sn $ blah1 ) X-SCHEMA 'nis' )" );
        
        try
        {
            modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
            fail( "Cannot add objectClass with bogus non-existant attributeTypes" );
        }
        catch( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );

        // -------------------------------------------------------------------
        // test add with valid attributeTypes in may list
        // -------------------------------------------------------------------

        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' SUP ( 2.5.6.0 $ dynamicObject ) " +
                "MAY ( sn $ cn ) X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' SUP ( 2.5.6.0 $ domain ) " +
                "MAY ( sn $ ou ) X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add with valid attributeTypes in must list
        // -------------------------------------------------------------------

        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' SUP ( 2.5.6.0 $ dynamicObject ) " +
                "MUST ( sn $ cn ) X-SCHEMA 'nis' )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' SUP ( 2.5.6.0 $ domain ) " +
                "MUST ( sn $ ou ) X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test add success full (with obsolete)
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
                "NAME ( 'blah0' 'altname0' ) DESC 'bogus' OBSOLETE SUP ( 2.5.6.0 $ dynamicObject ) STRUCTURAL " +
                "MUST ( sn $ cn ) " +
                "MAY ( sn $ ou ) " +
                "X-SCHEMA 'nis' ) " );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
                "NAME ( 'blah1' 'altname1' ) DESC 'bogus' OBSOLETE SUP ( 2.5.6.0 $ domain ) STRUCTURAL " +
                "MUST ( sn $ ou ) " +
                "MAY ( sn $ ou ) " +
                "X-SCHEMA 'nis' )" );
        
        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", true );

        // -------------------------------------------------------------------
        // test failure to replace
        // -------------------------------------------------------------------
        
        modify( DirContext.REMOVE_ATTRIBUTE, descriptions, "objectClasses" );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "nis", false );
        checkMatchingRulePresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "nis", false );
        
        try
        {
            modify( DirContext.REPLACE_ATTRIBUTE, descriptions, "objectClasses" );
            fail( "modify REPLACE operations should not be allowed" );
        }
        catch ( LdapOperationNotSupportedException e )
        {
            assertEquals( ResultCodeEnum.UNWILLING_TO_PERFORM, e.getResultCode() );
        }

        // -------------------------------------------------------------------
        // check add no schema info
        // -------------------------------------------------------------------
        
        descriptions.clear();
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10000 " +
            "NAME ( 'blah0' 'altname0' ) DESC 'bogus' OBSOLETE SUP ( 2.5.6.0 $ dynamicObject ) STRUCTURAL " +
            "MUST ( sn $ cn ) " +
            "MAY ( sn $ ou ) )" );
        descriptions.add( "( 1.3.6.1.4.1.18060.0.4.1.3.10001 " +
            "NAME ( 'blah1' 'altname1' ) DESC 'bogus' OBSOLETE SUP ( 2.5.6.0 $ domain ) STRUCTURAL " +
            "MUST ( sn $ ou ) " +
            "MAY ( sn $ ou ) )" );

        modify( DirContext.ADD_ATTRIBUTE, descriptions, "objectClasses" );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10000", "other", true );
        checkObjectClassPresent( "1.3.6.1.4.1.18060.0.4.1.3.10001", "other", true );
    }

    
    // -----------------------------------------------------------------------
    // Private Utility Methods 
    // -----------------------------------------------------------------------
    

    private void modify( int op, List<String> descriptions, String opAttr ) throws Exception
    {
        LdapDN dn = new LdapDN( getSubschemaSubentryDN() );
        Attribute attr = new AttributeImpl( opAttr );
        for ( String description : descriptions )
        {
            attr.add( description );
        }
        
        Attributes mods = new AttributesImpl();
        mods.put( attr );
        
        rootDSE.modifyAttributes( dn, op, mods );
    }
    
    
    private void enableSchema( String schemaName ) throws NamingException
    {
        // now enable the test schema
        ModificationItemImpl[] mods = new ModificationItemImpl[1];
        Attribute attr = new AttributeImpl( "m-disabled", "FALSE" );
        mods[0] = new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, attr );
        super.schemaRoot.modifyAttributes( "cn=" + schemaName, mods );
    }
    
    
    private void disableSchema( String schemaName ) throws NamingException
    {
        // now enable the test schema
        ModificationItemImpl[] mods = new ModificationItemImpl[1];
        Attribute attr = new AttributeImpl( "m-disabled", "TRUE" );
        mods[0] = new ModificationItemImpl( DirContext.REPLACE_ATTRIBUTE, attr );
        super.schemaRoot.modifyAttributes( "cn=" + schemaName, mods );
    }
    
    
    private String getByteCode( String resource ) throws IOException
    {
        InputStream in = getClass().getResourceAsStream( resource );
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        while ( in.available() > 0 )
        {
            out.write( in.read() );
        }
        
        return new String( Base64.encode( out.toByteArray() ) );
    }


    /**
     * Get's the subschemaSubentry attribute value from the rootDSE.
     * 
     * @return the subschemaSubentry distinguished name
     * @throws NamingException if there are problems accessing the RootDSE
     */
    private String getSubschemaSubentryDN() throws NamingException
    {
        SearchControls controls = new SearchControls();
        controls.setSearchScope( SearchControls.OBJECT_SCOPE );
        controls.setReturningAttributes( new String[]{ SUBSCHEMA_SUBENTRY } );
        
        NamingEnumeration<SearchResult> results = rootDSE.search( "", "(objectClass=*)", controls );
        SearchResult result = results.next();
        results.close();
        Attribute subschemaSubentry = result.getAttributes().get( SUBSCHEMA_SUBENTRY );
        return ( String ) subschemaSubentry.get();
    }

    
    /**
     * Gets the subschemaSubentry attributes for the global schema.
     * 
     * @return all operational attributes of the subschemaSubentry 
     * @throws NamingException if there are problems accessing this entry
     */
    private Attributes getSubschemaSubentryAttributes() throws NamingException
    {
        SearchControls controls = new SearchControls();
        controls.setSearchScope( SearchControls.OBJECT_SCOPE );
        controls.setReturningAttributes( new String[]{ "+", "*" } );
        
        NamingEnumeration<SearchResult> results = rootDSE.search( getSubschemaSubentryDN(), 
            "(objectClass=*)", controls );
        SearchResult result = results.next();
        results.close();
        return result.getAttributes();
    }
}
