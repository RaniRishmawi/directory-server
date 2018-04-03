package org.apache.directory.server.vgalpartition;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.naming.InvalidNameException;

import org.apache.directory.api.ldap.model.constants.SchemaConstants;
import org.apache.directory.api.ldap.model.cursor.ListCursor;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.exception.LdapException;
import org.apache.directory.api.ldap.model.filter.ExprNode;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.api.ldap.model.name.Dn;
import org.apache.directory.api.ldap.model.name.Rdn;
import org.apache.directory.server.core.api.LdapPrincipal;
import org.apache.directory.server.core.api.entry.ClonedServerEntry;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursor;
import org.apache.directory.server.core.api.filtering.EntryFilteringCursorImpl;
import org.apache.directory.server.core.api.interceptor.context.AddOperationContext;
import org.apache.directory.server.core.api.interceptor.context.DeleteOperationContext;
import org.apache.directory.server.core.api.interceptor.context.HasEntryOperationContext;
import org.apache.directory.server.core.api.interceptor.context.LookupOperationContext;
import org.apache.directory.server.core.api.interceptor.context.ModifyOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveAndRenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.MoveOperationContext;
import org.apache.directory.server.core.api.interceptor.context.RenameOperationContext;
import org.apache.directory.server.core.api.interceptor.context.SearchOperationContext;
import org.apache.directory.server.core.api.interceptor.context.UnbindOperationContext;
import org.apache.directory.server.core.api.partition.AbstractPartition;
import org.apache.directory.server.core.api.partition.Subordinates;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import zeva.vgalproxy.api.VgalCertificate;
import zeva.vgalproxy.api.VgalProxy;

/**
 * A read-only partition that communicates with VGAL service and gets
 * Certificates mapping them into LDAP entries.
 * 
 * TODO: consider extending AbstractLdifPartition instead TODO: clean up the
 * messy search method
 */
public class ReadOnlyVGALPartition extends AbstractPartition {

	private static final Logger LOG = LoggerFactory.getLogger(ReadOnlyVGALPartition.class);

	private VgalProxy vgalService;
	private IEmailValidator emailValidator;
	private IFilterEmailExtractor filterEmailExtractor;
	private ICertificateToPkcs7Convertor certificateToPkcs7Convertor;

	public ReadOnlyVGALPartition(VgalProxy vgalService, 
			IFilterEmailExtractor filterEmailExtractor,
			IEmailValidator emailValidator,
			ICertificateToPkcs7Convertor certificateToPkcs7Convertor) {
		this.vgalService = vgalService;
		this.emailValidator = emailValidator;
		this.filterEmailExtractor = filterEmailExtractor;
		this.certificateToPkcs7Convertor = certificateToPkcs7Convertor;
	}

	public EntryFilteringCursor search(SearchOperationContext searchContext) throws LdapException {

		LOG.info("Start search for record in vgal...");

		List<Entry> orgList = new ArrayList<Entry>();

		LdapPrincipal effectiveUser = searchContext.getSession().getEffectivePrincipal();

		String effectiveUserEmail = effectiveUser.getCertificateEmail();

		Dn dn = searchContext.getDn();

		SearchScope scope = searchContext.getScope();

		Dn suffixDn = getSuffixDn();

		if (dn != null) {
			if (dn.equals(suffixDn)) {

				LOG.info("Processing get record request...");

				ExprNode filter = searchContext.getFilter();

				String email = filterEmailExtractor.Extract(filter);

				if (email == null || !emailValidator.validate(email)) {
					LOG.warn("Cannot process request because email is invalid : " + email);
					return new EntryFilteringCursorImpl(new ListCursor<Entry>(orgList), searchContext, schemaManager);
				}

				if (scope.equals(SearchScope.ONELEVEL) || scope.equals(SearchScope.SUBTREE)) {

					VgalCertificate[] vgalCertificates = null;
					try {
						// just to make sure it does exist in VGAL
						vgalCertificates = vgalService.SearchByEmail(email,
								effectiveUserEmail == null ? "" : effectiveUserEmail);
					} catch (Exception ex) {
						LOG.error("Cannot retrieve record from vgal by email " + ex.getMessage());
						return new EntryFilteringCursorImpl(new ListCursor<Entry>(orgList), searchContext,
								schemaManager);
					}

					if (vgalCertificates != null && vgalCertificates.length > 0) {

						Entry e = new DefaultEntry(schemaManager, new Dn(new Rdn("mail", email), dn));
						addObjectClassesToEntry(e);
						e.add(SchemaConstants.CN_AT, email);
						e.add(SchemaConstants.SN_AT, email);
						e.add("mail", email);

						orgList.add(new ClonedServerEntry(e));
					}
				}
			} else if (suffixDn.equals(dn.getParent())) {

				LOG.info("Processing get details request...");

				Rdn rdn = dn.getRdn();

				String email = (String) rdn.getValue("mail");

				VgalCertificate[] vgalCertificates = null;
				try {
					vgalCertificates = vgalService.SearchByEmail(email,
							effectiveUserEmail == null ? "" : effectiveUserEmail);
				} catch (Exception ex) {
					LOG.error("Cannot retrieve record from vgal by email " + ex.getMessage());
					return new EntryFilteringCursorImpl(new ListCursor<Entry>(orgList), searchContext, schemaManager);
				}

				if (email == null || !emailValidator.validate(email)) {
					LOG.warn("Cannot process request because email is invalid : " + email);
					return new EntryFilteringCursorImpl(new ListCursor<Entry>(orgList), searchContext, schemaManager);
				}

				if (scope.equals(SearchScope.OBJECT) || scope.equals(SearchScope.SUBTREE)) {

					Entry e = new DefaultEntry(schemaManager, dn);
					addObjectClassesToEntry(e);
					e.add(SchemaConstants.CN_AT, email);
					e.add(SchemaConstants.SN_AT, email);
					e.add("mail", email);

					if (vgalCertificates != null && vgalCertificates.length > 0) {

						LOG.info("Received at least one certificate from vgal.");

						e.add(SchemaConstants.USER_CERTIFICATE_AT, vgalCertificates[0].getData());
						
						byte[] smimeCertificate;
						try {
							
							smimeCertificate =certificateToPkcs7Convertor.convert(vgalCertificates[0].getData());
							
							e.add(SchemaConstants.USER_SMIME_CERTIFICATE_AT, smimeCertificate);
							
						} catch (Exception ex) {
							// OK. but this means that certificate with Smime capabilities will not work on clients.
							LOG.warn("Error converting certificate to Pkcs7 format. " + ex.getMessage());
						}
					}

					orgList.add(new ClonedServerEntry(e));
				}
			}
		}

		return new EntryFilteringCursorImpl(new ListCursor<Entry>(orgList), searchContext, schemaManager);
	}
	
	private void addObjectClassesToEntry(Entry e) throws LdapException {
		e.add("objectClass", "top");
		e.add("objectClass", "inetOrgPerson");
		e.add("objectClass", "organizationalPerson");
		e.add("objectClass", "Person");
		e.add("objectClass", "pkiUser");
	}

	public void sync() throws Exception {
	}

	public Entry delete(DeleteOperationContext deleteContext) throws LdapException {
		return null;
	}

	public void add(AddOperationContext addContext) throws LdapException {
	}

	public void modify(ModifyOperationContext modifyContext) throws LdapException {
	}

	public Entry lookup(LookupOperationContext lookupContext) throws LdapException {

		Dn dn = lookupContext.getDn();
		Entry e = new DefaultEntry(schemaManager, new Dn(new Rdn("ou", "zeva"), dn));
		e.add("objectClass", "top");
		e.add("objectClass", "organizationalUnit");
		e.add("ou", "zeva");
		e.add(SchemaConstants.USER_PASSWORD_AT, "secret");

		return new ClonedServerEntry(e);
	}

	public boolean hasEntry(HasEntryOperationContext hasEntryContext) throws LdapException {
		return false;
	}

	public void rename(RenameOperationContext renameContext) throws LdapException {
	}

	public void move(MoveOperationContext moveContext) throws LdapException {
	}

	public void moveAndRename(MoveAndRenameOperationContext moveAndRenameContext) throws LdapException {
	}

	public void unbind(UnbindOperationContext unbindContext) throws LdapException {
	}

	public void saveContextCsn() throws Exception {
	}

	public Subordinates getSubordinates(Entry entry) throws LdapException {
		return new Subordinates();
	}

	@Override
	protected void doDestroy() throws Exception {
	}

	@Override
	protected void doInit() throws InvalidNameException, Exception {
	}

	@Override
	protected void doRepair() throws InvalidNameException, Exception {
	}

	public String toString() {
		return "Partition<" + id + ">";
	}
}