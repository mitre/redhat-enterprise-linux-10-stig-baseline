control 'SV-280989' do
  title 'RHEL 10 must encrypt, via the gtls driver, the transfer of audit records off-loaded onto a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 10 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the Secure Sockets Layer [SSL], Transport Layer Security [TLS], and Datagram TLS [DTLS] protocols) creates a method to securely encrypt and off-load auditing. When this utility is coupled with the omfwd module, it can use the ossl network stream driver, which leverages the OpenSSL library for Transport Layer Security (TLS) to securely encrypt and off-load auditing.'
  desc 'check', %q(Verify RHEL 10 explicitly defines a TLS driver (gtls or ossl) for encrypted rsyslog off-loading.

Search for an explicitly defined stream driver within "omfwd" action blocks with the following command:

$ sudo grep -rE 'StreamDriver\s*=\s*"(gtls|ossl)"' /etc/rsyslog.conf /etc/rsyslog.d/

If TLS-based "omfwd" forwarding is configured, but the command above returns no active configuration lines specifying either "gtls" or "ossl" within the action block, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to explicitly define a TLS driver for rsyslog to use for encrypting off-loaded audit records. The "ossl" driver is required for environments operating in FIPS mode.

Add the "streamdriver" parameter to the "omfwd" action rule in its configuration file (e.g., /etc/rsyslog.d/99-forwarding.conf).

Example:
action(
  type="omfwd"
  streamdriver="ossl"
  target="logserver.example.com"
  protocol="tcp"
  port="6514"
  tls="on"
)

After applying the configuration, restart the rsyslog service:
$ sudo systemctl restart rsyslog'
  impact 0.5
  tag check_id: 'C-85550r1195375_chk'
  tag severity: 'medium'
  tag gid: 'V-280989'
  tag rid: 'SV-280989r1197222_rule'
  tag stig_id: 'RHEL-10-200646'
  tag gtitle: 'SRG-OS-000342-GPOS-00133'
  tag fix_id: 'F-85455r1195376_fix'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224']
  tag 'documentable'
  tag cci: ['CCI-001851']
  tag nist: ['AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  streamdriver_check = command("grep -iEh 'StreamDriver[[:space:]]*=[[:space:]]*\"(gtls|ossl)\"' #{input('logging_conf_files').join(' ')} | grep -vE '^[[:space:]]*#'").stdout.strip

  describe 'Rsyslogd omfwd StreamDriver' do
    it 'should be set to gtls or ossl' do
      expect(streamdriver_check).to_not be_empty, 'StreamDriver set to gtls or ossl not found (or commented out) in conf file(s)'
    end
  end
end
