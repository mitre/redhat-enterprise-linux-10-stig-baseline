control 'SV-281012' do
  title 'RHEL 10 must be configured so that Secure Shell (SSH) clients use only DOD-approved Message Authentication Codes (MACs) employing FIPS 140-3-validated cryptographic hash algorithms to protect the confidentiality of SSH client connections.'
  desc 'Without cryptographic integrity protections, information can be altered by unauthorized users without detection.

Remote access (e.g., Remote Desktop Protocol [RDP]) is access to DOD nonpublic information systems by an authorized user (or an information system) communicating through an external, nonorganizational-controlled network. Remote access methods include, for example, dial-up, broadband, and wireless.

Cryptographic mechanisms used for protecting the integrity of information include, for example, signed hash functions that use asymmetric cryptography. This enables distribution of the public key to verify the hash information while maintaining the confidentiality of the secret key used to generate the hash.

RHEL 10 incorporates systemwide crypto policies by default. The SSH configuration file has no effect on the ciphers, MACs, or algorithms unless specifically defined in the "/etc/sysconfig/sshd" file. The employed algorithms can be viewed in the "/etc/crypto-policies/back-ends/openssh.config" file.'
  desc 'check', 'Verify RHEL 10 SSH clients are configured to use only MACs employing FIPS 140-3-approved algorithms.

To verify the MACs in the systemwide SSH configuration file, use the following command:

$ sudo grep -i MACs /etc/crypto-policies/back-ends/openssh.config
MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512

If the MACs entries in the "openssh.config" file have any hashes other than "hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha2-256,hmac-sha2-512", or they are missing or commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 SSH clients to use only MACs employing FIPS 140-3-approved algorithms.

Reinstall crypto-policies with the following command:

$ sudo dnf -y reinstall crypto-policies

Set the crypto-policy to FIPS with the following command:

$ sudo update-crypto-policies --set FIPS
Setting system policy to FIPS

Note: Systemwide crypto policies are applied on application startup. It is recommended to restart the system for the change of policies to fully take place.'
  impact 0.7
  tag check_id: 'C-85573r1165389_chk'
  tag severity: 'high'
  tag gid: 'V-281012'
  tag rid: 'SV-281012r1184645_rule'
  tag stig_id: 'RHEL-10-300050'
  tag gtitle: 'SRG-OS-000125-GPOS-00065'
  tag fix_id: 'F-85478r1165390_fix'
  tag 'documentable'
  tag cci: ['CCI-001453', 'CCI-000877']
  tag nist: ['AC-17 (2)', 'MA-4 c']

  only_if('Control not applicable - SSH is not installed within containerized RHEL', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  describe file('/etc/crypto-policies/back-ends/openssh.config') do
    it { should exist }
    its('content') { should match(/^MACs\s+hmac-sha2-256-etm@openssh\.com,hmac-sha2-512-etm@openssh\.com,hmac-sha2-256,hmac-sha2-512$/) }
  end
end
