control 'SV-281217' do
  title 'RHEL 10 must ensure that the pam_unix.so module is configured in the password-auth file to use a FIPS 140-3-approved cryptographic hashing algorithm for system authentication.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified; therefore, they cannot be relied on to provide confidentiality or integrity, and DOD data may be compromised.

RHEL 10 systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-3 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.'
  desc 'check', 'Verify RHEL 10 configures the pam_unix.so module to use sha512 in "/etc/pam.d/password-auth" with the following command:

$ sudo grep "^password.*pam_unix.so.*sha512" /etc/pam.d/password-auth
password sufficient pam_unix.so sha512

If "sha512" is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use the sha512 cryptographic hashing algorithm for local account passwords.

Edit/modify the following line in the "/etc/pam.d/password-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag gid: 'V-281217'
  tag rid: 'SV-281217r1195450_rule'
  tag stig_id: 'RHEL-10-600650'
  tag fix_id: 'F-85683r1195449_fix'
  tag cci: ['CCI-000803', 'CCI-000196', 'CCI-004062']
  tag nist: ['IA-7', 'IA-5 (1) (c)', 'IA-5 (1) (d)']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  if input('pam_config_included')
    impact 0.0
    describe 'N/A' do
      skip 'The required PAM configuration is included or substacked from system-auth; this control is Not Applicable'
    end
  else
    describe pam(pam_auth_files['password-auth']) do
      its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
    end
  end
end
