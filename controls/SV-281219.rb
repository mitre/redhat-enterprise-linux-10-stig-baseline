control 'SV-281219' do
  title 'RHEL 10 must be configured to use a FIPS 140-3-approved cryptographic hashing algorithm for system authentication by ensuring that the pam_unix.so module is configured in the "system-auth" file.'
  desc 'Unapproved mechanisms that are used for authentication to the cryptographic module are not verified and therefore cannot be relied on to provide confidentiality or integrity, and DOD data may be compromised.

RHEL 10 systems using encryption are required to use FIPS-compliant mechanisms for authenticating to cryptographic modules.

FIPS 140-3 is the current standard for validating that mechanisms used to access cryptographic modules use authentication that meets DOD requirements. This allows for Security Levels 1, 2, 3, or 4 for use on a general-purpose computing system.

'
  desc 'check', 'Verify RHEL 10 is configured to use a FIPS 140-3-approved cryptographic hashing algorithm in "/etc/pam.d/system-auth" via the pam_unix.so module with the following command:

$ sudo grep "^password.*pam_unix.so.*sha512" /etc/pam.d/system-auth
password sufficient pam_unix.so sha512

If "sha512" is missing, or the line is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use a FIPS 140-3-approved cryptographic hashing algorithm for system authentication in "/etc/pam.d/system-auth" via the "pam_unix.so" module.

Edit/modify the following line in the "/etc/pam.d/system-auth" file to include the sha512 option for pam_unix.so:

password sufficient pam_unix.so sha512'
  impact 0.5
  tag check_id: 'C-85780r1166607_chk'
  tag severity: 'medium'
  tag gid: 'V-281219'
  tag rid: 'SV-281219r1166609_rule'
  tag stig_id: 'RHEL-10-600710'
  tag gtitle: 'SRG-OS-000073-GPOS-00041'
  tag fix_id: 'F-85685r1166608_fix'
  tag satisfies: ['SRG-OS-000073-GPOS-00041', 'SRG-OS-000120-GPOS-00061']
  tag 'documentable'
  tag cci: ['CCI-004062', 'CCI-000803']
  tag nist: ['IA-5 (1) (d)', 'IA-7']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')

  if input('pam_config_included')
    impact 0.0
    describe 'N/A' do
      skip 'The required PAM configuration is included or substacked from system-auth; this control is Not Applicable'
    end
  else
    describe pam(pam_auth_files['system-auth']) do
      its('lines') { should match_pam_rule('password sufficient pam_unix.so sha512') }
    end
  end
end
