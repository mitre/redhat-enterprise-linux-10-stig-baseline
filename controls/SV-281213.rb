control 'SV-281213' do
  title 'RHEL 10 must configure the use of the pam_faillock.so module in the "/etc/pam.d/password-auth" file.'
  desc 'If the pam_faillock.so module is not loaded, the system will not correctly lockout accounts to prevent password guessing attacks.'
  desc 'check', 'Verify RHEL 10 includes the pam_faillock.so module in the "/etc/pam.d/password-auth" file:

$ sudo grep pam_faillock.so /etc/pam.d/password-auth
auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so

If the pam_faillock.so module is not present in the "/etc/pam.d/password-auth" file with the "preauth" line listed before pam_unix.so, this is a finding.

If the system administrator can demonstrate that the required configuration is contained in a Pluggable Authentication Module (PAM) configuration file included or substacked from the "system-auth" file, this is not a finding.'
  desc 'fix', 'Configure RHEL 10 to include the use of the pam_faillock.so module in the "/etc/pam.d/password-auth" file. If PAM is managed with "authselect", enable the feature with the following command:

$ sudo authselect enable-feature with-faillock

Otherwise, add/modify the appropriate sections of the "/etc/pam.d/password-auth" file to match the following lines:

Note: The "preauth" line must be listed before pam_unix.so.

auth required pam_faillock.so preauth
auth required pam_faillock.so authfail
account required pam_faillock.so'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000021-GPOS-00005'
  tag satisfies: ['SRG-OS-000021-GPOS-00005', 'SRG-OS-000329-GPOS-00128']
  tag gid: 'V-281213'
  tag rid: 'SV-281213r1166591_rule'
  tag stig_id: 'RHEL-10-600610'
  tag fix_id: 'F-85679r1166590_fix'
  tag cci: ['CCI-000044']
  tag nist: ['AC-7 a']
  tag 'host'
  tag 'container'

  describe pam('/etc/pam.d/password-auth') do
    its('lines') { should match_pam_rule('auth required pam_faillock.so preauth') }
    its('lines') { should match_pam_rule('auth required pam_faillock.so authfail') }
    its('lines') { should match_pam_rule('account required pam_faillock.so') }
  end
end
