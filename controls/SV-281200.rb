control 'SV-281200' do
  title 'RHEL 10 must not allow blank or null passwords.'
  desc 'If an account has an empty password, anyone could log in and run commands with the privileges of that account. Accounts with empty passwords must never be used in operational environments.'
  desc 'check', 'Verify RHEL 10 prohibits the use of null passwords with the following command:

$ sudo grep -i nullok /etc/pam.d/system-auth /etc/pam.d/password-auth

If output is produced, this is a finding.

If the system administrator (SA) can demonstrate that the required configuration is contained in a PAM configuration file included or substacked from the "system-auth" file, this is not a finding.'
  desc 'fix', 'Configure RHEL 10 to prohibit the use of null passwords.

If PAM is managed with "authselect", use the following command to remove instances of "nullok":

$ sudo authselect enable-feature without-nullok

Otherwise, remove any instances of the "nullok" option in the "/etc/pam.d/password-auth" and "/etc/pam.d/system-auth" files to prevent logins with empty passwords.

Note: Manual changes to the listed file may be overwritten by the "authselect" program.'
  impact 0.5
  tag check_id: 'C-85761r1166550_chk'
  tag severity: 'medium'
  tag gid: 'V-281200'
  tag rid: 'SV-281200r1166552_rule'
  tag stig_id: 'RHEL-10-600455'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85666r1166551_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-004066']
  tag nist: ['CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  pam_auth_files = input('pam_auth_files')
  file_list = pam_auth_files.values.join(' ')
  bad_entries = command("grep -i nullok #{file_list}").stdout.lines.map(&:strip)

  describe 'The system should be configureed' do
    subject { command("grep -i nullok #{file_list}") }
    it 'to not allow null passwords' do
      expect(subject.stdout.strip).to be_empty, "The system is configured to allow null passwords. Remove any instances of the `nullok` option from auth files: \n\t- #{bad_entries.join("\n\t- ")}"
    end
  end
end
