control 'SV-281038' do
  title 'RHEL 10 must be configured so that system commands are group-owned by root or a system account.'
  desc 'If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify RHEL 10 is configured so that the system commands contained in the following directories are group-owned by "root", or a required system account, with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -group root -exec stat -L -c "%G %n" {} \\;

If any system commands are returned and are not group-owned by "root" or a required system account, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the system commands are protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command file not group-owned by "root" or a required system account.

$ sudo chgrp root [FILE]'
  impact 0.5
  tag check_id: 'C-85599r1184671_chk'
  tag severity: 'medium'
  tag gid: 'V-281038'
  tag rid: 'SV-281038r1184683_rule'
  tag stig_id: 'RHEL-10-400105'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85504r1165468_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  required_system_account_caveats = input('required_system_accounts').map { |acct| "-group #{acct}" }.join(' ')

  failing_files = command("find -L #{input('system_command_dirs').join(' ')} ! #{required_system_account_caveats} -exec ls -d {} \\;").stdout.split("\n")

  describe 'System commands' do
    it 'should be group-owned by root' do
      expect(failing_files).to be_empty, "Files not group-owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
