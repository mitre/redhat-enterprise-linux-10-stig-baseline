control 'SV-281042' do
  title 'RHEL 10 must be configured so that library directories are group-owned by "root" or a system account.'
  desc 'If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify RHEL 10 is configured so that the systemwide shared library directories are group-owned by "root" or a system account with the following command:

$ sudo find /lib /lib64 /usr/lib /usr/lib64 ! -group root -type d -exec stat -c "%G %n" {} \\;

If any systemwide shared library directory is returned and is not group-owned by "root" or a required system account, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the systemwide shared library directories (/lib, /lib64, /usr/lib and /usr/lib64) are protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory not group-owned by "root".

$ sudo chgrp root [DIRECTORY]'
  impact 0.5
  tag check_id: 'C-85603r1184675_chk'
  tag severity: 'medium'
  tag gid: 'V-281042'
  tag rid: 'SV-281042r1184676_rule'
  tag stig_id: 'RHEL-10-400125'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85508r1165480_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
  tag 'host'
  tag 'container'

  non_root_owned_libs = input('system_libraries').filter { |lib|
    !input('required_system_accounts').include?(file(lib).group)
  }

  describe 'System libraries' do
    it 'should be owned by a required system account' do
      fail_msg = "Libs not group-owned by a system account:\n\t- #{non_root_owned_libs.join("\n\t- ")}"
      expect(non_root_owned_libs).to be_empty, fail_msg
    end
  end
end
