control 'SV-281039' do
  title 'RHEL 10 must be configured so that library files are owned by "root".'
  desc 'If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify RHEL 10 is configured so that the systemwide shared library files are owned by "root" with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 ! -user root ! -type d -exec stat -L -c "%U %n" {} \\;

If any systemwide shared library file is not owned by root, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the systemwide shared library files (/lib, /lib64, /usr/lib, and /usr/lib64) are protected from unauthorized access.

Run the following command, replacing "[FILE]" with any library file not owned by "root".

$ sudo chown root [FILE]'
  impact 0.5
  tag check_id: 'C-85600r1165470_chk'
  tag severity: 'medium'
  tag gid: 'V-281039'
  tag rid: 'SV-281039r1165472_rule'
  tag stig_id: 'RHEL-10-400110'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85505r1165471_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']

  failing_files = command("find -L #{input('system_libraries').join(' ')} -type f -name '*.so*' -perm /0022 -exec ls -d {} \\;").stdout.split("\n")

  describe 'System libraries' do
    it 'should be owned by root' do
      expect(failing_files).to be_empty, "Files not owned by root:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
