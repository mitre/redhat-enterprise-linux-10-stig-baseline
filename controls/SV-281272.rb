control 'SV-281272' do
  title 'RHEL 10 must not have any ".shosts" files on the system.'
  desc 'The ".shosts" files are used to configure host-based authentication for individual users or the system via Secure Shell (SSH). Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify RHEL 10 does not have any ".shosts" files on the system with the following command:

$ sudo find / -name .shosts

If a ".shosts" file is found, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have any ".shosts" files on the system.

Remove any found ".shosts" files from the system with the following command:

$ sudo rm /[path]/[to]/[file]/.shosts'
  impact 0.5
  tag check_id: 'C-85833r1166766_chk'
  tag severity: 'medium'
  tag gid: 'V-281272'
  tag rid: 'SV-281272r1166768_rule'
  tag stig_id: 'RHEL-10-700690'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85738r1166767_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  shosts_files = command('find / -xdev -xautofs -name .shosts').stdout.strip.split("\n")

  describe 'The RHEL10 filesystem' do
    it 'should not have any .shosts files present' do
      expect(shosts_files).to be_empty, "Discovered .shosts files:\n\t- #{shosts_files.join("\n\t- ")}"
    end
  end
end
