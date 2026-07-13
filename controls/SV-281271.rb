control 'SV-281271' do
  title 'RHEL 10 must not have a "shosts.equiv" file on the system.'
  desc 'The "shosts.equiv" files are used to configure host-based authentication for the system via Secure Shell (SSH). Host-based authentication is not sufficient for preventing unauthorized access to the system, as it does not require interactive identification and authentication of a connection request, or for the use of two-factor authentication.'
  desc 'check', 'Verify RHEL 10 does not have a "shosts.equiv" file on the system with the following command:

$ sudo find / -name shosts.equiv

If a "shosts.equiv" file is found, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to not have a "shosts.equiv" file on the system.

Remove any found "shosts.equiv" files from the system:

$ sudo rm /[path]/[to]/[file]/shosts.equiv'
  impact 0.5
  tag check_id: 'C-85832r1166763_chk'
  tag severity: 'medium'
  tag gid: 'V-281271'
  tag rid: 'SV-281271r1197244_rule'
  tag stig_id: 'RHEL-10-700680'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85737r1197243_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  shosts_files = command('find / -xdev -xautofs -name shosts.equiv').stdout.strip.split("\n")

  describe 'The filesystem' do
    it 'should not have any shosts.equiv files present' do
      expect(shosts_files).to be_empty, "Discovered shosts files:\n\t- #{shosts_files.join("\n\t- ")}"
    end
  end
end
