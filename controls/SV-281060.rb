control 'SV-281060' do
  title 'RHEL 10 must enforce mode "755" or less permissive for library files.'
  desc 'If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify RHEL 10 is configured so that the systemwide shared library files contained in the following directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type f -exec ls -l {} \\;

If any systemwide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the library files are protected from unauthorized access. Run the following command, replacing "[FILE]" with any library file with a mode more permissive than "755".

$ sudo chmod 755 [FILE]'
  impact 0.5
  tag check_id: 'C-85621r1165533_chk'
  tag severity: 'medium'
  tag gid: 'V-281060'
  tag rid: 'SV-281060r1165535_rule'
  tag stig_id: 'RHEL-10-400215'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85526r1165534_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
