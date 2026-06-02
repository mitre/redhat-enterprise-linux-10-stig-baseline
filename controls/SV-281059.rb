control 'SV-281059' do
  title 'RHEL 10 must enforce mode "755" or less permissive on library directories.'
  desc 'If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify RHEL 10 is configured so that the systemwide shared library directories have mode "755" or less permissive with the following command:

$ sudo find -L /lib /lib64 /usr/lib /usr/lib64 -perm /022 -type d -exec ls -l {} \\;

If any systemwide shared library file is found to be group-writable or world-writable, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the systemwide shared library directories (/lib, /lib64, /usr/lib, and /usr/lib64) are protected from unauthorized access.

Run the following command, replacing "[DIRECTORY]" with any library directory with a mode more permissive than "755".

$ sudo chmod 755 [DIRECTORY]'
  impact 0.5
  tag check_id: 'C-85620r1165530_chk'
  tag severity: 'medium'
  tag gid: 'V-281059'
  tag rid: 'SV-281059r1165532_rule'
  tag stig_id: 'RHEL-10-400210'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85525r1165531_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
