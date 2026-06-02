control 'SV-281037' do
  title 'RHEL 10 must be configured so that system commands are owned by "root".'
  desc 'If RHEL 10 allowed any user to make changes to software libraries, those changes might be implemented without undergoing the appropriate testing and approvals that are part of a robust change management process.

This requirement applies to RHEL 10 with software libraries that are accessible and configurable, as in the case of interpreted languages. Software libraries also include privileged programs that execute with escalated privileges.'
  desc 'check', 'Verify RHEL 10 is configured so that the system commands contained in the following directories are owned by "root" with the following command:

$ sudo find -L /bin /sbin /usr/bin /usr/sbin /usr/libexec /usr/local/bin /usr/local/sbin ! -user root -exec stat -L -c "%U %n" {} \\;

If any system commands are found to not be owned by root, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the system commands are protected from unauthorized access.

Run the following command, replacing "[FILE]" with any system command file not owned by "root".

$ sudo chown root [FILE]'
  impact 0.5
  tag check_id: 'C-85598r1165464_chk'
  tag severity: 'medium'
  tag gid: 'V-281037'
  tag rid: 'SV-281037r1165466_rule'
  tag stig_id: 'RHEL-10-400100'
  tag gtitle: 'SRG-OS-000259-GPOS-00100'
  tag fix_id: 'F-85503r1165465_fix'
  tag 'documentable'
  tag cci: ['CCI-001499']
  tag nist: ['CM-5 (6)']
end
