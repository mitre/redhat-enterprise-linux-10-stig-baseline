control 'SV-281057' do
  title 'RHEL 10 must enforce root group ownership of the "/etc/audit/" directory.'
  desc 'The "/etc/audit/" directory contains files that ensure the proper auditing of command execution, privilege escalation, file manipulation, and more. Protection of this directory is critical for system security.'
  desc 'check', 'Verify RHEL 10 enforces root group ownership of the "/etc/audit/" directory with the following command:

$ sudo stat -c "%G %n" /etc/audit/
root /etc/audit/

If "/etc/audit/" does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the "/etc/audit/" directory is group-owned by "root" with the following command:

$ sudo chgrp root /etc/audit/'
  impact 0.5
  tag check_id: 'C-85618r1165524_chk'
  tag severity: 'medium'
  tag gid: 'V-281057'
  tag rid: 'SV-281057r1165526_rule'
  tag stig_id: 'RHEL-10-400200'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-85523r1165525_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']

  describe file('/etc/audit/') do
    it { should exist }
    its('group') { should cmp 'root' }
  end
end
