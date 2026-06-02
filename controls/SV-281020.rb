control 'SV-281020' do
  title 'RHEL 10 must be configured so that the "/etc/group-" file is group-owned by "root".'
  desc 'The "/etc/group-" file is a backup file of "/etc/group", and as such contains information regarding groups that are configured on the system. Protection of this file is important for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/group-" file is group-owned by "root" with the following command:

$ sudo stat -c "%G %n" /etc/group-
root /etc/group-

If the "/etc/group-" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group of the "/etc/group-" file is set to "root" by running the following command:

$ sudo chgrp root /etc/group-'
  impact 0.5
  tag check_id: 'C-85581r1165413_chk'
  tag severity: 'medium'
  tag gid: 'V-281020'
  tag rid: 'SV-281020r1165415_rule'
  tag stig_id: 'RHEL-10-400015'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85486r1165414_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
