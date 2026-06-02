control 'SV-281028' do
  title 'RHEL 10 must be configured so that the "/etc/passwd-" file is group-owned by "root".'
  desc 'The "/etc/passwd-" file is a backup file of "/etc/passwd", and as such contains information about the users that are configured on the system. Protection of this file is critical for system security.'
  desc 'check', 'Verify RHEL 10 is configured so that the "/etc/passwd-" file is group-owned by "root" with the following command:

$ sudo stat -c "%G %n" /etc/passwd-
root /etc/passwd-

If the "/etc/passwd-" file does not have a group owner of "root", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the group of the "/etc/passwd-" file is set to "root" by running the following command:

$ sudo chgrp root /etc/passwd-'
  impact 0.5
  tag check_id: 'C-85589r1165437_chk'
  tag severity: 'medium'
  tag gid: 'V-281028'
  tag rid: 'SV-281028r1165439_rule'
  tag stig_id: 'RHEL-10-400055'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85494r1165438_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
