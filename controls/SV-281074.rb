control 'SV-281074' do
  title 'RHEL 10 must be configured so that all local files and directories have a valid group owner.'
  desc 'Files without a valid group owner may be unintentionally inherited if a group is assigned the same group identifier (GID) as the GID of the files without a valid group owner.'
  desc 'check', "Verify RHEL 10 is configured so that all local files and directories have a valid group with the following command:

$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nogroup

If any files on the system do not have an assigned group, this is a finding."
  desc 'fix', 'Configure RHEL 10 so that all local files and directories have a valid group owner.

Either remove all files and directories from RHEL 10 that do not have a valid group, or assign a valid group to all files and directories on the system with the "chgrp" command:

$ sudo chgrp <group> <file>'
  impact 0.5
  tag check_id: 'C-85635r1165575_chk'
  tag severity: 'medium'
  tag gid: 'V-281074'
  tag rid: 'SV-281074r1165577_rule'
  tag stig_id: 'RHEL-10-400285'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85540r1165576_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
