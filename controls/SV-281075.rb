control 'SV-281075' do
  title 'RHEL 10 must be configured so that all local files and directories must have a valid owner.'
  desc 'Unowned files and directories may be unintentionally inherited if a user is assigned the same user identifier (UID) as the UID of the unowned files.'
  desc 'check', "Verify RHEL 10 is configured so that all local files and directories have a valid owner with the following command:

$ df --local -P | awk {'if (NR!=1) print $6'} | sudo xargs -I '{}' find '{}' -xdev -nouser

If any files on the system do not have an assigned owner, this is a finding."
  desc 'fix', 'Configure RHEL 10 so that all local files and directories must have a valid owner.

Either remove all files and directories that do not have a valid user from the system, or assign a valid user to all unowned files and directories on RHEL 10 with the "chown" command:

$ sudo chown <user> <file>'
  impact 0.5
  tag check_id: 'C-85636r1165578_chk'
  tag severity: 'medium'
  tag gid: 'V-281075'
  tag rid: 'SV-281075r1165580_rule'
  tag stig_id: 'RHEL-10-400290'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85541r1165579_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
