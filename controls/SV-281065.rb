control 'SV-281065' do
  title 'RHEL 10 must enforce mode "0750" or less permissive for local interactive user home directories.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  desc 'check', %q(Verify RHEL 10 is configured so that the assigned home directory of all local interactive users has a mode of "0750" or less permissive with the following command:

Note: This may miss interactive users that have been assigned a privileged user identifier (UID). Evidence of interactive use may be obtained from a number of log files containing system login information.

$ stat -L -c '%a %n' $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd) 2>/dev/null
700 /home/disauser

If home directories referenced in "/etc/passwd" do not have a mode of "0750" or less permissive, this is a finding.)
  desc 'fix', %q(Configure RHEL 10 so that the mode of interactive user's home directories is set to "0750". 

To change the mode of a local interactive user's home directory, use the following command:

Note: The example will be for the user "disauser".

$ sudo chmod 0750 /home/disauser)
  impact 0.5
  tag check_id: 'C-85626r1165548_chk'
  tag severity: 'medium'
  tag gid: 'V-281065'
  tag rid: 'SV-281065r1165550_rule'
  tag stig_id: 'RHEL-10-400240'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85531r1165549_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
