control 'SV-281049' do
  title "RHEL 10 must ensure that all local interactive user home directories are group-owned by the home directory owner's primary group."
  desc "If the group identifier (GID) of a local interactive user's home directory is not the same as the primary GID of the user, this would allow unauthorized access to the user's files. Users who share the same group may not be able to access files that they legitimately should be able to access.

"
  desc 'check', %q(Verify RHEL 10 interactive users' home directories are group-owned by the user's primary GID with the following command:

Note: This may miss local interactive users that have been assigned a privileged user identifier (UID). Evidence of interactive use may be obtained from several log files containing system login information. The returned directory "/home/disauser" is used as an example.

$ sudo ls -ld $(awk -F: '($3>=1000)&&($7 !~ /nologin/){print $6}' /etc/passwd)
drwxr-x--- 2 disauser admin 4096 Jun 5 12:41 disauser

Check the user's primary group with the following command:

$ sudo grep $(grep disauser /etc/passwd | awk -F: '{print $4}') /etc/group
admin:x:250:disauser,doduser,nsauser

If the user home directory referenced in "/etc/passwd" is not group-owned by that user's primary GID, this is a finding.)
  desc 'fix', %q(Configure RHEL 10 interactive users' home directories to be group-owned by the user's primary GID.

Change the group owner of a local interactive user's home directory to the group found in "/etc/passwd". To change the group owner of a local interactive user's home directory, use the following command:

Note: The example will be for the user "disauser", who has a home directory of "/home/disauser" and has a primary group of users.

$ sudo chgrp users /home/disauser)
  impact 0.5
  tag check_id: 'C-85610r1184784_chk'
  tag severity: 'medium'
  tag gid: 'V-281049'
  tag rid: 'SV-281049r1197223_rule'
  tag stig_id: 'RHEL-10-400160'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85515r1165501_fix'
  tag satisfies: ['SRG-OS-000080-GPOS-00048', 'SRG-OS-000420-GPOS-00186']
  tag 'documentable'
  tag cci: ['CCI-000213', 'CCI-002385']
  tag nist: ['AC-3', 'SC-5 a']
end
