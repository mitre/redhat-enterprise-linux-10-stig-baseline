control 'SV-281095' do
  title 'RHEL 10 must prohibit local initialization files from executing world-writable programs.'
  desc 'If user startup files execute world-writable programs, especially in unprotected directories, they could be maliciously modified to destroy user files or otherwise compromise the system at the user level. If the system is compromised at the user level, it is easier to elevate privileges to eventually compromise the system at the root and network level.'
  desc 'check', 'Verify RHEL 10 local initialization files do not execute world-writable programs with the following command:

Note: The example will be for a system that is configured to create user home directories in the "/home" directory.

$ sudo find /home -perm -002 -type f -name ".[^.]*" -exec ls -ld {} \\;

If any local initialization files are found to reference world-writable files, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that local initialization files do not execute world-writable programs with the following command:

$ sudo chmod 0755 <file>'
  impact 0.5
  tag check_id: 'C-85656r1165638_chk'
  tag severity: 'medium'
  tag gid: 'V-281095'
  tag rid: 'SV-281095r1184678_rule'
  tag stig_id: 'RHEL-10-400500'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85561r1184677_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
