control 'SV-281176' do
  title 'RHEL 10 must be configured so that all local interactive user initialization file executable search path statements do not contain statements that will reference a working directory other than user home directories.'
  desc "The executable search path (typically the PATH environment variable) contains a list of directories for the shell to search to find executables. If this path includes the current working directory (other than the user's home directory), executables in these directories may be executed instead of system commands.

This variable is formatted as a colon-separated list of directories. If there is an empty entry, such as a leading or trailing colon or two consecutive colons, this is interpreted as the current working directory. If deviations from the default system search path for the local interactive user are required, they must be documented with the information system security officer (ISSO)."
  desc 'check', 'Verify RHEL 10 local interactive user initialization file executable search path statements do not contain statements that will reference a working directory other than user home directories with the following commands:

$ sudo find /home -maxdepth 2 -type f -name ".[^.]*" -exec grep -iH path= {} \\;
PATH="$HOME/.local/bin:$HOME/bin:$PATH"

If any local interactive user initialization files have executable search path statements that include directories outside of their home directory, and this is not documented with the ISSO as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that all local interactive user initialization file executable search path statements do not contain statements that will reference a working directory other than user home directories.

Edit the local interactive user initialization files to change any PATH variable statements that reference directories other than their home directory.

If a local interactive user requires path variables to reference a directory owned by the application, it must be documented with the ISSO.'
  impact 0.5
  tag check_id: 'C-85737r1166478_chk'
  tag severity: 'medium'
  tag gid: 'V-281176'
  tag rid: 'SV-281176r1166480_rule'
  tag stig_id: 'RHEL-10-600170'
  tag gtitle: 'SRG-OS-000362-GPOS-00149'
  tag fix_id: 'F-85642r1166479_fix'
  tag 'documentable'
  tag cci: ['CCI-003980']
  tag nist: ['CM-11 (2)']
end
