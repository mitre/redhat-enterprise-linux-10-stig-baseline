control 'SV-281063' do
  title 'RHEL 10 must be configured to prohibit modification of permissions for cron configuration files and directories from the operating system defaults.'
  desc 'If the permissions of cron configuration files or directories are modified from the operating system defaults, it may be possible for individuals to insert unauthorized cron jobs that perform unauthorized actions, including potentially escalating privileges.'
  desc 'check', %q(Verify RHEL 10 is configured so that the owner, group, and mode of cron configuration files and directories match the operating system defaults with the following command:

$ rpm --verify cronie crontabs | awk '! ($2 == "c" && $1 ~ /^.\..\.\.\.\..\./) {print $0}'

If the command returns any output, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to prohibit modification of permissions for cron configuration files and directories from the operating system defaults with the following commands:

$ sudo dnf reinstall cronie crontabs
$ rpm --setugids cronie crontabs
$ rpm --setperms cronie crontabs'
  impact 0.5
  tag check_id: 'C-85624r1195402_chk'
  tag severity: 'medium'
  tag gid: 'V-281063'
  tag rid: 'SV-281063r1195403_rule'
  tag stig_id: 'RHEL-10-400230'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85529r1165543_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
