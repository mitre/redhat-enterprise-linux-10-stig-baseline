control 'SV-281300' do
  title 'RHEL 10 must disable the ability of systemd to spawn an interactive boot process.'
  desc 'Using interactive or recovery boot, the console user could disable auditing, firewalls, or other services, weakening system security.'
  desc 'check', "Verify RHEL 10 is configured so that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --info=ALL | grep args | grep 'systemd.confirm_spawn'

If any output is returned, this is a finding."
  desc 'fix', 'Configure RHEL 10 so that the current GRUB 2 configuration disables the ability of systemd to spawn an interactive boot process with the following command:

$ sudo grubby --update-kernel=ALL --remove-args="systemd.confirm_spawn"'
  impact 0.5
  tag check_id: 'C-85861r1167048_chk'
  tag severity: 'medium'
  tag gid: 'V-281300'
  tag rid: 'SV-281300r1167050_rule'
  tag stig_id: 'RHEL-10-700980'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85766r1167049_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  grubby = command('grubby --info=ALL').stdout

  describe parse_config(grubby) do
    its('args') { should_not include 'systemd.confirm_spawn' }
  end
end
