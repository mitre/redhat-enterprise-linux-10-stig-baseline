control 'SV-281318' do
  title 'RHEL 10 must disable storing core dumps.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers or system operators trying to debug problems. Enabling core dumps on production systems is not recommended; however, there may be overriding operational requirements to enable advanced debugging. Permitting temporary enablement of core dumps during such situations must be reviewed through local needs and policy.'
  desc 'check', %q(Note: If kernel dumps are disabled in accordance with RHEL-10-701090, this requirement is not applicable.

Verify RHEL 10 disables storing core dumps for all users by issuing the following command:

$ sudo grep -ir storage /etc/systemd/ | grep -v '#'
/etc/systemd/coredump.conf:Storage=none

If the "Storage" item is missing or the value is anything other than "none", and the need for core dumps is not documented with the information system security officer as an operational requirement for all domains that have the "core" item assigned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to disable storing core dumps for all users.

Create or edit the setting in a drop-in configuration file:

$ sudo vi /etc/systemd/coredump.conf

Add the following line:

Storage=none'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281318'
  tag rid: 'SV-281318r1167104_rule'
  tag stig_id: 'RHEL-10-701160'
  tag fix_id: 'F-85784r1167103_fix'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag legacy: []
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('storing_core_dumps_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe parse_config_file('/etc/systemd/coredump.conf') do
      its('Coredump.Storage') { should cmp 'none' }
    end
  end
end
