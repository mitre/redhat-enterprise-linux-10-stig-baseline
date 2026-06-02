control 'SV-281317' do
  title 'RHEL 10 must disable core dump backtraces.'
  desc 'A core dump includes a memory image taken at the time the operating system terminates an application. The memory image could contain sensitive data and is generally useful only for developers or system operators trying to debug problems.

Enabling core dumps on production systems is not recommended; however, there may be overriding operational requirements to enable advanced debugging. Permitting temporary enablement of core dumps during such situations must be reviewed through local needs and policy.'
  desc 'check', %q(Note: If kernel dumps are disabled in accordance with RHEL-10-701090, this requirement is not applicable.

Verify RHEL 10 disables core dump backtraces by issuing the following command:

$ sudo grep -ir ProcessSizeMax /etc/systemd/ | grep -v '#'
/etc/systemd/coredump.conf:ProcessSizeMax=0

If the "ProcessSizeMax" item is missing or the value is anything other than "0", and the need for core dumps is not documented with the information system security officer as an operational requirement for all domains that have the "core" item assigned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to disable core dump backtraces.

Create or edit the setting in a drop-in configuration file:

$ sudo vi /etc/systemd/coredump.conf:

Add the following line:

ProcessSizeMax=0'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag gid: 'V-281317'
  tag rid: 'SV-281317r1167101_rule'
  tag stig_id: 'RHEL-10-701150'
  tag fix_id: 'F-85783r1167100_fix'
  tag cci: ['CCI-000366', 'CCI-000381']
  tag legacy: []
  tag nist: ['CM-6 b', 'CM-7 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('core_dumps_required')
    impact 0.0
    describe 'N/A' do
      skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
    end
  else

    describe parse_config_file('/etc/systemd/coredump.conf') do
      its('Coredump.ProcessSizeMax') { should cmp '0' }
    end
  end
end
