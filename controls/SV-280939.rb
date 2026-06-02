control 'SV-280939' do
  title 'RHEL 10 must use a separate file system for "/var".'
  desc 'Ensuring that "/var" is mounted on its own partition enables the setting of more restrictive mount options. This helps protect system services such as daemons or other programs that use it. It is not uncommon for the "/var" directory to contain world-writable directories installed by other software packages.'
  desc 'check', 'Verify RHEL 10 uses a separate file system/partition for "/var" with the following command:

$ mount | grep /var
/dev/mapper/luks-51150299-f295-4145-b8f0-ebe9c6dfd5a0 on /var type xfs (rw,nodev,relatime,seclabel,attr2)
Note: Options displayed for mount may differ.

If a separate entry for "/var" is not in use, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use a separate file system for the "/var" directory by migrating the "/var" path onto a separate file system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-280939'
  tag rid: 'SV-280939r1184729_rule'
  tag stig_id: 'RHEL-10-000550'
  tag fix_id: 'F-85405r1165171_fix'
  tag cci: ['CCI-000366', 'CCI-002385']
  tag nist: ['CM-6 b', 'SC-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe mount('/var') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/var' } do
    it { should exist }
  end
end
