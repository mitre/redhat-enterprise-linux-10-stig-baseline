control 'SV-280941' do
  title 'RHEL 10 must use a separate file system for "/var/tmp".'
  desc 'The "/var/tmp" partition is used as temporary storage by many programs. Placing "/var/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs that use it.'
  desc 'check', 'Verify RHEL 10 uses a separate file system/partition for "/var/tmp" with the following command:

$ mount | grep /var/tmp
/dev/mapper/luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)
Note: Options displayed for mount may differ.

If a separate entry for "/var/tmp" is not in use, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use a separate file system for the "/var/tmp" path by migrating "/var/tmp" onto a separate file system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-280941'
  tag rid: 'SV-280941r1184731_rule'
  tag stig_id: 'RHEL-10-000570'
  tag fix_id: 'F-85407r1165177_fix'
  tag cci: ['CCI-000366', 'CCI-002385']
  tag nist: ['CM-6 b', 'SC-5 a']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe mount('/var/tmp') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/var/tmp' } do
    it { should exist }
  end
end
