control 'SV-280938' do
  title 'RHEL 10 must use a separate file system for "/tmp".'
  desc 'The "/tmp" partition is used as temporary storage by many programs. Placing "/tmp" in its own partition enables the setting of more restrictive mount options, which can help protect programs that use it.'
  desc 'check', 'Verify RHEL 10 uses a separate file system/partition for "/tmp" with the following command:

$ mount | grep /tmp
/dev/mapper/luks-2d7e1b45-73c4-4282-8838-15a897e0d04e on /tmp type xfs(rw,nodev,nosuid,noexec,seclabel)

Note: Options displayed for mount may differ.

If a separate entry for "/tmp" is not in use, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use a separate file system for temporary storage directories by migrating the "/tmp" path onto a separate file system.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag gid: 'V-280938'
  tag rid: 'SV-280938r1184728_rule'
  tag stig_id: 'RHEL-10-000540'
  tag fix_id: 'F-85404r1165168_fix'
  tag cci: ['CCI-000366', 'CCI-002385']
  tag nist: ['CM-6 b', 'SC-5 a']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe mount('/tmp') do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == '/tmp' } do
    it { should exist }
  end
end
