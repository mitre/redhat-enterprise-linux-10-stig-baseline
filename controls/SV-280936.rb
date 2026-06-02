control 'SV-280936' do
  title 'RHEL 10 must use a separate file system for the system audit data path.'
  desc 'Placing "/var/log/audit" in its own partition enables better separation between audit files and other system files and helps ensure that auditing cannot be halted due to the partition running out of space.'
  desc 'check', 'Verify RHEL 10 uses a separate file system/partition for the system audit data path with the following command:

Note: /var/log/audit is used as the example as it is a common location.

$ mount | grep /var/log/audit
/dev/mapper/rootvg-varlogaudit on /var/log/audit type xfs (rw,relatime,seclabel,attr2,inode64,logbufs=8,logbsize=32k,noquota)
Note: Options displayed for mount may differ.

If no line is returned, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to use a separate file system for the system audit data path by migrating "/var/log/audit" onto a separate file system.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-280936'
  tag rid: 'SV-280936r1184726_rule'
  tag stig_id: 'RHEL-10-000520'
  tag fix_id: 'F-85402r1165162_fix'
  tag cci: ['CCI-000366', 'CCI-001849']
  tag nist: ['CM-6 b', 'AU-4']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_data_path = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe mount(audit_data_path) do
    it { should be_mounted }
  end

  describe etc_fstab.where { mount_point == audit_data_path } do
    it { should exist }
  end
end
