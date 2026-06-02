control 'SV-281091' do
  title 'RHEL 10 must mount "/var/log/audit" with the "nodev" option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify RHEL 10 is configured so that "/var/log/audit" is mounted with the "nodev" option:

$ mount | grep /var/log/audit
/dev/mapper/luks-4e45e1ad-5337-42c4-a19f-ee12ccc1d502 on /var/log/audit type xfs (rw,nodev,nosuid,noexec,seclabel)

If the "/var/log/audit" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/var/log/audit" with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/var/log/audit" directory.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281091'
  tag rid: 'SV-281091r1165628_rule'
  tag stig_id: 'RHEL-10-400400'
  tag fix_id: 'F-85557r1165627_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/var/log/audit'
  option = 'nodev'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
