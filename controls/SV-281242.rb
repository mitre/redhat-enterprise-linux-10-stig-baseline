control 'SV-281242' do
  title 'RHEL 10 must mount "/var/log" with the "nodev" option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify RHEL 10 is configured so that "/var/log" is mounted with the "nodev" option:

$ mount | grep /var/log
/dev/mapper/luks-c651f493-9fdc-4c6e-a711-0a4f03149661 on /var/log type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)

If the "/var/log" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/var/log" with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/var/log" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /var/log'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281242'
  tag rid: 'SV-281242r1166678_rule'
  tag stig_id: 'RHEL-10-700170'
  tag fix_id: 'F-85708r1166677_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/var/log'
  option = 'nodev'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
