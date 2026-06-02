control 'SV-281238' do
  title 'RHEL 10 must mount "/tmp" with the "nodev" option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify RHEL 10 is configured so that "/tmp" is mounted with the "nodev" option:

$ mount | grep /tmp
/dev/mapper/luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)

If the "/tmp" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/tmp" with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/tmp" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /tmp'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281238'
  tag rid: 'SV-281238r1166666_rule'
  tag stig_id: 'RHEL-10-700150'
  tag fix_id: 'F-85704r1166665_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/tmp'
  option = 'nodev'
  mount_option_enabled = input('mount_tmp_options')[option]

  if mount_option_enabled
    describe mount(path) do
      its('options') { should include option }
    end

    describe etc_fstab.where { mount_point == path } do
      its('mount_options.flatten') { should include option }
    end
  else
    describe mount(path) do
      its('options') { should_not include option }
    end

    describe etc_fstab.where { mount_point == path } do
      its('mount_options.flatten') { should_not include option }
    end
  end
end
