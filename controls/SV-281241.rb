control 'SV-281241' do
  title 'RHEL 10 must mount "/var" with the "nodev" option.'
  desc 'The "nodev" mount option causes the system to not interpret character or block special devices. Executing character or block special devices from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.

The only legitimate location for device files is the "/dev" directory located on the root partition, with the exception of chroot jails if implemented.'
  desc 'check', 'Verify RHEL 10 is configured so that "/var" is mounted with the "nodev" option:

$ mount | grep /var
/dev/mapper/luks-51150299-f295-4145-b8f0-ebe9c6dfd5a0 on /var type xfs (rw,nodev,relatime,seclabel,attr2)

If the "/var" file system is mounted without the "nodev" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/var" with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/var" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /var'
  impact 0.5
  tag check_id: 'C-85802r1166673_chk'
  tag severity: 'medium'
  tag gid: 'V-281241'
  tag rid: 'SV-281241r1166675_rule'
  tag stig_id: 'RHEL-10-700165'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85707r1166674_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/var'
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
