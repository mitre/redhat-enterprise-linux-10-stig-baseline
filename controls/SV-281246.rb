control 'SV-281246' do
  title 'RHEL 10 must mount "/var/tmp" with the "noexec" option.'
  desc 'The "noexec" mount option causes the system to not execute binary files. This option must be used for mounting any file system not containing approved binary files, as they may be incompatible. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify RHEL 10 is configured so that "/var/tmp" is mounted with the "noexec" option:

$ mount | grep /var/tmp
/dev/mapper/luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)

If the "/var/tmp" file system is mounted without the "noexec" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/var/tmp" with the "noexec" option.

Modify "/etc/fstab" to use the "noexec" option on the "/var/tmp" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /var/tmp'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281246'
  tag rid: 'SV-281246r1166690_rule'
  tag stig_id: 'RHEL-10-700190'
  tag fix_id: 'F-85712r1166689_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/var/tmp'
  option = 'noexec'

  describe mount(path) do
    its('options') { should include option }
  end

  describe etc_fstab.where { mount_point == path } do
    its('mount_options.flatten') { should include option }
  end
end
