control 'SV-281240' do
  title 'RHEL 10 must mount "/tmp" with the "nosuid" option.'
  desc 'The "nosuid" mount option causes the system to not execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', 'Verify RHEL 10 is configured so that "/tmp" is mounted with the "nosuid" option:

$ mount | grep /tmp
/dev/mapper/luks-c98555c8-0462-4b97-9afa-6db8c4bfee3b on /var/tmp type xfs (rw,nosuid,nodev,noexec,relatime,seclabel,attr2)

If the "/tmp" file system is mounted without the "nosuid" option, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to mount "/tmp" with the "nosuid" option.

Modify "/etc/fstab" to use the "nosuid" option on the "/tmp" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /tmp'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281240'
  tag rid: 'SV-281240r1166672_rule'
  tag stig_id: 'RHEL-10-700160'
  tag fix_id: 'F-85706r1166671_fix'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  path = '/tmp'
  option = 'nosuid'
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
