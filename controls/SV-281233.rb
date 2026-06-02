control 'SV-281233' do
  title 'RHEL 10 must prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot" directory.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Verify RHEL 10 is configured so that the "/boot" directory is mounted with the "nosuid" option with the following command:

$ mount | grep '\s/boot\s'
/dev/sda1 on /boot type xfs (rw,nodev,nosuid,relatime,seclabel,attr2)

If the "/boot" file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot" directory.

Modify "/etc/fstab" to use the "nosuid" option on the "/boot" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /boot'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag gid: 'V-281233'
  tag rid: 'SV-281233r1166651_rule'
  tag stig_id: 'RHEL-10-700125'
  tag fix_id: 'F-85699r1166650_fix'
  tag cci: ['CCI-000366', 'CCI-001764']
  tag nist: ['CM-6 b', 'CM-7 (2)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe mount('/boot') do
    it { should be_mounted }
    its('options') { should include 'nosuid' }
  end
end
