control 'SV-281234' do
  title 'RHEL 10 must prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot/efi" directory.'
  desc 'The "nosuid" mount option causes the system not to execute "setuid" and "setgid" files with owner privileges. This option must be used for mounting any file system not containing approved "setuid" and "setguid" files. Executing files from untrusted file systems increases the opportunity for nonprivileged users to attain unauthorized administrative access.'
  desc 'check', %q(Note: For systems that use BIOS and for vfat systems, this requirement is not applicable.

Verify RHEL 10 is configured so that the "/boot/efi "directory is mounted with the "nosuid" option with the following command:

$ mount | grep '\s/boot/efi\s'
/dev/sda1 on /boot/efi type vfat (rw,nosuid,relatime,fmask=0077,dmask=0077,codepage=437,iocharset=ascii,shortname=winnt,errors=remount-ro)

If the "/boot/efi" file system does not have the "nosuid" option set, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to prevent files with the "setuid" and "setgid" bit set from being executed on the "/boot/efi" directory.

Modify "/etc/fstab" to use the "nosuid" option on the "/boot/efi" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /boot/efi'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-281234'
  tag rid: 'SV-281234r1166654_rule'
  tag stig_id: 'RHEL-10-700130'
  tag fix_id: 'F-85700r1166653_fix'
  tag cci: ['CCI-000366', 'CCI-001764', 'CCI-000213']
  tag nist: ['CM-6 b', 'CM-7 (2)', 'AC-3']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  boot_efi_path = input('boot_efi_mountpoint')
  boot_efi = mount(boot_efi_path)

  if boot_efi.mounted?
    if boot_efi.type == 'vfat'
      impact 0.0
      describe 'vfat filesystem detected on /boot/efi' do
        skip 'This control is Not Applicable for vfat file systems.'
      end
    else
      describe boot_efi do
        it { should be_mounted }
        its('options') { should include 'nosuid' }
      end
    end
  else
    impact 0.0
    describe 'System running BIOS' do
      skip 'The System is running a BIOS; this control is Not Applicable.'
    end
  end
end
