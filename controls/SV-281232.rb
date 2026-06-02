control 'SV-281232' do
  title 'RHEL 10 must mount "/boot" with the "nodev" option.'
  desc 'The only legitimate location for device files is the "/dev" directory located on the root partition. The only exception to this is chroot jails.'
  desc 'check', %q(Verify RHEL 10 is configured so that the "/boot" mount point has the "nodev" option with the following command:

$ mount | grep '\s/boot\s'
/dev/sda1 on /boot type xfs (rw,nodev,nosuid,relatime,seclabel,attr2)

If the "/boot" file system does not have the "nodev" option set, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to mount "/boot" with the "nodev" option.

Modify "/etc/fstab" to use the "nodev" option on the "/boot" directory.

To reload all implicit mount units and update the dependency graph so that new options will apply correctly at next remount, run the following command:

$ sudo systemctl daemon-reload

Use the following command to apply the changes immediately without a reboot:

$ sudo mount -o remount /boot'
  impact 0.5
  tag check_id: 'C-85793r1166646_chk'
  tag severity: 'medium'
  tag gid: 'V-281232'
  tag rid: 'SV-281232r1166648_rule'
  tag stig_id: 'RHEL-10-700120'
  tag gtitle: 'SRG-OS-000368-GPOS-00154'
  tag fix_id: 'F-85698r1166647_fix'
  tag 'documentable'
  tag cci: ['CCI-001764']
  tag nist: ['CM-7 (2)']
  tag 'host'

  only_if('Control not applicable within a container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if file('/sys/firmware/efi').exist?
    impact 0.0
    describe 'System running UEFI' do
      skip 'The System is running UEFI; this control is Not Applicable.'
    end
  else
    describe mount('/boot') do
      it { should be_mounted }
      its('options') { should include 'nodev' }
    end
  end
end
