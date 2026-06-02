control 'SV-281288' do
  title 'RHEL 10 must be configured to disable USB mass storage.'
  desc 'USB mass storage permits easy introduction of unknown devices, thereby
facilitating malicious activity.'
  desc 'check', 'Verify RHEL 10 disables the ability to load the USB Storage kernel module with the following command:

$ sudo grep -rs usb-storage /etc/modprobe.conf /etc/modprobe.d/*
/etc/modprobe.d/usb-storage.conf:install usb-storage /bin/false
/etc/modprobe.d/usb-storage.conf:blacklist usb-storage

If the command does not return any output, or either line is commented out, and use of USB Storage is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to prevent the usb-storage kernel module from being loaded.

Add the following lines to the file "/etc/modprobe.d/usb-storage.conf" (or create "usb-storage.conf" if it does not exist):

$ sudo vi /etc/modprobe.d/usb-storage.conf

install usb-storage /bin/false
blacklist usb-storage'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000114-GPOS-00059'
  tag satisfies: ['SRG-OS-000114-GPOS-00059', 'SRG-OS-000378-GPOS-00163', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-281288'
  tag rid: 'SV-281288r1166816_rule'
  tag stig_id: 'RHEL-10-700850'
  tag fix_id: 'F-85754r1166815_fix'
  tag cci: ['CCI-000778', 'CCI-000366', 'CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-6 b', 'CM-7 (9) (b)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }
  if input('usb_storage_required') == true
    describe kernel_module('usb_storage') do
      it { should_not be_disabled }
      it { should_not be_blacklisted }
    end
  else
    describe kernel_module('usb_storage') do
      it { should be_disabled }
      it { should be_blacklisted }
    end
  end
end
