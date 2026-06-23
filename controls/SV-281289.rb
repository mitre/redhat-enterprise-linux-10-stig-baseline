control 'SV-281289' do
  title 'RHEL 10 must disable Bluetooth.'
  desc 'This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 10 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice and pointing devices, and near field communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. 

Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the authorizing official. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that must be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 10 operating system.

'
  desc 'check', 'Verify RHEL 10 disables the ability to load the Bluetooth kernel module with the following command:

$ sudo grep -rs bluetooth /etc/modprobe.conf /etc/modprobe.d/*
/etc/modprobe.d/bluetooth.conf:install bluetooth /bin/false
/etc/modprobe.d/bluetooth.conf:blacklist bluetooth

If the command does not return any output, or the lines are commented out, and use of Bluetooth is not documented with the information system security officer as an operational requirement, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable the Bluetooth adapter when not in use.

Add the following lines to the file "/etc/modprobe.d/bluetooth.conf" (or create "bluetooth.conf" if it does not exist):

$ sudo vi /etc/modprobe.d/bluetooth.conf

install bluetooth /bin/false
blacklist bluetooth

Reboot the system for the settings to take effect.'
  impact 0.5
  tag check_id: 'C-85850r1166817_chk'
  tag severity: 'medium'
  tag gid: 'V-281289'
  tag rid: 'SV-281289r1166819_rule'
  tag stig_id: 'RHEL-10-700860'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85755r1166818_fix'
  tag satisfies: ['SRG-OS-000095-GPOS-00049', 'SRG-OS-000300-GPOS-00118']
  tag 'documentable'
  tag cci: ['CCI-000381', 'CCI-001443']
  tag nist: ['CM-7 a', 'AC-18 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('bluetooth_installed')
    if input('bluetooth_required')
      impact 0.0
      describe 'N/A' do
        skip "Profile inputs indicate that this parameter's setting is a documented operational requirement"
      end
    else

      describe kernel_module('bluetooth') do
        it { should be_disabled }
        it { should be_blacklisted }
      end
    end
  else
    impact 0.0
    describe 'Device or operating system does not have a Bluetooth adapter installed' do
      skip 'If the device or operating system does not have a Bluetooth adapter installed, this requirement is not applicable.'
    end
  end
end
