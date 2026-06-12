control 'SV-281290' do
  title 'RHEL 10 must disable wireless network adapters.'
  desc 'This requirement applies to wireless peripheral technologies (e.g., wireless mice, keyboards, displays, etc.) used with RHEL 10 systems. Wireless peripherals (e.g., Wi-Fi/Bluetooth/IR keyboards, mice and pointing devices, and near field communications [NFC]) present a unique challenge by creating an open, unsecured port on a computer. 

Wireless peripherals must meet DOD requirements for wireless data transmission and be approved for use by the authorizing official. Even though some wireless peripherals, such as mice and pointing devices, do not ordinarily carry information that must be protected, modification of communications with these wireless peripherals may be used to compromise the RHEL 10 operating system.

'
  desc 'check', 'Note: This requirement is not applicable for systems that do not have physical wireless network radios.

Verify RHEL 10 disables wireless interfaces on the system with the following command:

$ nmcli device status
DEVICE                    TYPE            STATE                    CONNECTION
virbr0                      bridge         connected             virbr0
wlp7s0                    wifi              connected            wifiSSID
enp6s0                    ethernet     disconnected        --
p2p-dev-wlp7s0     wifi-p2p     disconnected        --
lo                             loopback    unmanaged           --
virbr0-nic                tun              unmanaged          --

If a wireless interface is configured and has not been documented and approved by the information system security officer, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable all wireless network interfaces with the following command:

$ nmcli radio all off'
  impact 0.5
  tag check_id: 'C-85851r1166820_chk'
  tag severity: 'medium'
  tag gid: 'V-281290'
  tag rid: 'SV-281290r1166822_rule'
  tag stig_id: 'RHEL-10-700870'
  tag gtitle: 'SRG-OS-000299-GPOS-00117'
  tag fix_id: 'F-85756r1166821_fix'
  tag satisfies: ['SRG-OS-000299-GPOS-00117', 'SRG-OS-000300-GPOS-00118', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000481-GPOS-00481']
  tag 'documentable'
  tag cci: ['CCI-001444', 'CCI-001443', 'CCI-002421', 'CCI-002418']
  tag nist: ['AC-18 (1)', 'AC-18 (1)', 'SC-8 (1)', 'SC-8']

  if input('wifi_hardware')
    describe command('nmcli device') do
      its('stdout.strip') { should_not match(/wifi\s*connected/) }
    end
  else
    impact 0.0
    describe 'Skip' do
      skip 'The system does not have a wireless network adapter; this control is Not Applicable.'
    end
  end
end
