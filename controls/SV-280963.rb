control 'SV-280963' do
  title 'RHEL 10 must have the USBGuard package enabled.'
  desc 'The USBGuard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the "usbguard-rules.conf" file. The policy and the authorization state of USB devices can be modified during runtime using the USBGuard tool.

The system administrator (SA) must work with the site information system security officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.'
  desc 'check', 'Note: If the system is virtual machine with no virtual or physical USB peripherals attached, this is not applicable.

Verify RHEL 10 has USBGuard enabled with the following command:

$ systemctl is-active usbguard
active

If USBGuard is not active, ask the SA to indicate how unauthorized peripherals are being blocked.

If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the USBGuard service enabled by running the following command:

$ sudo systemctl enable --now usbguard'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag gid: 'V-280963'
  tag rid: 'SV-280963r1165244_rule'
  tag stig_id: 'RHEL-10-200561'
  tag fix_id: 'F-85429r1165243_fix'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']
  tag 'host'

  only_if('This requirement does not apply to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  peripherals_service = input('peripherals_service')

  describe service(peripherals_service) do
    it "is expected to be running. \n\tConfigure the service to ensure your devices function as expected." do
      expect(subject.running?).to be(true), "The #{peripherals_service} service is not running"
    end
    it "is expected to be enabled. \n\tConfigure the service to ensure your devices function as expected." do
      expect(subject.enabled?).to be(true), "The #{peripherals_service} service is not enabled"
    end
  end
end
