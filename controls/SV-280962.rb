control 'SV-280962' do
  title 'RHEL 10 must have the USBGuard package installed.'
  desc 'The USBGuard-daemon is the main component of the USBGuard software framework. It runs as a service in the background and enforces the USB device authorization policy for all USB devices. The policy is defined by a set of rules using a rule language described in the "usbguard-rules.conf" file. The policy and the authorization state of USB devices can be modified during runtime using the USBGuard tool.

The system administrator (SA) must work with the site information system security officer (ISSO) to determine a list of authorized peripherals and establish rules within the USBGuard software framework to allow only authorized devices.'
  desc 'check', 'Verify RHEL 10 has USBGuard installed on the operating system with the following command:

$ sudo dnf list --installed usbguard
Installed Packages
usbguard.x86_64                             1.1.3-6.el10                              @rhel-10-for-x86_64-appstream-rpms

If the USBGuard package is not installed, ask the SA to indicate how unauthorized peripherals are being blocked.

If there is no evidence that unauthorized peripherals are being blocked before establishing a connection, this is a finding.

If the system is a virtual machine with no virtual or physical USB peripherals attached, this is not a finding.'
  desc 'fix', 'Configure RHEL 10 to have the USBGuard package installed with the following command:

$ sudo dnf -y install usbguard

Enable the service to start on boot and then start it with the following commands:

$ sudo systemctl enable usbguard
$ sudo systemctl start usbguard

Verify the status of the service with the following command:

$ sudo systemctl status usbguard

Note: USBGuard must be configured to allow authorized devices once it is enabled on RHEL 10.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000378-GPOS-00163'
  tag gid: 'V-280962'
  tag rid: 'SV-280962r1195350_rule'
  tag stig_id: 'RHEL-10-200560'
  tag fix_id: 'F-85428r1165240_fix'
  tag cci: ['CCI-001958', 'CCI-003959']
  tag nist: ['IA-3', 'CM-7 (9) (b)']
  tag 'host'

  only_if('This requirement is Not Applicable in the container', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  peripherals_package = input('peripherals_package')

  describe package(peripherals_package) do
    it "is expected to be installed. \n\tConfigure the service to ensure your devices function as expected." do
      expect(subject.installed?).to be(true), "The #{peripherals_package} package is not installed"
    end
  end
end
