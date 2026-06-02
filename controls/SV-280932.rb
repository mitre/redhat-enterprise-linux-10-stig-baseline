control 'SV-280932' do
  title 'RHEL 10 must check the GNU Privacy Guard (GPG) signature of software packages originating from external software repositories before installation.'
  desc 'Changes to any software components can have significant effects on the overall security of the operating system. This requirement ensures the software has not been tampered with and has been provided by a trusted vendor.

All software packages must be signed with a cryptographic key recognized and approved by the organization.

Verifying the authenticity of software prior to installation validates the integrity of the software package received from a vendor.'
  desc 'check', 'Verify RHEL 10 dnf always checks the GPG signature of software packages originating from external software repositories before installation with the following command:

$ sudo grep -w gpgcheck /etc/dnf/dnf.conf
gpgcheck=1

If "gpgcheck" is not set to "1", or if the option is missing or commented out, ask the system administrator how the GPG signatures of software packages are being verified.

If no process to verify GPG signatures has been approved by the organization, this is a finding.'
  desc 'fix', 'Configure RHEL 10 dnf to always check the GPG signature of software packages originating from external software repositories before installation.

Add or update the following line in the [main] section of the "/etc/dnf/dnf.conf" file:

gpgcheck=1'
  impact 0.7
  tag check_id: 'C-85493r1197214_chk'
  tag severity: 'high'
  tag gid: 'V-280932'
  tag rid: 'SV-280932r1197215_rule'
  tag stig_id: 'RHEL-10-001030'
  tag gtitle: 'SRG-OS-000366-GPOS-00153'
  tag fix_id: 'F-85398r1165150_fix'
  tag 'documentable'
  tag cci: ['CCI-001749', 'CCI-003992']
  tag nist: ['CM-5 (3)', 'CM-14']
  tag 'host'
  tag 'container'

  describe 'DNF configuration should enforce GPG signature checking' do
    subject { parse_config_file('/etc/dnf/dnf.conf').params['main'] }
    its('gpgcheck') { should cmp 1 }
  end
end
