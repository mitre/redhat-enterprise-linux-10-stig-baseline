control 'SV-280983' do
  title 'RHEL 10 must have the "rsyslog" package installed.'
  desc 'The "rsyslogd" is a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support local and remote logging. Couple this utility with "gnutls" (which is a secure communications library implementing the Secure Sockets Layer [SSL], Transport Layer Security [TLS], and Datagram TLS [DTLS] protocols), to create a method to securely encrypt and off-load auditing.'
  desc 'check', 'Verify RHEL 10 has the "rsyslogd" package installed with the following command:

$ sudo dnf list --installed rsyslog
Installed Packages
rsyslog.x86_64                                        8.2412.0-1.el10                                         @AppStream

If the "rsyslogd" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "rsyslogd" package installed with the following command:

$ sudo dnf -y install rsyslogd'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag gid: 'V-280983'
  tag rid: 'SV-280983r1195368_rule'
  tag stig_id: 'RHEL-10-200640'
  tag fix_id: 'F-85449r1165303_fix'
  tag cci: ['CCI-000366', 'CCI-000154', 'CCI-001851']
  tag nist: ['CM-6 b', 'AU-6 (4)', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe package('rsyslog') do
      it { should be_installed }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
