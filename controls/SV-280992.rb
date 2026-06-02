control 'SV-280992' do
  title 'RHEL 10 must have the packages required for encrypting off-loaded audit logs installed.'
  desc 'The "rsyslog-gnutls" package provides Transport Layer Security (TLS) support for the rsyslog daemon, which enables secure remote logging.'
  desc 'check', 'Verify RHEL 10 has the "rsyslog-gnutls" package installed with the following command:

$ sudo dnf list --installed rsyslog-gnutls
Installed Packages
rsyslog-gnutls.x86_64                                     8.2412.0-1.el10                                     @AppStream

If the "rsyslog-gnutls" package is not installed, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have the "rsyslog-gnutls" package installed with the following command:

$ sudo dnf -y install rsyslog-gnutls'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000120-GPOS-00061'
  tag gid: 'V-280992'
  tag rid: 'SV-280992r1195379_rule'
  tag stig_id: 'RHEL-10-200650'
  tag fix_id: 'F-85458r1165330_fix'
  tag cci: ['CCI-000366', 'CCI-000803']
  tag nist: ['CM-6 b', 'IA-7']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe package('rsyslog-gnutls') do
      it { should be_installed }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
