control 'SV-280990' do
  title 'RHEL 10 must monitor all remote access methods.'
  desc 'Logging remote access methods can be used to trace the decrease in the risks associated with remote user access management. It can also be used to spot cyberattacks and ensure ongoing compliance with organizational policies surrounding the use of remote access methods.'
  desc 'check', %q(Verify RHEL 10 monitors all remote access methods with the following command:

$ sudo grep -rE '(auth.\*|authpriv.\*|daemon.\*)' /etc/rsyslog.conf /etc/rsyslog.d/
/etc/rsyslog.conf:authpriv.*                                              /var/log/secure

If "auth.*", "authpriv.*", or "daemon.*" are not configured to be logged, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to monitor all remote access methods.

Add or update the following lines to the "/etc/rsyslog.conf" file or a file in "/etc/rsyslog.d":

auth.*;authpriv.*;daemon.* /var/log/secure

Restart the "rsyslog" service with the following command for the changes to take effect:

$ sudo systemctl restart rsyslog.service'
  impact 0.5
  tag check_id: 'C-85551r1165323_chk'
  tag severity: 'medium'
  tag gid: 'V-280990'
  tag rid: 'SV-280990r1165325_rule'
  tag stig_id: 'RHEL-10-200647'
  tag gtitle: 'SRG-OS-000032-GPOS-00013'
  tag fix_id: 'F-85456r1165324_fix'
  tag 'documentable'
  tag cci: ['CCI-000067']
  tag nist: ['AC-17 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('Control not applicable; remote access not configured within containerized RHEL', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  rsyslog = file('/etc/rsyslog.conf')

  describe rsyslog do
    it { should exist }
  end

  if rsyslog.exist?

    auth_pattern = %r{^\s*[a-z.;*]*auth(,[a-z,]+)*\.\*\s*/*}
    authpriv_pattern = %r{^\s*[a-z.;*]*authpriv(,[a-z,]+)*\.\*\s*/*}
    daemon_pattern = %r{^\s*[a-z.;*]*daemon(,[a-z,]+)*\.\*\s*/*}

    rsyslog_conf = command('grep -E \'(auth.*|authpriv.*|daemon.*)\' /etc/rsyslog.conf')

    describe 'Logged remote access methods' do
      it 'should include auth.*' do
        expect(rsyslog_conf.stdout).to match(auth_pattern), 'auth.* not configured for logging'
      end
      it 'should include authpriv.*' do
        expect(rsyslog_conf.stdout).to match(authpriv_pattern), 'authpriv.* not configured for logging'
      end
      it 'should include daemon.*' do
        expect(rsyslog_conf.stdout).to match(daemon_pattern), 'daemon.* not configured for logging'
      end
    end
  end
end
