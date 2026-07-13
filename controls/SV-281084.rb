control 'SV-281084' do
  title 'RHEL 10 must enforce that all local initialization files configured by systemd-tmpfiles have mode "0600" or less permissive.'
  desc 'Excessive permissions on local interactive user home directories may allow unauthorized access to user files by other users.'
  desc 'check', 'Verify RHEL 10 enforces that all local initialization files configured by systemd-tmpfiles have mode "0600" or less permissive.

Check that all files from "/usr/share/rootfiles/" are overridden correctly in RHEL 10:
 
$ sudo grep /usr/share/rootfiles/ /etc/tmpfiles.d/*.conf
C /root/.bash_logout   600 root root - /usr/share/rootfiles/.bash_logout
C /root/.bash_profile  600 root root - /usr/share/rootfiles/.bash_profile
C /root/.bashrc        600 root root - /usr/share/rootfiles/.bashrc
C /root/.cshrc         600 root root - /usr/share/rootfiles/.cshrc
C /root/.tcshrc        600 root root - /usr/share/rootfiles/.tcshrc
 
If any files are not configured to "600", or if no files are found by grep, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce that all local initialization files configured by systemd-tmpfiles have mode "0600" or less permissive.

Ensure the following lines are in a ".conf" file under "/etc/tmpfiles.d/":
 
C /root/.bash_logout   600 root root - /usr/share/rootfiles/.bash_logout
C /root/.bash_profile  600 root root - /usr/share/rootfiles/.bash_profile
C /root/.bashrc        600 root root - /usr/share/rootfiles/.bashrc
C /root/.cshrc         600 root root - /usr/share/rootfiles/.cshrc
C /root/.tcshrc        600 root root - /usr/share/rootfiles/.tcshrc'
  impact 0.5
  tag check_id: 'C-85645r1165605_chk'
  tag severity: 'medium'
  tag gid: 'V-281084'
  tag rid: 'SV-281084r1165607_rule'
  tag stig_id: 'RHEL-10-400335'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85550r1165606_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  mode = input('expected_modes')['systemd_tmpfiles_root_init_files']
  expected_tmpfiles_entries = [
    { target: '/root/.bash_logout', source: '/usr/share/rootfiles/.bash_logout' },
    { target: '/root/.bash_profile', source: '/usr/share/rootfiles/.bash_profile' },
    { target: '/root/.bashrc', source: '/usr/share/rootfiles/.bashrc' },
    { target: '/root/.cshrc', source: '/usr/share/rootfiles/.cshrc' },
    { target: '/root/.tcshrc', source: '/usr/share/rootfiles/.tcshrc' },
  ]

  tmpfiles_lines = command('grep -h /usr/share/rootfiles/ /etc/tmpfiles.d/*.conf').stdout.lines.map(&:strip)
  missing_entries = expected_tmpfiles_entries.reject do |entry|
    expected_line = /
      \AC\s+#{Regexp.escape(entry[:target])}\s+#{Regexp.escape(mode)}
      \s+root\s+root\s+-\s+#{Regexp.escape(entry[:source])}(?:\s|$)
    /x
    tmpfiles_lines.any? { |line| line.match?(expected_line) }
  end

  describe 'systemd-tmpfiles root initialization file overrides' do
    it "should configure all rootfiles entries with mode #{mode}" do
      formatted_missing_entries = missing_entries.map do |entry|
        "C #{entry[:target]} #{mode} root root - #{entry[:source]}"
      end
      expect(missing_entries).to be_empty, "Missing or incorrectly configured entries:\n\t- #{formatted_missing_entries.join("\n\t- ")}"
    end
  end
end
