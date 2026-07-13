control 'SV-281262' do
  title "RHEL 10 must be configured so that Secure Shell (SSH) server configuration files' permissions are not modified."
  desc 'Service configuration files enable or disable features of their respective services, which if configured incorrectly can lead to insecure and vulnerable configurations. Therefore, service configuration files must be owned by the correct group to prevent unauthorized changes.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 is configured so that SSH server configuration files' permissions are not modified.

Check the permissions of the "/etc/ssh/sshd_config" file with the following command:

$ sudo rpm --verify openssh-server | awk '! ($2 == "c" && $1 ~ /^.\..\.\.\.\..\./) {print $0}'

If the command returns any output, this is a finding.)
  desc 'fix', "Configure RHEL 10 so that SSH server configuration files' permissions are not modified.

Run the following commands to restore the correct permissions of OpenSSH server configuration files:

$ sudo rpm --setugids openssh-server
$ sudo rpm --setperms openssh-server"
  impact 0.5
  tag check_id: 'C-85823r1166736_chk'
  tag severity: 'medium'
  tag gid: 'V-281262'
  tag rid: 'SV-281262r1184762_rule'
  tag stig_id: 'RHEL-10-700590'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85728r1166737_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
  tag 'host'
  tag 'container'

  system_file = '/etc/ssh/sshd_config'

  mode = input('expected_modes')[system_file]

  describe file(system_file) do
    it { should exist }
    it { should_not be_more_permissive_than(mode) }
  end
end
