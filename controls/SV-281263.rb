control 'SV-281263' do
  title 'RHEL 10 must be configured so that SSHD accepts public key authentication.'
  desc 'Without the use of multifactor authentication, the ease of access to privileged functions is greatly increased. Multifactor authentication requires using two or more factors to achieve authentication. A privileged account is defined as an information system account with authorizations of a privileged user. A DOD common access card (CAC) with DOD-approved PKI is an example of multifactor authentication.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.

'
  desc 'check', %q(Note: If the system administrator demonstrates the use of an approved alternate multifactor authentication method, this requirement is not applicable.

Verify RHEL 10 SSH daemons accept public key encryption with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*pubkeyauthentication'
/etc/ssh/sshd_config.d/10-stig.conf:PubkeyAuthentication yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i pubkeyauthentication
pubkeyauthentication yes

If the "PubkeyAuthentication" keyword is not set to "yes" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to accept public key authentication.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

PubkeyAuthentication yes

Restart the SSH daemon with the following command for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85824r1166739_chk'
  tag severity: 'medium'
  tag gid: 'V-281263'
  tag rid: 'SV-281263r1184763_rule'
  tag stig_id: 'RHEL-10-700600'
  tag gtitle: 'SRG-OS-000105-GPOS-00052'
  tag fix_id: 'F-85729r1166740_fix'
  tag satisfies: ['SRG-OS-000105-GPOS-00052', 'SRG-OS-000106-GPOS-00053', 'SRG-OS-000107-GPOS-00054', 'SRG-OS-000108-GPOS-00055']
  tag 'documentable'
  tag cci: ['CCI-000765', 'CCI-000766']
  tag nist: ['IA-2 (1)', 'IA-2 (2)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  describe sshd_config do
    its('PubkeyAuthentication') { should cmp 'yes' }
  end
end
