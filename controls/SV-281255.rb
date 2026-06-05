control 'SV-281255' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon does not allow Kerberos authentication.'
  desc "Kerberos authentication for SSH is often implemented using Generic Security Service Application Program Interface (GSSAPI). If Kerberos is enabled through SSH, the SSH daemon provides a means of access to the system's Kerberos implementation. Vulnerabilities in the system's Kerberos implementations may be subject to exploitation.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files."
  desc 'check', %q(Verify RHEL 10 SSH daemons do not allow Kerberos authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*kerberosauthentication'
/etc/ssh/sshd_config.d/10-stig.conf:KerberosAuthentication no

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i kerberosauthentication
kerberosauthentication no

If the "KerberosAuthentication" keyword is not set to "no" in a drop-in that lexicographically precedes 50-redhat.conf, no output is returned, and the use of Kerberos authentication has not been documented with the information system security officer, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to not allow Kerberos authentication.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

KerberosAuthentication no

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85816r1166715_chk'
  tag severity: 'medium'
  tag gid: 'V-281255'
  tag rid: 'SV-281255r1184755_rule'
  tag stig_id: 'RHEL-10-700520'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-85721r1166716_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']

  only_if('This control is Not Applicable to containers without SSH installed', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || directory('/etc/ssh').exist?
  }

  use_kerberos = input('kerberos_required') ? 'yes' : 'no'

  describe sshd_config do
    its('KerberosAuthentication') { should cmp use_kerberos }
  end
end
