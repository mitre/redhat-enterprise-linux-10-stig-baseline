control 'SV-281254' do
  title 'RHEL 10 must be configured so that the Secure Shell (SSH) daemon does not allow Generic Security Service Application Program Interface (GSSAPI) authentication.'
  desc "GSSAPI authentication is used to provide additional authentication mechanisms to applications. Allowing GSSAPI authentication through SSH exposes the system's GSSAPI to remote hosts, increasing the attack surface of the system.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files."
  desc 'check', %q(Verify RHEL 10 SSH daemons do not allow GSSAPI authentication with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*gssapiauthentication'
/etc/ssh/sshd_config.d/10-stig.conf:GSSAPIAuthentication no
/etc/ssh/sshd_config.d/50-redhat.conf:GSSAPIAuthentication yes

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i gssapiauthentication
gssapiauthentication no

If the "GSSAPIAuthentication" keyword is not set to "no" in a drop-in that lexicographically precedes 50-redhat.conf, no output is returned, and the use of GSSAPI authentication has not been documented with the information system security officer, this is a finding.)
  desc 'fix', 'Configure RHEL 10 SSH daemons to not allow GSSAPI authentication.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

GSSAPIAuthentication no

Restart the SSH service with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85815r1166712_chk'
  tag severity: 'medium'
  tag gid: 'V-281254'
  tag rid: 'SV-281254r1184754_rule'
  tag stig_id: 'RHEL-10-700510'
  tag gtitle: 'SRG-OS-000364-GPOS-00151'
  tag fix_id: 'F-85720r1166713_fix'
  tag 'documentable'
  tag cci: ['CCI-001813']
  tag nist: ['CM-5 (1) (a)']
end
