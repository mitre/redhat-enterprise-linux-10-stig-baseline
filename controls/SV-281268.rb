control 'SV-281268' do
  title 'RHEL 10 must force a frequent session key renegotiation for Secure Shell (SSH) connections to the server.'
  desc 'Without protection of the transmitted information, confidentiality and integrity may be compromised because unprotected communications can be intercepted and either read or altered.

This requirement applies to both internal and external networks and all types of information system components from which information can be transmitted (e.g., servers, mobile devices, notebook computers, printers, copiers, scanners, and facsimile machines). Communication paths outside the physical protection of a controlled boundary are exposed to the possibility of interception and modification.

Protecting the confidentiality and integrity of organizational information can be accomplished by physical means (e.g., employing physical distribution systems) or by logical means (e.g., employing cryptographic techniques). If physical means of protection are employed, then logical means (cryptography) do not have to be employed, and vice versa.

Session key regeneration limits the chances of a session key becoming compromised.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', %q(Verify RHEL 10 SSH servers are configured to force frequent session key renegotiation with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*rekeylimit'
/etc/ssh/sshd_config.d/10-stig.conf:RekeyLimit 1G 1h

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i rekeylimit
rekeylimit 1073741824 3600

If the "RekeyLimit" keyword is not set to "1G 1h" in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to force a frequent session key renegotiation for SSH connections to the server.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

RekeyLimit 1G 1h

Restart the SSH daemon with the following command for the settings to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000423-GPOS-00187'
  tag satisfies: ['SRG-OS-000033-GPOS-00014', 'SRG-OS-000420-GPOS-00186', 'SRG-OS-000424-GPOS-00188', 'SRG-OS-000423-GPOS-00187']
  tag gid: 'V-281268'
  tag rid: 'SV-281268r1184768_rule'
  tag stig_id: 'RHEL-10-700650'
  tag fix_id: 'F-85734r1166755_fix'
  tag cci: ['CCI-000068', 'CCI-002418', 'CCI-002421']
  tag nist: ['AC-17 (2)', 'SC-8', 'SC-8 (1)']
  tag 'host'
  tag 'container-conditional'

  only_if('This control is Not Applicable to containers without SSH enabled', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system) || file('/etc/ssh/sshd_config').exist?
  }

  describe sshd_config do
    its('RekeyLimit') { should cmp '1G 1h' }
  end
end
