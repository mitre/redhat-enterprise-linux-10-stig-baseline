control 'SV-280985' do
  title 'RHEL 10 must be configured to forward audit records via Transmission Control Protocol (TCP) to a different system or media from the system being audited via rsyslog.'
  desc 'Information stored in one location is vulnerable to accidental or incidental deletion or alteration.

Off-loading is a common process in information systems with limited audit storage capacity.

RHEL 10 installation media provides "rsyslogd", a system utility providing support for message logging. Support for both internet and Unix domain sockets enables this utility to support both local and remote logging. Coupling this utility with "gnutls" (a secure communications library implementing the Secure Sockets Layer [SSL], Transport Layer Security [TLS], and Datagram TLS [DTLS] protocols) creates a method to securely encrypt and off-load auditing.

The rsyslog provides three ways to forward message: the traditional User Datagram Protocol (UDP) transport, which is extremely lossy but standard; the plain TCP-based transport, which loses messages only during certain situations but is widely available; and the Reliable Event Logging Protocol (RELP) transport, which does not lose messages but is currently available only as part of the rsyslogd 3.15.0 and above.

Examples of each configuration:

UDP *.* @remotesystemname
TCP *.* @@remotesystemname
RELP *.* :omrelp:remotesystemname:2514

Note that a port number was given as there is no standard port for RELP.'
  desc 'check', %q(Verify RHEL 10 audit system off-loads audit records onto a different system or media from the system being audited via rsyslog using TCP with the following commands:

To check for legacy configuration syntax, perform the following:

$ sudo grep -ir '@@' /etc/rsyslog.conf /etc/rsyslog.d/

To check for Rainer script syntax, perform the following:

$ sudo grep -rq 'type="omfwd"' /etc/rsyslog.conf /etc/rsyslog.d/

If a remote server is not configured, or the line is commented out, ask the system administrator to indicate how the audit logs are off-loaded to a different system or media. 

If there is no evidence that the audit logs are being off-loaded to another system or media, this is a finding.)
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000479-GPOS-00224'
  tag satisfies: ['SRG-OS-000342-GPOS-00133', 'SRG-OS-000479-GPOS-00224', 'SRG-OS-000480-GPOS-00227']
  tag gid: 'V-280985'
  tag rid: 'SV-280985r1197221_rule'
  tag stig_id: 'RHEL-10-200642'
  tag fix_id: 'F-85451r1184701_fix'
  tag cci: ['CCI-001851', 'CCI-000366']
  tag nist: ['AU-4 (1)', 'CM-6 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  if input('alternative_logging_method') == ''
    describe command("grep -i 'type=\"omfwd\"' #{input('logging_conf_files').join(' ')}") do
      its('stdout') { should match(/^.*:\s*#\s*action\(\s*type\s*=\s*"omfwd"/i) }
    end
  else
    describe 'manual check' do
      skip 'Manual check required. Ask the administrator to indicate how logging is done for this system.'
    end
  end
end
