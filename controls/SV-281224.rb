control 'SV-281224' do
  title 'RHEL 10 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a Secure Shell (SSH) login.'
  desc 'The warning message reinforces policy awareness during the login process and facilitates possible legal action against attackers. Alternatively, systems whose ownership should not be obvious should ensure use of a banner that does not provide easy attribution.

OpenSSH uses the first occurrence of a keyword it sees, and drop-in files are read in lexicographical order at the start of the configuration. Red Hat recommends using drop-in files rather than changing base configuration files.'
  desc 'check', "Verify RHEL 10 is configured so that any SSH connection to the operating system displays the Standard Mandatory DOD Notice and Consent Banner before granting access to the system.

Check for the location of the banner file currently being used with the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\\r' | tr '\\n' ' ' | xargs sudo grep -iH '^\\s*banner'
/etc/ssh/sshd_config.d/10-stig.conf:Banner /etc/issue

If the line is commented out or the file is missing, this is a finding."
  desc 'fix', 'Configure RHEL 10 to display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via SSH.

Edit a file in "/etc/ssh/sshd_config.d" to uncomment or add the banner keyword and configure it to point to a file that will contain the login banner (this file may be named differently or be in a different location if using a version of SSH that is provided by a third-party vendor).

An example configuration line is:

Banner /etc/issue'
  impact 0.5
  tag check_id: 'C-85785r1166622_chk'
  tag severity: 'medium'
  tag gid: 'V-281224'
  tag rid: 'SV-281224r1184753_rule'
  tag stig_id: 'RHEL-10-700010'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85690r1166623_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']
end
