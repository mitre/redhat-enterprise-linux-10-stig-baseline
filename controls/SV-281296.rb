control 'SV-281296' do
  title 'RHEL 10 must be configured with a timeout interval for the Secure Shell (SSH) daemon.'
  desc 'Terminating an idle SSH session within a short time period reduces the window of opportunity for unauthorized personnel to take control of a management session enabled on the console or console port that has been left unattended. In addition, quickly terminating an idle SSH session will also free up resources committed by the managed network element.

Terminating network connections associated with communications sessions includes, for example, deallocating associated TCP/IP address/port pairs at the operating system level and deallocating networking assignments at the application level if multiple application sessions are using a single operating system-level network connection. This does not mean that the operating system terminates all sessions or network access; it only ends the inactive session and releases the resources associated with that session.

RHEL 10 uses "/etc/ssh/sshd_config" for configurations of OpenSSH. Within the "sshd_config", the product of the values of "ClientAliveInterval" and "ClientAliveCountMax" are used to establish the inactivity threshold. 

The "ClientAliveInterval" is a timeout interval in seconds after which if no data has been received from the client, sshd will send a message through the encrypted channel to request a response from the client. 

The "ClientAliveCountMax" is the number of client alive messages that may be sent without sshd receiving any messages back from the client. If this threshold is met, sshd will disconnect the client. 

For more information on these settings and others, refer to the sshd_config man pages.

'
  desc 'check', %q(Verify RHEL 10 is configured with an SSH timeout interval.

Verify the "ClientAliveInterval" variable is set to a value of "600" or less by performing the following command:

$ sudo /usr/sbin/sshd -dd 2>&1 | awk '/filename/ {print $4}' | tr -d '\r' | tr '\n' ' ' | xargs sudo grep -iH '^\s*clientaliveinterval'
/etc/ssh/sshd_config.d/10-stig.conf::ClientAliveInterval 600

Verify the runtime setting with the following command:

$ sudo sshd -T | grep -i clientaliveinterval
clientaliveinterval 600

If the "ClientAliveInterval" keyword is not set to a value of "600" or less in a drop-in that lexicographically precedes 50-redhat.conf, or if no output is returned, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to automatically terminate all network connections associated with SSH traffic at the end of a session or after 10 minutes of inactivity.

Note: This setting must be applied in conjunction with RHEL-10-700660 to function correctly.

In "/etc/ssh/sshd_config.d", create a drop file that will lexicographically precede 50-redhat.conf and add the following line:

ClientAliveInterval 600

Restart the SSH daemon with the following command for the changes to take effect:

$ sudo systemctl restart sshd.service'
  impact 0.5
  tag check_id: 'C-85857r1166838_chk'
  tag severity: 'medium'
  tag gid: 'V-281296'
  tag rid: 'SV-281296r1184670_rule'
  tag stig_id: 'RHEL-10-700930'
  tag gtitle: 'SRG-OS-000163-GPOS-00072'
  tag fix_id: 'F-85762r1166839_fix'
  tag satisfies: ['SRG-OS-000163-GPOS-00072', 'SRG-OS-000279-GPOS-00109', 'SRG-OS-000395-GPOS-00175']
  tag 'documentable'
  tag cci: ['CCI-001133', 'CCI-002361', 'CCI-002891']
  tag nist: ['SC-10', 'AC-12', 'MA-4 (7)']
end
