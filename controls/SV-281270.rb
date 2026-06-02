control 'SV-281270' do
  title 'RHEL 10 must forward mail from postmaster to the root account using a postfix alias.'
  desc 'It is critical for the appropriate personnel to be aware if a system is at risk of failing to process audit logs as required. Without this notification, the security personnel may be unaware of an impending failure of the audit capability, and system operation may be adversely affected.

Audit processing failures include software/hardware errors, failures in the audit capturing mechanisms, and audit storage capacity being reached or exceeded.'
  desc 'check', 'Verify RHEL 10 notifies administrators in the event of an audit processing failure.

Check that the "/etc/aliases" file has a defined value for "root".

$ sudo grep "postmaster:\\s*root$" /etc/aliases
postmaster:     root

If the command does not return a line, or the line is commented out, ask the system administrator to indicate how they and the information systems security officer are notified of an audit process failure. 

If there is no evidence of the proper personnel being notified of an audit processing failure, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to have a valid email address as an alias for the root account.

Append the following line to "/etc/aliases":

postmaster: root

Run the following command:

$ sudo newaliases'
  impact 0.5
  tag check_id: 'C-85831r1166760_chk'
  tag severity: 'medium'
  tag gid: 'V-281270'
  tag rid: 'SV-281270r1166762_rule'
  tag stig_id: 'RHEL-10-700670'
  tag gtitle: 'SRG-OS-000046-GPOS-00022'
  tag fix_id: 'F-85736r1166761_fix'
  tag 'documentable'
  tag cci: ['CCI-000139']
  tag nist: ['AU-5 a']
  tag 'host'
  tag 'container'

  options = { assignment_regex: /^(\S+):\s*(\S+)/ }

  describe parse_config_file('/etc/aliases', options) do
    its('postmaster') { should cmp 'root' }
  end
end
