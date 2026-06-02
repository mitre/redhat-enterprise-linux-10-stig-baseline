control 'SV-281297' do
  title 'RHEL 10 must not default to the graphical display manager unless approved.'
  desc 'Unnecessary service packages must not be installed to decrease the attack surface of the system. Graphical display managers have a long history of security vulnerabilities and must not be used unless approved and documented.'
  desc 'check', 'Verify RHEL 10 is configured to boot to the command line with the following command:

$ systemctl get-default
multi-user.target

If the system default target is not set to "multi-user.target", and the information system security officer lacks a documented requirement for a graphical user interface, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to boot to the command line by setting the default target to "multi-user" with the following command:

$ sudo systemctl set-default multi-user.target'
  impact 0.5
  tag check_id: 'C-85858r1166841_chk'
  tag severity: 'medium'
  tag gid: 'V-281297'
  tag rid: 'SV-281297r1166843_rule'
  tag stig_id: 'RHEL-10-700940'
  tag gtitle: 'SRG-OS-000095-GPOS-00049'
  tag fix_id: 'F-85763r1166842_fix'
  tag 'documentable'
  tag cci: ['CCI-000381']
  tag nist: ['CM-7 a']
end
