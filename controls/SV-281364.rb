control 'SV-281364' do
  title 'RHEL 10 must enforce mode "0640" or less for the "/etc/audit/auditd.conf" file to prevent unauthorized access.'
  desc "Without the capability to restrict the roles and individuals that can select which events are audited, unauthorized personnel may be able to prevent the auditing of critical events. Misconfigured audits may degrade the system's performance by overwhelming the audit log. Misconfigured audits may also make it more difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one."
  desc 'check', 'Verify RHEL 10 enforces the mode of "/etc/audit/auditd.conf" with the following command:

$ sudo stat -c "%a %n" /etc/audit/auditd.conf
640 /etc/audit/auditd.conf

If "/etc/audit/auditd.conf" does not have a mode of "0640", this is a finding.'
  desc 'fix', 'Configure RHEL 10 to set the mode of the "/etc/audit/auditd.conf" file to "0640" with the following command:

$ sudo chmod 0640 /etc/audit/auditd.conf'
  impact 0.5
  tag check_id: 'C-85925r1167240_chk'
  tag severity: 'medium'
  tag gid: 'V-281364'
  tag rid: 'SV-281364r1167242_rule'
  tag stig_id: 'RHEL-10-900000'
  tag gtitle: 'SRG-OS-000063-GPOS-00032'
  tag fix_id: 'F-85830r1167241_fix'
  tag 'documentable'
  tag cci: ['CCI-000171']
  tag nist: ['AU-12 b']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  mode = input('expected_modes')['auditd_conf']

  describe file(auditd_conf.conf_path) do
    it { should_not be_more_permissive_than(mode) }
  end
end
