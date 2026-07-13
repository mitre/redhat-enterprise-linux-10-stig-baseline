control 'SV-281102' do
  title 'RHEL 10 must allocate an "audit_backlog_limit" of sufficient size to capture processes that start prior to the audit daemon.'
  desc 'Without the capability to generate audit records, it would be difficult to establish, correlate, and investigate the events relating to an incident or identify those responsible for one.

If auditing is enabled late in the startup process, the actions of some startup processes may not be audited. Some audit systems also maintain state information only available if auditing is enabled before a given process is created.

Audit records can be generated from various components within the information system (e.g., module or policy filter).

Allocating an "audit_backlog_limit" of sufficient size is critical in maintaining a stable boot process. With an insufficient limit allocated, the system is susceptible to boot failures and crashes.'
  desc 'check', %q(Verify RHEL 10 allocates a sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following command:

$ grep -oP 'audit_backlog_limit=\K[0-9]+' /proc/cmdline
8192

If the command returns any outputs, and "audit_backlog_limit" is less than "8192", this is a finding.)
  desc 'fix', 'Configure RHEL 10 to allocate sufficient "audit_backlog_limit" to capture processes that start prior to the audit daemon with the following command:

$ sudo grubby --update-kernel=ALL --args=audit_backlog_limit=8192

The setting will be applied on reboot.'
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000037-GPOS-00015'
  tag gid: 'V-281102'
  tag rid: 'SV-281102r1195414_rule'
  tag stig_id: 'RHEL-10-500030'
  tag fix_id: 'F-85568r1195413_fix'
  tag cci: ['CCI-001849', 'CCI-001464', 'CCI-000130', 'CCI-000135', 'CCI-000169', 'CCI-002884', 'CCI-000172']
  tag nist: ['AU-4', 'AU-14 (1)', 'AU-3 a', 'AU-3 (1)', 'AU-12 a', 'MA-4 (1) (a)', 'AU-12 c']
  tag 'host'

  only_if('Control not applicable within a container without sudo enabled', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  expected_audit_backlog_limit = input('expected_audit_backlog_limit')

  grubby = command('grubby --info=ALL').stdout

  grubby_args = (parse_config(grubby) || {})['args'].to_s
  arg_match = grubby_args.match(/audit_backlog_limit\s*=\s*(?<actual_audit_backlog_limit>\d+)/)

  describe 'Audit backlog limit' do
    it 'should be set' do
      expect(arg_match).not_to be_nil, 'Setting for audit_backlog_limit not found in grubby output'
    end
    unless arg_match.nil?
      it "should be at least #{expected_audit_backlog_limit}" do
        expect(arg_match[:actual_audit_backlog_limit].to_i).to be >= expected_audit_backlog_limit
      end
    end
  end
end
