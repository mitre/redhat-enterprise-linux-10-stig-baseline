control 'SV-281106' do
  title "RHEL 10 must allocate audit record storage capacity to store at least one week's worth of audit records."
  desc 'To ensure RHEL 10 systems have a sufficient storage capacity in which to write the audit logs, RHEL 10 must be able to allocate audit record storage capacity.

The task of allocating audit record storage capacity is usually performed during initial installation of RHEL 10.'
  desc 'check', 'Verify RHEL 10 allocates audit record storage capacity to store at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

Note: The partition size needed to capture a week of audit records is based on the activity level of the system and the total storage capacity available. Typically 10GB of storage space for audit records should be sufficient.

Determine which partition the audit records are being written to with the following command:

$ sudo grep -w log_file /etc/audit/auditd.conf
log_file = /var/log/audit/audit.log

Check the size of the partition that audit records are written to with the following command and verify whether it is sufficiently large:

$ df -h /var/log/audit/
Filesystem                                             Size  Used Avail Use% Mounted on
/dev/mapper/luks-4e45e1ad-5337-42c4-a19f-ee12ccc1d502   10G  263M  9.7G   3% /var/log/audit

If the audit record partition is not allocated for sufficient storage capacity, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to allocate enough storage capacity for at least one week of audit records when audit records are not immediately sent to a central audit record storage facility.

If audit records are stored on a partition made specifically for audit records, resize the partition with sufficient space to contain one week of audit records.

If audit records are not stored on a partition made specifically for audit records, a new partition with sufficient space must be created.'
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'SRG-OS-000341-GPOS-00132'
  tag gid: 'V-281106'
  tag rid: 'SV-281106r1166270_rule'
  tag stig_id: 'RHEL-10-500100'
  tag fix_id: 'F-85572r1166269_fix'
  tag cci: ['CCI-001849', 'CCI-001851']
  tag nist: ['AU-4', 'AU-4 (1)']
  tag 'host'

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  audit_log_dir = command("dirname #{auditd_conf.log_file}").stdout.strip

  describe file(audit_log_dir) do
    it { should exist }
    it { should be_directory }
  end

  # Fetch partition sizes in 1K blocks for consistency
  partition_info = command("df -B 1K #{audit_log_dir}").stdout.split("\n")
  partition_sz_arr = partition_info.last.gsub(/\s+/m, ' ').strip.split

  # Get unused space percentage
  percentage_space_unused = (100 - partition_sz_arr[4].to_i)

  describe "auditd_conf's space_left threshold" do
    it 'should be under the amount of space currently available (in 1K blocks) for the audit log directory' do
      expect(auditd_conf.space_left.to_i).to be <= percentage_space_unused
    end
  end
end
