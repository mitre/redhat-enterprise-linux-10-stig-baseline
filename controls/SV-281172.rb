control 'SV-281172' do
  title 'RHEL 10 must not allow duplicate user IDs (UIDs) to exist for interactive users.'
  desc 'To ensure accountability and prevent unauthenticated access, interactive users must be identified and authenticated to prevent potential misuse and compromise of the system.

'
  desc 'check', %q(Verify RHEL 10 contains no duplicate UIDs for interactive users with the following command:

$ sudo awk -F ":" 'list[$3]++{print $1, $3}' /etc/passwd

If output is produced and the accounts listed are interactive user accounts, this is a finding.)
  desc 'fix', 'Configure RHEL 10 to not allow duplicate UIDs to exist for interactive users.

Edit the file "/etc/passwd", and provide each interactive user account that has a duplicate UID with a unique UID.'
  impact 0.5
  tag check_id: 'C-85733r1166466_chk'
  tag severity: 'medium'
  tag gid: 'V-281172'
  tag rid: 'SV-281172r1166468_rule'
  tag stig_id: 'RHEL-10-600130'
  tag gtitle: 'SRG-OS-000104-GPOS-00051'
  tag fix_id: 'F-85638r1166467_fix'
  tag satisfies: ['SRG-OS-000104-GPOS-00051', 'SRG-OS-000121-GPOS-00062']
  tag 'documentable'
  tag cci: ['CCI-000764', 'CCI-000804']
  tag nist: ['IA-2', 'IA-8']
  tag 'host'
  tag 'container'

  user_count = passwd.where { uid.to_i >= 1000 }.entries.length

  describe "Count of interactive unique user IDs should match interactive user count (#{user_count}): UID count" do
    subject { passwd.where { uid.to_i >= 1000 }.uids.uniq.length }
    it { should eq user_count }
  end
end
