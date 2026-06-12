control 'SV-281180' do
  title 'RHEL 10 must enforce a 24-hours minimum password lifetime restriction for passwords for new users or password changes in "/etc/login.defs".'
  desc "Enforcing a minimum password lifetime helps to prevent repeated password changes to defeat the password reuse or history enforcement requirement. If users are allowed to immediately and continually change their password, the password could be repeatedly changed in a short period of time to defeat the organization's policy regarding password reuse.

Setting the minimum password age protects against users cycling back to a favorite password after satisfying the password reuse requirement."
  desc 'check', 'Verify RHEL 10 enforces 24 hours as the minimum password lifetime for new user accounts.

Check for the value of "PASS_MIN_DAYS" in "/etc/login.defs" with the following command:

$ sudo grep -i pass_min_days /etc/login.defs
PASS_MIN_DAYS 1

If the "PASS_MIN_DAYS" parameter value is not "1" or greater or is commented out, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce 24 hours as the minimum password lifetime.

Add the following line in "/etc/login.defs" (or modify the line to have the required value):

PASS_MIN_DAYS 1'
  impact 0.5
  tag check_id: 'C-85741r1166490_chk'
  tag severity: 'medium'
  tag gid: 'V-281180'
  tag rid: 'SV-281180r1166492_rule'
  tag stig_id: 'RHEL-10-600210'
  tag gtitle: 'SRG-OS-000075-GPOS-00043'
  tag fix_id: 'F-85646r1166491_fix'
  tag 'documentable'
  tag cci: ['CCI-004066']
  tag nist: ['IA-5 (1) (h)']

  value = input('pass_min_days')
  setting = input_object('pass_min_days').name.upcase

  describe "/etc/login.defs does not have `#{setting}` configured" do
    let(:config) { login_defs.read_params[setting] }
    it "greater than #{value} day" do
      expect(config).to cmp <= value
    end
  end
end
