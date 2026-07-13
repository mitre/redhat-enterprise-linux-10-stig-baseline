control 'SV-281193' do
  title 'RHEL 10 must enforce password complexity rules for the "root" account.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks.

Password complexity is one factor of several that determines how long it takes to crack a password. The more complex the password, the greater the number of possible combinations that must be tested before the password is compromised.'
  desc 'check', 'Verify RHEL 10 enforces password complexity rules for the "root" account.

Check if "root" user is required to use complex passwords with the following command:

$ sudo grep enforce_for_root /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf
/etc/security/pwquality.conf:enforce_for_root

If "enforce_for_root" is commented out or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to enforce password complexity on the "root" account.

Add or update the following line in the "/etc/security/pwquality.conf" file or a configuration file in the "/etc/security/pwquality.conf.d/" directory to contain the "enforce_for_root" parameter:

enforce_for_root'
  impact 0.5
  tag check_id: 'C-85754r1166529_chk'
  tag severity: 'medium'
  tag gid: 'V-281193'
  tag rid: 'SV-281193r1166531_rule'
  tag stig_id: 'RHEL-10-600405'
  tag gtitle: 'SRG-OS-000072-GPOS-00040'
  tag fix_id: 'F-85659r1166530_fix'
  tag satisfies: ['SRG-OS-000072-GPOS-00040', 'SRG-OS-000071-GPOS-00039', 'SRG-OS-000070-GPOS-00038', 'SRG-OS-000266-GPOS-00101', 'SRG-OS-000078-GPOS-00046', 'SRG-OS-000480-GPOS-00225', 'SRG-OS-000069-GPOS-00037']
  tag 'documentable'
  tag cci: ['CCI-000192', 'CCI-000193', 'CCI-000194', 'CCI-000195', 'CCI-000205', 'CCI-000366', 'CCI-001619', 'CCI-004066']
  tag nist: ['IA-5 (1) (a)', 'IA-5 (1) (b)', 'CM-6 b', 'IA-5 (1) (h)']
  tag 'host'
  tag 'container'

  setting = 'enforce_for_root'

  describe 'pwquality.conf settings for the root account' do
    let(:config_files) do
      ['/etc/security/pwquality.conf'] +
        command("find /etc/security/pwquality.conf.d -maxdepth 1 -type f -name '*.conf' | sort").stdout.lines.map(&:strip)
    end

    let(:setting_value) do
      config_files.flat_map do |path|
        next [] unless file(path).file?

        file(path).content.lines.grep(/^\s*#{Regexp.escape(setting)}\s*(?:#.*)?$/)
      end
    end

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is set more than once in pwquality.conf or pwquality.conf.d/*.conf"
    end
  end
end
