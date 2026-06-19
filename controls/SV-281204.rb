control 'SV-281204' do
  title 'RHEL 10 must ensure the password complexity module in the system-auth file is configured for three or fewer retries.'
  desc 'Use of a complex password helps to increase the time and resources required to compromise the password. Password complexity, or strength, is a measure of the effectiveness of a password in resisting attempts at guessing and brute-force attacks. "pwquality" enforces complex password construction configuration and has the ability to limit brute-force attacks on the system.

RHEL 10 uses "pwquality" as a mechanism to enforce password complexity. This is set in both of the following: 

"/etc/pam.d/password-auth"
"/etc/pam.d/system-auth"

By limiting the number of attempts to meet the pwquality module complexity requirements before returning with an error, the system will audit abnormal attempts at password changes.'
  desc 'check', 'Verify RHEL 10 is configured to limit the "pwquality" retry option to "3" with the following command:

$ sudo grep -w retry /etc/security/pwquality.conf /etc/security/pwquality.conf.d/*.conf 
retry = 3 

If the value of "retry" is set to "0" or greater than "3", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to limit the "pwquality" retry option to "3".

Add or update the following line in the "/etc/security/pwquality.conf" file or a file in the "/etc/security/pwquality.conf.d/" directory to contain the "retry" parameter:

retry = 3'
  impact 0.5
  tag check_id: 'C-85765r1166562_chk'
  tag severity: 'medium'
  tag gid: 'V-281204'
  tag rid: 'SV-281204r1197240_rule'
  tag stig_id: 'RHEL-10-600485'
  tag gtitle: 'SRG-OS-000069-GPOS-00037'
  tag fix_id: 'F-85670r1166563_fix'
  tag 'documentable'
  tag cci: ['CCI-000366', 'CCI-000192', 'CCI-004066']
  tag nist: ['CM-6 b', 'IA-5 (1) (a)', 'IA-5 (1) (h)']
  tag 'host'

  only_if('This control is Not Applicable for containers', impact: 0.0) do
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  end

  setting = 'retry'
  expected_value = input('min_retry')

  describe 'pwquality.conf settings' do
    let(:config_files) do
      ['/etc/security/pwquality.conf'] +
        command("find /etc/security/pwquality.conf.d -maxdepth 1 -type f -name '*.conf' | sort").stdout.lines.map(&:strip)
    end

    let(:setting_value) do
      config_files.flat_map do |path|
        next [] unless file(path).file?

        config = parse_config_file(path, multiple_values: true)
        value = config.params[setting]
        value.is_a?(Integer) ? [value] : Array(value)
      end
    end

    it "has `#{setting}` set" do
      expect(setting_value).not_to be_empty, "#{setting} is not set in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "only sets `#{setting}` once" do
      expect(setting_value.length).to eq(1), "#{setting} is set more than once in pwquality.conf or pwquality.conf.d/*.conf"
    end

    it "sets `#{setting}` to greater than 0 and no more than #{expected_value}" do
      expect(setting_value.first.to_i).to be > 0, "#{setting} is set to 0 in pwquality.conf or pwquality.conf.d/*.conf"
      expect(setting_value.first.to_i).to be <= expected_value.to_i, "#{setting} is set to more than #{expected_value} in pwquality.conf or pwquality.conf.d/*.conf"
    end
  end
end
