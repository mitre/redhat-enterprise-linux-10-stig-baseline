control 'SV-281064' do
  title 'RHEL 10 must enforce mode "0740" or less permissive for local initialization files.'
  desc "Local initialization files are used to configure the user's shell environment upon login. Malicious modification of these files could compromise accounts upon login."
  desc 'check', %q(Verify RHEL 10 is configured so that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "disauser" user, who has a home directory of "/home/disauser".

$ sudo find /home -maxdepth 2 -type f -name ".*" -exec stat -c "%n %a" {} \; | awk '$2 > 740'
/home/disauser/.bash_profile 770 

If any local initialization files are returned, this indicates a mode more permissive than "0740", and this is a finding.)
  desc 'fix', 'Configure RHEL 10 so that all local initialization files have a mode of "0740" or less permissive with the following command:

Note: The example will be for the "disauser" user, who has a home directory of "/home/disauser".

$ sudo chmod 0740 /home/disauser/.<INIT_FILE>'
  impact 0.5
  tag check_id: 'C-85625r1165545_chk'
  tag severity: 'medium'
  tag gid: 'V-281064'
  tag rid: 'SV-281064r1165547_rule'
  tag stig_id: 'RHEL-10-400235'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag fix_id: 'F-85530r1165546_fix'
  tag 'documentable'
  tag cci: ['CCI-000213']
  tag nist: ['AC-3']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  ignore_shells = input('non_interactive_shells').join('|')

  homedirs = users.where { !shell.match(ignore_shells) && (uid >= 1000 || uid.zero?) }.homes
  alternate_ini_file_dirs = input('alternate_ini_file_dirs')
  ifiles = command("find #{homedirs.join(' ')} #{alternate_ini_file_dirs.join(' ')} -xdev -maxdepth 1 -name '.*' -type f -print0").stdout.split("\0")

  exempt_ini_files = input('exempt_ini_files')
  expected_mode = input('initialization_file_mode')
  failing_files = ifiles.select { |ifile| !exempt_ini_files.include?(ifile) && file(ifile).more_permissive_than?(expected_mode) }

  describe 'All RHEL 10 local initialization files' do
    it "must have mode '#{expected_mode}' or less permissive" do
      expect(failing_files).to be_empty, "Failing files:\n\t- #{failing_files.join("\n\t- ")}"
    end
  end
end
