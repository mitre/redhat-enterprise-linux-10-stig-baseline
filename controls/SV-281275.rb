control 'SV-281275' do
  title 'RHEL 10 must not allow unattended or automatic login via the graphical user interface.'
  desc 'Failure to restrict system access to authenticated users negatively
impacts operating system security.'
  desc 'check', 'Note: This requirement assumes the use of the RHEL 10 default graphical user interface, the GNOME desktop environment. If the system does not have any graphical user interface installed, this requirement is not applicable.

Verify RHEL 10 does not allow an unattended or automatic login to the system via a graphical user interface.

Check for the value of the "AutomaticLoginEnable" in the "/etc/gdm/custom.conf" file with the following command:

$  grep -i automaticlogin /etc/gdm/custom.conf
AutomaticLoginEnable=false

If the value of "AutomaticLoginEnable" is not set to "false", this is a finding.'
  desc 'fix', 'Configure RHEL 10 so that the GNOME desktop display manager disables automatic login.

Update the "/etc/gdm/custom.conf" file to disable automatic login to the GNOME desktop:

$ sudo vi /etc/gdm/custom.conf

[daemon]
AutomaticLoginEnable=false'
  impact 0.7
  tag severity: 'high'
  tag gtitle: 'SRG-OS-000080-GPOS-00048'
  tag gid: 'V-281275'
  tag rid: 'SV-281275r1166777_rule'
  tag stig_id: 'RHEL-10-700720'
  tag fix_id: 'F-85741r1166776_fix'
  tag cci: ['CCI-000366', 'CCI-000213']
  tag nist: ['CM-6 b', 'AC-3']
  tag 'host'

  only_if('This requirement is Not Applicable inside a container, the containers host manages the containers filesystems') {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  custom_conf = '/etc/gdm/custom.conf'

  if package('gnome-desktop3').installed?
    if (f = file(custom_conf)).exist?
      describe parse_config_file(custom_conf) do
        its('daemon.AutomaticLoginEnable') { cmp false }
      end
    else
      describe f do
        it { should exist }
      end
    end
  else
    impact 0.0
    describe 'The system does not have GDM installed' do
      skip 'The system does not have GDM installed, this requirement is Not Applicable.'
    end
  end
end
