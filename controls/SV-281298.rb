control 'SV-281298' do
  title 'RHEL 10 must disable the systemd Ctrl-Alt-Delete burst key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed operating system environment, this can create the risk of short-term loss of availability of systems due to unintentional reboot. 

In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify RHEL 10 is configured to not reboot the system when Ctrl-Alt-Delete is pressed seven times within two seconds with the following command:

$ grep -iR CtrlAltDelBurstAction /etc/systemd/
/etc/systemd/system.conf:CtrlAltDelBurstAction=none

If the "CtrlAltDelBurstAction" is not set to "none", is commented out, or is missing, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable the "CtrlAltDelBurstAction".

Update the "/etc/systemd/system.conf" configuration file as follows:

$ sudo vi /etc/systemd/system.conf

CtrlAltDelBurstAction=none

Reload the daemon for this change to take effect:

$ sudo systemctl daemon-reload'
  impact 0.7
  tag check_id: 'C-85859r1166844_chk'
  tag severity: 'high'
  tag gid: 'V-281298'
  tag rid: 'SV-281298r1166846_rule'
  tag stig_id: 'RHEL-10-700950'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-85764r1166845_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']

  only_if('This control is Not Applicable to containers', impact: 0.0) {
    !%w[docker podman kubepods lxc].include?(virtualization.system)
  }

  describe command('grep -iR CtrlAltDelBurstAction /etc/systemd/system*') do
    its('exit_status') { should eq 0 }
    its('stdout') { should match(/^[[:space:]]*CtrlAltDelBurstAction[[:space:]]*=[[:space:]]*none/i) }
  end
end
