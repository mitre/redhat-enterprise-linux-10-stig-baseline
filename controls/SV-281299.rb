control 'SV-281299' do
  title 'RHEL 10 must disable the x86 Ctrl-Alt-Delete key sequence.'
  desc 'A locally logged-on user who presses Ctrl-Alt-Delete when at the console can reboot the system. If accidentally pressed, as could happen in the case of a mixed operating system environment, this can create the risk of short-term loss of systems availability due to unintentional reboot. 

In a graphical user environment, risk of unintentional reboot from the Ctrl-Alt-Delete sequence is reduced because the user will be prompted before any action is taken.'
  desc 'check', 'Verify RHEL 10 is not configured to reboot the system when Ctrl-Alt-Delete is pressed with the following command:

$ sudo systemctl status ctrl-alt-del.target
o ctrl-alt-del.target
        Loaded: masked (Reason: Unit ctrl-alt-del.target is masked.)
        Active: inactive (dead)

If the "ctrl-alt-del.target" is loaded and not masked, this is a finding.'
  desc 'fix', 'Configure RHEL 10 to disable the "ctrl-alt-del.target" with the following command:

$ sudo systemctl disable --now ctrl-alt-del.target
$ sudo systemctl mask --now ctrl-alt-del.target'
  impact 0.7
  tag check_id: 'C-85860r1166847_chk'
  tag severity: 'high'
  tag gid: 'V-281299'
  tag rid: 'SV-281299r1166849_rule'
  tag stig_id: 'RHEL-10-700960'
  tag gtitle: 'SRG-OS-000324-GPOS-00125'
  tag fix_id: 'F-85765r1166848_fix'
  tag 'documentable'
  tag cci: ['CCI-002235']
  tag nist: ['AC-6 (10)']
end
