control 'SV-281177' do
  title 'RHEL 10 must assign a home directory to all local interactive users in the "/etc/passwd" file.'
  desc 'If local interactive users are not assigned a valid home directory, there is no place for the storage and control of files they should own.'
  desc 'check', "Verify RHEL 10 interactive users have a home directory assigned with the following command:

$ sudo awk -F: '($3>=1000)&&($7 !~ /nologin/){print $1, $3, $6}' /etc/passwd
nsauser:x:1000:1000:nsauser:/home/nsauser:/bin/bash
disauser:x:1001:1001:disauser:/home/disauser:/bin/bash
doduser:x:1002:1002:doduser:/home/doduser:/bin/bash

Inspect the output and verify that all interactive users (normally users with a user identifier [UID] greater than 1000) have a home directory defined.

If a user's home directory is not defined, this is a finding."
  desc 'fix', 'Configure RHEL 10 interactive users to have a home directory assigned in the "/etc/passwd" file.

Create and assign home directories to all local interactive users on RHEL 10 that do not have a home directory assigned.'
  impact 0.5
  tag check_id: 'C-85738r1184747_chk'
  tag severity: 'medium'
  tag gid: 'V-281177'
  tag rid: 'SV-281177r1184748_rule'
  tag stig_id: 'RHEL-10-600180'
  tag gtitle: 'SRG-OS-000420-GPOS-00186'
  tag fix_id: 'F-85643r1166482_fix'
  tag 'documentable'
  tag cci: ['CCI-002385']
  tag nist: ['SC-5 a']
end
