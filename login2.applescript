tell application "System Events" to tell process "Xcode"
    keystroke (system attribute "ACCOUNT_2FA")
    key code 76
    -- wait for account to show up in account list
	repeat while not (exists of row 2 of table 1 of scroll area 1 of window "Accounts")
		delay 0.1
	end repeat
end tell

tell application "Xcode" to quit
