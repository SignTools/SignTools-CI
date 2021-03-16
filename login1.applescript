repeat while application "Xcode" is not running
	delay 0.1
end repeat

tell application "System Events" to tell process "Xcode"
    -- wait for add account (+) button
	repeat while not (exists button 1 of window "Accounts")
		delay 0.1
	end repeat
    key code 53 # close dummy account import password prompt
    delay 1
    -- alternatively, could tab until it's at the "Accounts" button:
    # click menu item "Preferences…" of menu 1 of menu bar item "Xcode" of menu bar 1
    # key code 98 using command down # enable tab navigation
    # key code 48 # a lot of times...

    -- while there are any existing accounts added, remove them
    repeat while (exists of row 2 of table 1 of scroll area 1 of window "Accounts")
		click button 2 of window "Accounts"
        delay 1
	end repeat
    -- add new account
    click button 1 of window "Accounts"
    delay 1
    key code 76
    delay 3
    keystroke (system attribute "ACCOUNT_NAME")
    key code 76
    delay 3
    keystroke (system attribute "ACCOUNT_PASS")
    key code 76
end tell
