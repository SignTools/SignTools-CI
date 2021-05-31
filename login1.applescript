repeat while application "Xcode" is not running
	delay 0.1
end repeat

tell application "System Events" to tell process "Xcode"
    repeat while not (exists menu item "Preferences…" of menu 1 of menu bar item "Xcode" of menu bar 1)
        delay 0.1
    end repeat
    click menu item "Preferences…" of menu 1 of menu bar item "Xcode" of menu bar 1

    repeat while not (exists button "Accounts" of tool bar 1 of window 1)
        delay 0.1
    end repeat
    click button "Accounts" of tool bar 1 of window 1

    repeat while not (exists button 2 of window "Accounts")
        delay 0.1
    end repeat
    tell window "Accounts"
	    -- row 1 is table header
        -- while there are any existing accounts added, remove them
        repeat while (exists row 2 of table 1 of scroll area 1)
            click button 2
            delay 0.1
        end repeat

        -- add new account
        click button 1

        repeat while not (exists sheet 1)
            delay 0.1
        end repeat
        tell sheet 1
            -- account type selection screen
            repeat while not (exists button "Continue")
                delay 0.1
            end repeat
            -- leave default account type "Apple ID"
            key code 76
            repeat while not (exists button "Next")
                delay 0.1
            end repeat
            keystroke (system attribute "ACCOUNT_NAME")
            key code 76
            repeat while not (exists static text "Password:")
                delay 0.1
            end repeat
            keystroke (system attribute "ACCOUNT_PASS")
            key code 76
        end tell
    end tell
end tell
