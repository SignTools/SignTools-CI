tell application "System Events" to tell window "Accounts" of process "Xcode"
    -- bypass 2fa upgrade prompt
    try
        tell sheet 1 of sheet 1
            repeat with _group in (every group of group 1 of UI element 1 of scroll area 1)
                if (exists button "Other options" of _group) then
                    click button "Other options" of _group
                    delay 1
                    exit repeat
                end if
            end repeat
            if (exists button "Don’t Upgrade") then
                click button "Don’t Upgrade"
            end if
            if (exists button "Do not upgrade") then --monterey
                click button "Do not upgrade"
            end if
        end tell
    end try
    -- check if account exists in account list
    if not (exists of row 2 of table 1 of scroll area 1) then
        error
    end if
    -- check if at least one team exists
    if (count of rows of table 1 of scroll area 2) < 1 then
        error
    end if
end tell
