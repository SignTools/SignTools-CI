tell application "System Events" to tell process "Xcode"
    -- check if account exists in account list
	if not (exists of row 2 of table 1 of scroll area 1 of window "Accounts") then
		error
	end if
end tell
