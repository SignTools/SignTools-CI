tell application "System Events" to tell window "Accounts" of process "Xcode"
	-- check if account exists in account list
	if not (exists of row 2 of table 1 of scroll area 1) then
		error
	end if
	-- check if at least one team exists
	if (count of rows of table 1 of scroll area 2) < 1 then
		error
	end if
end tell
