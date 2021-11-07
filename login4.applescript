tell application "System Events" to tell window "Accounts" of process "Xcode"
	tell table 1 of scroll area 2
		repeat with i from 1 to count of rows
			tell row i
				-- print each team name to stderr
				log (get value of static text 1 of UI element 1)
			end tell
		end repeat
	end tell
end tell
