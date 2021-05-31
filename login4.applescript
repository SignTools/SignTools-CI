tell application "System Events" to tell window "Accounts" of process "Xcode"
	repeat while not (exists table 1 of scroll area 1 of sheet 1)
		delay 0.1
		click button "Manage Certificates…"
	end repeat
	repeat while (count of rows of table 1 of scroll area 1 of sheet 1 < 2)
		delay 0.1
	end repeat
   	tell table 1 of scroll area 1 of sheet 1
	    -- row 1 is table header
		repeat with i from 2 to count of rows
			tell row i
				-- there could be multiple table headers which have only 1 column
				-- make sure to ignore them
				if (exists UI element 4) and value of static text 1 of UI element 4 is equal to "Revoked" then
					error
				end if
			end tell
		end repeat
	end tell
end tell
