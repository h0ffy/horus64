;##############################################################################
; DEBUG Macros
; 
; Used internally for testing purposes
; To test variable value inside win64.inc use bug() function to output its value
;##############################################################################
%macro DEBUG 0
	 %$DEBUG 1
%endmacro

%macro dbgmsg 1+
	%ifdef %$DEBUG
		%warning %1
	%endif
%endmacro

; Debug Messages
 bug(x) dbgmsg x
