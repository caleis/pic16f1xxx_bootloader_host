; *****************************************************************************

	PROCESSOR	16F1574

; *****************************************************************************
	#include <xc.inc>
;
; *****************************************************************************
	PSECT   ResVect, class=CODE, delta=2
ResVect:
	movlw	high(Application)
	movwf	PCLATH
	goto	Application
	dw	0x0cc

	PSECT   IntVect, class=CODE, delta=2
IntVect:
	goto	ApplicationInt
	
; *****************************************************************************
Application:
	xorlw	0x10
	nop
	movlw	0x55
	goto	Application

ApplicationInt:
	addlw	0x20
	nop
	movlw	0xaa
	goto	ApplicationInt
	
; *****************************************************************************


	END



