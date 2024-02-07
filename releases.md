Version 0.3

    -> Modifications to the /get_pid and /pid routes: when the "country" parameter is empty, the user is redirected to the 
    /pid route to choose the corresponding country. In the /pid route, when a card is selected, the user is redirected 
    back to /getpid, now with the desired country information.
	
    -> A new mandatory argument, "device_publickey", has been added. This new attribute is the wallet instance public key.
	
    -> Added a tutorial on how to use Pytest, which can be found in the tests folder, "Pytest_Tutorial.md".
	
    -> Correction in the encoding process where the data was encoded twice in base64. Rectified to just base64 encoding.


Version 0.4

    -> Added tutorial on using the Robot framework, found in the tests folder under the name, "robot_tutorial.md".
	
    -> Added functionality for issuing mDL requests, both in CBOR and SD-JWT format. To use the "/mdl" and "/getmdl" 
    routes, the operation and arguments required are the same as for the PID.
	
    -> Added metadata to the PID ("issuance_date", "expiry_date", "issuing_authority" and "issuing_country").
	
    -> Added the "un_distinguishing_sign" attribute to the mDL.

