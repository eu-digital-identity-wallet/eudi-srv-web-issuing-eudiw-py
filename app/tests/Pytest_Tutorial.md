Architecture

There is a total of 6 files for running pytest tests, where 5 of them contain the tests, and another one is the main file that runs all the tests.
	
 	➔ test_route_ee_tara.py -> tests for the country of Estonia
	➔ test_route_eidasnode.py -> tests for the Eidas Node
	➔ test_route_formatter.py -> tests on the "/formatter" route
	➔ test_route_pid.py -> tests on the "/pid" route
	➔ test_route_pt_cmd.py -> tests on the "/cmd" route
	➔ main_pytest.py -> main file where all the tests are executed

Tutorial for running Pytest tests:
	
 	1. Go to the location where the 6 Pytest test files are located (.\app\tests\).
	2. Run one of the following commands in the terminal:
		a. python main_pytest.py 0
		b. python main_pytest.py 1

You can choose between two options:
	
 	➔ 0 – If you want a report to be generated at the end with all the tests in an HTML file ("reportPytest.html") 
  		that you can save in the current directory (.\app\tests\) and open to view the results in your browser. You can 
    	also save the file for later use.
	➔ 1 – Only runs all the tests and presents the results in the terminal, without creating any additional files.
