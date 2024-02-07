Install

    pip install robotframework
    pip install --upgrade robotframework-seleniumlibrary
    pip install selenium==4.9.0

Test cases

    ➔Fake_Country_Form_Test -> test for Fake Country PID Form 
    ➔Eidas_Node_CW_Test -> test for the Eidas Node CW PID
    ➔Estonian_Issuer_Test -> test for Estonian Issuer PID
    ➔Portuguese_Issuer_Test -> test for Portuguese Issuer PID
    ➔Czechia_Issuer_Test -> test for Czechia Issuer PID
    ➔EidasNodeCW_Test_Fail -> test for selecting the Incorrect Level of Assurance in Eidas Node CW PID
    ➔EidasNodeCW_Test_Fail_2 -> test for input Wrong Credentials in Eidas Node CW PID
    ➔Fake_Country_Form_Test_MDL -> test for Fake Country MDL Form
    ➔Portuguese_Issuer_Test_MDL -> test for Portuguese MDL Issuer
    

Usage Examples

    Go to tests Directory
        to test all test cases
           -> robot test.robot 

        for individual test
           -> robot -t <testcase>  test.robot     
