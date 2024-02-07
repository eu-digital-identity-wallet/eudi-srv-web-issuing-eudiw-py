*** Settings ***
Library    ../../.venv/Lib/site-packages/robot/libraries/Telnet.py
Library    SeleniumLibrary
Library    ../../.venv/Lib/site-packages/robot/libraries/DateTime.py
Library    ../../.venv/Lib/site-packages/robot/libraries/XML.py

*** Variables ***
#link for PID Initial Page
${link} =    https://preprod.issuer.eudiw.dev/pid 

#link for MDL Initial Page
${linkMdl}=    https://preprod.issuer.eudiw.dev/mdl

#Portuguese Credentials
${numTelePT}=    123456789
${PINPT}=   123456


*** Test Cases ***

#Robot Test for Fake Country PID Form
FakeCountryForm_Test
    Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
    Maximize Browser Window
    Click Element    //*[@id="FC"]
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="selectCountryForm"]/span/input[1]
    Input Text    CurrentGivenName   teste
    Input Text    CurrentFamilyName    teste
    Input Text    DateOfBirth        27092000
    Input Text    PersonIdentifier    teste
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="given_name"]]/td
    ${text}=    Get Text    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="given_name"]]/td
    Should Be Equal As Strings    teste    ${text}    
    Sleep    5s
    Close Browser


#Robot Test for Eidas Node Country CW PID
EidasNodeCW_Test
    Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
    Maximize Browser Window
    Click Element    //*[@id="CW"]
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="slider1"]
    Click Button    //*[@id="buttonNextSlide1"]
    Wait Until Element Is Visible    //*[@id="buttonNextSlide2"]
    Click Button    //*[@id="buttonNextSlide2"]
    Wait Until Element Is Visible    //*[@id="username"]
    Input Text    username   xavi
    Input Text    password    creus
    Select From List By Index    name:eidasloa   5
    Click Button    //*[@id="idpSubmitbutton"]
    Wait Until Element Is Visible    //*[@id="consentSelector"]
    Click Button    //*[@id="buttonNext"]
    Wait Until Element Is Visible    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
    ${text}=    Get Text    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
    Should Be Equal As Strings    Test PID issuer    ${text} 
    Sleep    5s
    Close Browser

#Robot Test for Estonian PID Issuer
EstonianIssuer_Test
    Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
    Maximize Browser Window
    Click Element    //*[@id="EE"]
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Click Element    xpath:/html/body/div[1]/div/div[4]/div[2]/nav/ul/li[3]
    Wait Until Element Is Visible    id:sid-personal-code
    Input Text    id:sid-personal-code   30303039914
    Click Button    //*[@id="smartIdForm"]/table/tbody/tr[2]/td[2]/button
    Sleep    20s
    Wait Until Element Is Visible    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
    ${text}=    Get Text    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
    Should Be Equal As Strings    Test PID issuer    ${text} 
    Close Browser


#Robot Test for Portuguese PID Issuer
# PortugueseIssuer_Test
#     Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
#     Maximize Browser Window
#     Click Element    //*[@id="PT"]
#     Click Button    //*[@id="selectCountryForm"]/span/input[1]
#     Wait Until Element Is Visible    //*[@id="selectAuthPanel"]/div[2]/input[2]
#     Execute Javascript    window.scrollTo(0, 1500)
#     Click Element    //*[@id="selectAuthPanel"]/div[2]/input[2]
#     Wait Until Element Is Visible    //*[@id="mainPageContent"]/div[2]/div[2]/input[10]
#     Execute Javascript    window.scrollTo(0, 1500)
#     Click Element   //*[@id="mainPageContent"]/div[2]/div[2]/input[10]
#     Sleep    5s
#     Wait Until Element Is Visible    id:inputMobile
#     Input Text    id:inputMobile    ${numTelePT}
#     Input Text    //*[@id="MainContent_txtPin"]    ${PINPT}
#     Click Button    //*[@id="MainContent_btnNext"]
#     Wait Until Element Is Visible    //*[@id="MainContent_txtMobileTAN"]
#     Sleep    20s
#     Execute Javascript    window.scrollTo(0, 1500)
#     Click Button    //*[@id="MainContent_btnNext"]
#     Wait Until Element Is Visible    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
#     ${text}=    Get Text    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
#     Should Be Equal As Strings    Test PID issuer    ${text}
#     Sleep    5s
#     Close Browser

#Robot Test for Czechia PID Issuer

# CzechiaIssuerTest
#     Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
#     Maximize Browser Window
#     Click Element    //*[@id="CZ"]
#     Click Button    //*[@id="selectCountryForm"]/span/input[1]
#     Wait Until Element Is Visible    //*[@id="TESTP"]/button
#     Click Button    //*[@id="TESTP"]/button
#     Click Element    //*[@id="idp20"]/div[1]/a
#     Wait Until Element Is Visible    //*[@id="btnSubmit"]
#     Click Button    //*[@id="btnSubmit"]
#     Sleep    5s
#     Close Browser


#Robot Test for Incorrect Level of Assurance in Eidas Node CW PID
EidasNodeCW_Test_Fail
    Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
    Maximize Browser Window
    Click Element    //*[@id="CW"]
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="slider1"]
    Click Button    //*[@id="buttonNextSlide1"]
    Wait Until Element Is Visible    //*[@id="buttonNextSlide2"]
    Click Button    //*[@id="buttonNextSlide2"]
    Wait Until Element Is Visible    //*[@id="username"]
    Input Text    username   xavi
    Input Text    password    creus
    Click Button    //*[@id="idpSubmitbutton"]
    Wait Until Element Is Visible    //*[@id="buttonNext"]
    Click Button    //*[@id="buttonNext"]
    Wait Until Element Is Visible    xpath:/html/body
    ${text}=    Get Text    xpath:/html/body
    Should Be Equal As Strings    Error 303: 202019 - Incorrect Level of Assurance in IdP response    ${text} 
    Sleep    5s
    Close Browser

#Robot Test for Wrong Credentials in Eidas Node CW PID
EidasNodeCW_Test_Fail2
    Open Browser    ${link}    googlechrome    options=add_argument("--ignore-certificate-errors")
    Maximize Browser Window
    Click Element    //*[@id="CW"]
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="slider1"]
    Click Button    //*[@id="buttonNextSlide1"]
    Wait Until Element Is Visible    //*[@id="buttonNextSlide2"]
    Click Button    //*[@id="buttonNextSlide2"]
    Wait Until Element Is Visible    //*[@id="username"]
    Input Text    username   xavi
    Input Text    password    123456
    Click Button    //*[@id="idpSubmitbutton"]
    Wait Until Element Is Visible    xpath:/html/body
    ${text}=    Get Text    xpath:/html/body
    Should Be Equal As Strings    Error 303: 003002 - Authentication Failed.    ${text} 
    Sleep    5s

    Close Browser

#Robot Test for  Fake Country MDL Form
FakeCountryForm_Test_MDL
    Open Browser    ${linkMdl}    googlechrome    options=add_argument("--ignore-certificate-errors")
    Maximize Browser Window
    Click Element    //*[@id="FC"]
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="selectCountryForm"]/span/input[1]
    Input Text    CurrentGivenName   teste
    Input Text    CurrentFamilyName    teste
    Input Text    DateOfBirth        27092000
    Input Text    BirthPlace    teste
    Input Text    DocumentNumber    teste
    ${portrait}=    Convert To String    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
    Input Text    Portrait    ${portrait}
    Input Text    IssueDate1    22022222
    Input Text    ExpiryDate1    03033333
    Click Button    //*[@id="selectCountryForm"]/span/input[1]
    Wait Until Element Is Visible    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="given_name"]]/td
    ${text}=    Get Text    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="given_name"]]/td
    Should Be Equal As Strings    teste    ${text}    
    Sleep    5s
    Close Browser

#Robot Test for Portuguese MDL Issuer
# PortugueseIssuerTestMDL
#     Open Browser    ${linkMdl}    googlechrome    options=add_argument("--ignore-certificate-errors")
#     Maximize Browser Window
#     Click Element    //*[@id="PT"]
#     Click Button    //*[@id="selectCountryForm"]/span/input[1]
#     Wait Until Element Is Visible    //*[@id="selectAuthPanel"]/div[2]/input[2]
#     Execute Javascript    window.scrollTo(0, 1500)
#     Click Element    //*[@id="selectAuthPanel"]/div[2]/input[2]
#     Wait Until Element Is Visible    //*[@id="mainPageContent"]/div[2]/div[2]/input[10]
#     Execute Javascript    window.scrollTo(0, 1500)
#     Click Element   //*[@id="mainPageContent"]/div[2]/div[2]/input[10]
#     Sleep    5s
#     Wait Until Element Is Visible    id:inputMobile
#     Input Text    id:inputMobile    ${numTelePT}
#     Input Text    //*[@id="MainContent_txtPin"]    ${PINPT}
#     Click Button    //*[@id="MainContent_btnNext"]
#     Wait Until Element Is Visible    //*[@id="MainContent_txtMobileTAN"]
#     Sleep    20s
#     Execute Javascript    window.scrollTo(0, 1500)
#     Click Button    //*[@id="MainContent_btnNext"]
#     Wait Until Element Is Visible    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
#     ${text}=    Get Text    //*[@id="eidasCountries"]/table/tbody/tr[.//th[text()="issuing_authority"]]/td
#     Should Be Equal As Strings    Test MDL issuer    ${text}
#     Sleep    5s
#     Close Browser
