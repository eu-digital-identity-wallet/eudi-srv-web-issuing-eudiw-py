# PID issuer support


This section is intended to assist all users on how to use the PID Issuer test GUI to request a PID, aiming to demonstrate it explicitly and as straightforwardly as possible, for all available countries up to version 0.3.

## 1. eIDAS-Node (eIDAS CW)

Requesting a PID using eIDAS-Node (eIDAS node deployed for PID issuing testing purposes) is a simple 3-step process.

The first displayed page shows the requested attributes to the eIDAS-node for issuing a PID, which are:

+ Family Name
+ First Name
+ Date of Birth
+ National Identifier

To proceed, please click the "Next" button located in the bottom right corner, indicating that you authorize access to these attributes.

On the next page, please click the "Next" button to continue, since no additional attributes are requested. You will be redirected to a new page where you can authenticate yourself.

On the authentication page, you need to enter your username and password, and change the "Level of Assurance" field to "LoA High".
The test user data is as follows:
+ Username: xavi
+ Password: creus

To proceed, please click the "Submit" button at the bottom of the page.

Finally, in the last step, the data corresponding to the attributes requested in the first step is displayed. Please click the "Submit" button, and the PID will be issued in mdoc and sd-jwt format.

The last page displays the content of the PID issued by the PID Issuer.
On this page, there are two options:
+ Cancel - You will be redirected to the initial country selection page.
+ Store - This option simulates the storage of the mdoc and sd-jwt in the EUDI Wallet. If you select it, both the mdoc and sd-jwt format of the issued PID will be displayed.


## 2. Utopia (Form country)

The Country form consists of only one step, and unlike all the others, it does not require authentication and you can enter your own PID information.

When you select this option, a page will be displayed, with a form that you need to fill in with the necessary data to make the PID request:
+ First Name
+ Family Name
+ Date of Birth
+ National Identifier

In the end, simply click the "Submit" button.


The last page displays the content of the PID issued by the PID Issuer.
On this page, there are two options:
+ Cancel - You will be redirected to the initial country selection page.
+ Store - This option simulates the storage of the mdoc and sd-jwt in the EUDI Wallet. If you select it, both the mdoc and sd-jwt format of the issued PID will be displayed.

## 3. Portugal

In the case of Portugal, it's important to note that there is no test user available. Therefore, you will need to have a Portuguese ID card ("Cartão de Cidadão"),visit the Autenticação.Gov pre-prod website (https://pprwww.autenticacao.gov.pt/) and make a request in order to use the CMD ("Chave Móvel Digital") in the pre-production environment (or you can use directly your Portuguese ID card).


The first page that appears is related to how the user wants to authenticate, with two options available:
+ Citizen Card ("Cartão de Cidadão")
+ Mobile Digital Key ("Chave Móvel Digital")

After selecting the preferred authentication method - we are assuming that you will select the Mobile Digital Key -, simply click the "Continue" button.

Next, you will be shown the required attributes to issue the PID, and you'll need to authorize the access to these attributes. In this case, the required attributes are:
+ Surname
+ First Name
+ Date of Birth
+ Civil Identification number

To proceed, please click the "Autorizar" button. Please note that by clicking this button, you are granting permission to retrieve the value of the required attributes.

Next, you will be asked to fill in two fields:
+ Mobile Number
+ PIN (Mobile Digital Key authentication PIN)

Once you have correctly filled in these two pieces of information, please click the "Autenticar" button.

If everything is correct, you will be presented with a new page and asked for a confirmation code. The code will be sent to the mobile number you provided on the previous page (by SMS or “push notification”). Once you have the code inserted, please click "Confirmar."

The last page displays the content of the PID issued by the PID Issuer.
On this page, there are two options:
+ Cancel - You will be redirected to the initial country selection page.
+ Store - This option simulates the storage of the mdoc and sd-jwt in the EUDI Wallet. If you select it, both the mdoc and sd-jwt format of the issued PID will be displayed.


## 4. Estonia

The PID request for Estonia depends on the chosen type of authentication, and the first page presented is for selecting the desired authentication type.

To follow this tutorial, the default language of the website, which was Estonian, has been changed to English. You can do this by selecting the "English" option in the upper right corner.

There are 4 types of authentications:
 + ID-Card
+ Mobile-ID
+ Smart-ID
+ EU eID

For this tutorial, we will only mention authentication using "Mobile-ID" and "Smart-ID" because there are test users available for these methods. For more information on each type of authentication, please refer to the documentation (https://e-gov.github.io/TARA-Doku/Testing#21-quick-reference-of-testing-accounts).


**Mobile-ID**

Please select the "Mobile-ID" option from the menu and enter your personal code and the corresponding mobile phone number. Then, click the "Continue" button.
Here's an example, using the test user:
+ Personal code: 60001017869
+ Phone number: 68000769

**Smart-ID**

In case you choose authentication with Smart-ID, select the "Smart-ID" option from the menu and then enter your personal code. After that, pease click the "Continue" button. 

Here's an example, using the test user:
+ Personal code: 30303039914

Finally, regardless of the chosen authentication method, the page displayed after your authentication will be the same, containing the PID issued by the PID Issuer.
On this page, there are two options:
+ Cancel - You will be redirected to the initial country selection page.
+ Store - This option simulates the storage of the mdoc and sd-jwt in the EUDI Wallet. If you select it, both the mdoc and sd-jwt format of the issued PID will be displayed.


For more detailed information, please read read [this text](help_en.pdf).


